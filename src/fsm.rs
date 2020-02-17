use crate::dns_parser::{self, Name, QueryClass, QueryType, RRData};
use futures::channel::mpsc;
use futures::{SinkExt, select};
use futures_util::stream::StreamExt;
use futures_util::future::FutureExt;
use get_if_addrs::get_if_addrs;
use log::{debug, error, trace, warn};
use std::convert::TryFrom;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::runtime::Handle;

use super::{DEFAULT_TTL, MDNS_PORT};
use crate::address_family::AddressFamily;
use crate::services::{ServiceData, Services};

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;

#[derive(Clone, Debug)]
pub enum Command {
    SendUnsolicited {
        svc: ServiceData,
        ttl: u32,
        include_ip: bool,
    },
    Shutdown,
}

pub struct FSM<AF: AddressFamily> {
    socket: UdpSocket,
    services: Services,
    commands: mpsc::UnboundedReceiver<Command>,
    outgoing_rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    outgoing_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    _af: PhantomData<AF>,
}

impl<AF: AddressFamily> FSM<AF> {
    pub fn new(
        handle: &Handle,
        services: &Services,
    ) -> io::Result<(FSM<AF>, mpsc::UnboundedSender<Command>)> {
        let std_socket = AF::bind()?;
        let socket = UdpSocket::try_from(std_socket)?;
        let (tx, rx) = mpsc::unbounded();
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded();

        let fsm = FSM {
            socket: socket,
            services: services.clone(),
            commands: rx,
            outgoing_rx,
            outgoing_tx,
            _af: PhantomData,
        };

        Ok((fsm, tx))
    }

    async fn recv_packet(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        // loop {
        let (bytes, addr) = match self.socket.recv_from(&mut buf).await {
            Ok((bytes, addr)) => (bytes, addr),
            // Err(ref ioerr) if ioerr.kind() == WouldBlock => break,
            Err(err) => return Err(err),
        };

        if bytes >= buf.len() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("buffer too small for packet from {:?}", addr)));
        }

        self.handle_packet(&buf[..bytes], addr);
        Ok(())
    }

    async fn handle_packet(&mut self, buffer: &[u8], addr: SocketAddr) {
        trace!("received packet from {:?}", addr);

        let packet = match dns_parser::Packet::parse(buffer) {
            Ok(packet) => packet,
            Err(error) => {
                warn!("couldn't parse packet from {:?}: {}", addr, error);
                return;
            }
        };

        if !packet.header.query {
            trace!("received packet from {:?} with no query", addr);
            return;
        }

        if packet.header.truncated {
            warn!("dropping truncated packet from {:?}", addr);
            return;
        }

        let mut unicast_builder = dns_parser::Builder::new_response(packet.header.id, false, true)
            .move_to::<dns_parser::Answers>();
        let mut multicast_builder =
            dns_parser::Builder::new_response(packet.header.id, false, true)
                .move_to::<dns_parser::Answers>();
        unicast_builder.set_max_size(None);
        multicast_builder.set_max_size(None);

        for question in packet.questions {
            debug!(
                "received question: {:?} {}",
                question.qclass, question.qname
            );

            if question.qclass == QueryClass::IN || question.qclass == QueryClass::Any {
                if question.qu {
                    unicast_builder = self.handle_question(&question, unicast_builder);
                } else {
                    multicast_builder = self.handle_question(&question, multicast_builder);
                }
            }
        }

        if !multicast_builder.is_empty() {
            let response = multicast_builder.build().unwrap_or_else(|x| x);
            let addr = SocketAddr::new(AF::mdns_group(), MDNS_PORT);
            self.outgoing_tx.send((response, addr)).await;
        }

        if !unicast_builder.is_empty() {
            let response = unicast_builder.build().unwrap_or_else(|x| x);
            self.outgoing_tx.send((response, addr)).await;
        }
    }

    fn handle_question(
        &self,
        question: &dns_parser::Question,
        mut builder: AnswerBuilder,
    ) -> AnswerBuilder {
        let services = self.services.read().unwrap();

        match question.qtype {
            QueryType::A | QueryType::AAAA | QueryType::All
                if question.qname == *services.get_hostname() =>
            {
                builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
            }
            QueryType::PTR => {
                for svc in services.find_by_type(&question.qname) {
                    builder = svc.add_ptr_rr(builder, DEFAULT_TTL);
                    builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
                }
            }
            QueryType::SRV => {
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
                }
            }
            QueryType::TXT => {
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                }
            }
            _ => (),
        }

        builder
    }

    fn add_ip_rr(&self, hostname: &Name, mut builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        let interfaces = match get_if_addrs() {
            Ok(interfaces) => interfaces,
            Err(err) => {
                error!("could not get list of interfaces: {}", err);
                return builder;
            }
        };

        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }

            trace!("found interface {:?}", iface);
            match iface.ip() {
                IpAddr::V4(ip) if !AF::v6() => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::A(ip))
                }
                IpAddr::V6(ip) if AF::v6() => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::AAAA(ip))
                }
                _ => (),
            }
        }

        builder
    }

    async fn send_unsolicited(&mut self, svc: &ServiceData, ttl: u32, include_ip: bool) {
        let mut builder =
            dns_parser::Builder::new_response(0, false, true).move_to::<dns_parser::Answers>();
        builder.set_max_size(None);

        let services = self.services.read().unwrap();

        builder = svc.add_ptr_rr(builder, ttl);
        builder = svc.add_srv_rr(services.get_hostname(), builder, ttl);
        builder = svc.add_txt_rr(builder, ttl);
        if include_ip {
            builder = self.add_ip_rr(services.get_hostname(), builder, ttl);
        }

        if !builder.is_empty() {
            let response = builder.build().unwrap_or_else(|x| x);
            let addr = SocketAddr::new(AF::mdns_group(), MDNS_PORT);
            self.outgoing_tx.send((response, addr)).await;
        }
    }

    pub async fn run(mut self) -> Result<(), io::Error> {

        loop {
            select! {
                cmd = self.commands.next().fuse() => {
                    match cmd {
                        Some(Command::Shutdown) => return Ok(()),
                        Some(Command::SendUnsolicited {
                            svc,
                            ttl,
                            include_ip,
                        }) => {
                            self.send_unsolicited(&svc, ttl, include_ip);
                        }
                        None => {
                            warn!("responder disconnected without shutdown");
                            return Ok(());
                        }
                    }
                },
                _ = self.recv_packet().fuse() => (),
                response = self.outgoing_rx.next().fuse() => {
                    match response {
                        Some((response, addr)) => {
                            trace!("sending packet to {:?}", addr);

                            if let Err(err) = self.socket.send_to(&response, addr).await {
                                 warn!("error sending packet {:?}", err);
                            }
                        },
                        None => (), // TODO handle ?
                    }
                }
            }
        }
    }
}
