use super::message::messages_handler;
use super::message::Message;
use crate::config::Config;
use crate::logger::Loggable;
use crate::logger::Logger;
use crate::node::peer_discoverer;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::error::Error;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;
use std::{sync::Arc, sync::Mutex};
pub struct StreamHandler {
    socket_addrs: Vec<SocketAddr>,
    config: Config,
    logger: Arc<Mutex<Logger>>,
    user_ips: Vec<String>,
    port: String,
}

impl StreamHandler {
    const TIMEOUT: Duration = Duration::new(10, 0);
    pub fn new(config: Config, logger: Arc<Mutex<Logger>>) -> Result<Self, Box<dyn Error>> {
        let port = config.puertos_dns[0].clone();
        let mut peer_ips =
            peer_discoverer::discover(&config.direcciones_dns[0], &config.puertos_dns[0])?;
        logger.debug(&format!("Found peer IPs: {:?}", peer_ips));
        peer_ips.shuffle(&mut thread_rng());
        let mut user_ips: Vec<String> = Vec::new();
        for ip in &config.ips {
            for _ in 0..10 {
                user_ips.push(ip.to_string());
            }
        }
        Ok(Self {
            socket_addrs: peer_ips,
            config,
            logger,
            user_ips,
            port,
        })
    }

    pub fn request_stream(&mut self) -> Result<TcpStream, Box<dyn Error>> {
        let mut stream: TcpStream;
        self.logger.debug(&format!(
            "Thread {} pidiendo stream",
            std::thread::current().name().unwrap_or("unknown")
        ));
        loop {
            if !self.user_ips.is_empty() {
                let ip = self.user_ips[0].clone();
                self.user_ips.remove(0);
                let ip_and_port = ip + ":" + &self.port;
                self.logger.debug(&format!(
                    "Conectandose con IP especificada en config {}",
                    ip_and_port,
                ));
                match TcpStream::connect(ip_and_port) {
                    Ok(s) => stream = s,
                    Err(e) => {
                        self.logger.error(&format!(
                            "Error conectandose con IP especificada en config {}",
                            e,
                        ));
                        let peer = match self.socket_addrs.pop() {
                            Some(peer) => peer,
                            None => {
                                self.logger
                                    .error("[request_stream] No more peers to connect to");
                                // Boxed Error no more peers
                                return Err(Box::new(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "No more peers to connect to",
                                )));
                            }
                        };
                        stream = match TcpStream::connect_timeout(&peer, Self::TIMEOUT) {
                            Ok(s) => s,
                            Err(e) => {
                                self.logger
                                    .error(&format!("[request_stream] Peer timed out: {}", e));
                                continue;
                            }
                        };
                        stream.set_read_timeout(Some(Duration::new(60, 0)))?;
                    }
                };
            } else {
                let peer = match self.socket_addrs.pop() {
                    Some(peer) => peer,
                    None => {
                        self.logger
                            .error("[request_stream] No more peers to connect to");
                        // Boxed Error no more peers
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "No more peers to connect to",
                        )));
                    }
                };
                stream = match TcpStream::connect_timeout(&peer, Self::TIMEOUT) {
                    Ok(s) => s,
                    Err(e) => {
                        self.logger
                            .error(&format!("[request_stream] Peer timed out: {}", e));
                        continue;
                    }
                };
            }

            match handshake(&stream, self.config.version_protocolo_handshake) {
                Ok(_) => {
                    self.logger.debug(&format!(
                        "Thread: {} Handshake successful",
                        std::thread::current().name().unwrap_or_default()
                    ));
                }
                Err(e) => {
                    self.logger.error(&format!(
                        "Thread: {} Handshake failed: {}",
                        std::thread::current().name().unwrap_or_default(),
                        e
                    ));
                    continue;
                }
            }

            let message = match Message::new_send_headers_message() {
                Ok(m) => m,
                Err(e) => {
                    self.logger.error(&format!(
                        "Thread: {} Error creating sendheaders message: {}",
                        std::thread::current().name().unwrap_or_default(),
                        e
                    ));
                    continue;
                }
            };
            match messages_handler::send_message(message, &stream) {
                Ok(_) => {
                    self.logger.debug(&format!(
                        "Thread: {} Sendheaders message sent",
                        std::thread::current().name().unwrap_or_default()
                    ));
                    break;
                }
                Err(e) => {
                    self.logger.error(&format!(
                        "Thread: {} Error sending sendheaders message: {}",
                        std::thread::current().name().unwrap_or_default(),
                        e
                    ));
                    continue;
                }
            }
        }
        Ok(stream)
    }
}

pub trait StreamHandlerTrait {
    fn request_stream(&mut self) -> Result<TcpStream, Box<dyn Error>>;
}

impl StreamHandlerTrait for Arc<Mutex<StreamHandler>> {
    fn request_stream(&mut self) -> Result<TcpStream, Box<dyn Error>> {
        let mut stream_handler = match self.lock() {
            Ok(s) => s,
            Err(e) => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Error locking stream_handler: {}", e),
                )));
            }
        };
        stream_handler.request_stream()
    }
}

/// Function used to handle the handshake process with a peer.
/// It takes a `TcpStream` as an argument and returns a `Result` with the result of the operation.
/// The handshake process consists of sending a version message and receiving a version message
/// and a verack message.
/// The version message contains information about the node, such as its version number and
/// supported services.
///
/// # Arguments
///
/// * `stream` - The TCP stream to send the message over.
///
/// ```
pub fn handshake(stream: &TcpStream, protocol_version: i32) -> Result<(), std::io::Error> {
    // handshake por cada stream.
    let message = match Message::new_version_message(protocol_version, 0) {
        Ok(message) => message,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error creating version message: {}", e),
            ))
        }
    };
    messages_handler::send_message(message, stream)?;
    messages_handler::receive_message_serialized(*b"version\x00\x00\x00\x00\x00", stream)?;

    let verack_message = match Message::new_ver_ack_message() {
        Ok(verack_message) => verack_message,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error creating verack message {}", e),
            ))
        }
    };

    messages_handler::send_message(verack_message, stream)?;
    messages_handler::receive_message_serialized(*b"verack\x00\x00\x00\x00\x00\x00", stream)?;

    Ok(())
}
