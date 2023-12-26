use std::{
    net::TcpListener,
    sync::{
        mpsc::{Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
};

use crate::{config::Config, controller::NodeMessages, logger::Loggable};

pub(crate) struct NodeServer;

impl NodeServer {
    pub fn run(
        logger: Arc<Mutex<super::Logger>>,
        node_peer_listener_tx: Sender<NodeMessages>,
        node_node_server_rx: Receiver<NodeMessages>,
        config: Config,
    ) -> Result<(), std::io::Error> {
        logger.info("Starting node server");
        let port = match config.puertos_dns.first() {
            Some(port) => port,
            None => {
                let err_msg = "No port to open server found";
                logger.error(err_msg);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
            }
        };
        let listener = match TcpListener::bind("0.0.0.0:".to_owned() + port) {
            Ok(listener) => listener,
            Err(e) => {
                let err_msg = format!("Failed to bind to port {}: {}", port, e);
                logger.error(&err_msg);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
            }
        };
        logger.debug(&format!("Server listening on port {}", port));
        loop {
            match node_node_server_rx.try_recv() {
                Ok(message) => {
                    if let NodeMessages::EndConnection() = message {
                        logger.debug("End connection message received");
                        return Ok(());
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    let err_msg = "Node server communication channel disconnected";
                    logger.error(err_msg);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
                }
            };
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        logger.info(&format!("New connection: {}", stream.peer_addr().unwrap()));
                        // enviar stream por channel a peer listener
                        match node_peer_listener_tx.send(NodeMessages::NewPeer(stream)) {
                            Ok(_) => {}
                            Err(err) => {
                                let err_msg =
                                    format!("Error sending stream to peer listener: {}", err);
                                logger.error(&err_msg);
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    err_msg,
                                ));
                            }
                        }
                    }
                    Err(err_msg) => {
                        logger.error(&err_msg.kind().to_string());
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
                    }
                }
            }
        }
    }
}
