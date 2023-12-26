use crate::{
    config::Config,
    controller::NodeMessages,
    logger::Loggable,
    node::stream_handler::{StreamHandler, StreamHandlerTrait},
};
use std::{
    net::TcpStream,
    sync::{
        mpsc::{channel, Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
    thread,
};

use super::message::{
    block::{transaction::Transaction, Block},
    messages_handler,
};

pub enum PeerListenerOutput {
    Transaction(Transaction),
    Block(Block),
}

pub(crate) struct PeerListener;

impl PeerListener {
    pub fn run(
        stream_handler: &mut Arc<Mutex<StreamHandler>>,
        logger: Arc<Mutex<super::Logger>>,
        config: Config,
        node_peer_listener_rx: Receiver<NodeMessages>,
        peer_listener_output_tx: Sender<PeerListenerOutput>,
    ) -> Result<(), std::io::Error> {
        logger.info("Running peer listener");
        let number_of_peers = config.active_peers;
        let mut handles = vec![];
        let (threads_to_peer_listener_tx, threads_to_peer_listener_rx): (
            Sender<NodeMessages>,
            Receiver<NodeMessages>,
        ) = channel();
        let mut peer_listener_to_threads_tx_vec = Vec::<Sender<NodeMessages>>::new();
        for peer_index in 0..number_of_peers {
            Self::spawn_peer_listener_thread(
                &peer_index,
                stream_handler,
                &logger,
                &mut peer_listener_to_threads_tx_vec,
                &threads_to_peer_listener_tx,
                &mut handles,
                None,
            )?;
        }
        let logger_clone = Arc::clone(&logger);
        let peer_listener_thread_messages_listener_handle = thread::Builder::new()
            .name("peer_listener_thread_messages_listener".to_string())
            .spawn(move || {
                for message in threads_to_peer_listener_rx.iter() {
                    match message {
                        NodeMessages::NewTransactionArrived(tx) => {
                            match peer_listener_output_tx.send(PeerListenerOutput::Transaction(tx))
                            {
                                Ok(_) => {}
                                Err(e) => {
                                    let err_msg = format!(
                                        "Error sending new transaction to block_processor: {}",
                                        e
                                    );
                                    logger_clone.error(err_msg.as_str());
                                }
                            }
                        }
                        NodeMessages::NewBlockArrived(block) => {
                            match peer_listener_output_tx.send(PeerListenerOutput::Block(block)) {
                                Ok(_) => {}
                                Err(e) => {
                                    let err_msg = format!(
                                        "Error sending new block to block_processor: {}",
                                        e
                                    );
                                    logger_clone.error(err_msg.as_str());
                                }
                            }
                        }
                        _ => {}
                    };
                }
                Ok(())
            })?;
        handles.push(peer_listener_thread_messages_listener_handle);
        for message in node_peer_listener_rx.iter() {
            match message {
                NodeMessages::EndConnection() => {
                    for peer_listener_tx in peer_listener_to_threads_tx_vec.iter() {
                        match peer_listener_tx.send(NodeMessages::EndConnection()) {
                            Ok(_) => {}
                            Err(e) => {
                                let err_msg = format!(
                                    "Error enviando mensaje a cada peer_listener thread: {}",
                                    e
                                );
                                logger.error(err_msg.as_str());
                            }
                        };
                    }
                }
                NodeMessages::NewPeer(peer) => {
                    logger.debug("Spawning new peer listener thread received from server");
                    Self::spawn_peer_listener_thread(
                        &(number_of_peers + 1),
                        stream_handler,
                        &logger,
                        &mut peer_listener_to_threads_tx_vec,
                        &threads_to_peer_listener_tx,
                        &mut handles,
                        Some(peer),
                    )?;
                }
                _ => {}
            };
        }
        drop(threads_to_peer_listener_tx);
        for handle in handles {
            match handle.join() {
                Ok(_) => {}
                Err(e) => logger.error(&format!("Error en hilo: {:?}", e)),
            }
        }
        logger.info("End of peer listener");
        Ok(())
    }

    fn spawn_peer_listener_thread(
        peer_index: &i32,
        stream_handler: &mut Arc<Mutex<StreamHandler>>,
        logger: &Arc<Mutex<super::Logger>>,
        peer_listener_to_threads_tx_vec: &mut Vec<Sender<NodeMessages>>,
        threads_to_peer_listener_tx: &Sender<NodeMessages>,
        handles: &mut Vec<thread::JoinHandle<Result<(), std::io::Error>>>,
        mut stream: Option<TcpStream>,
    ) -> Result<(), std::io::Error> {
        let mut stream_handler_clone = Arc::clone(stream_handler);
        let logger_clone = Arc::clone(logger);
        let (tx, peer_listener_thread_rx) = channel();
        peer_listener_to_threads_tx_vec.push(tx);
        let threads_to_peer_listener_tx_clone = threads_to_peer_listener_tx.clone();
        let peer_listener_thread_handle = thread::Builder::new()
            .name(format!("peer_listener_{}", peer_index))
            .spawn(move || loop {
                match peer_listener_thread_rx.try_recv() {
                    Ok(message) => {
                        if let NodeMessages::EndConnection() = message {
                            logger_clone.debug("End connection message received");
                            return Ok(());
                        }
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        let err_msg = "Peer listener disconnected";
                        logger_clone.error(err_msg);
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
                    }
                };
                if stream.is_none() {
                    match stream_handler_clone.request_stream() {
                        Ok(s) => stream = Some(s),
                        Err(e) => {
                            let err_msg = format!("Error requesting stream: {}", e);
                            logger_clone.error(err_msg.as_str());
                            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
                        }
                    };
                }
                match messages_handler::handle_peer_messages(
                    &mut stream,
                    &logger_clone,
                    threads_to_peer_listener_tx_clone.clone(),
                ) {
                    Ok(_) => {}
                    Err(e) => {
                        let err_msg = format!("Error handling peer messages: {}", e);
                        logger_clone.error(err_msg.as_str());
                        stream = None;
                    }
                };
            })?;
        handles.push(peer_listener_thread_handle);
        Ok(())
    }
}
