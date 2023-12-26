use std::{
    error::Error,
    net::TcpStream,
    sync::{mpsc::Receiver as Reciever, Arc, Mutex},
    thread::{self, JoinHandle},
};

use crate::logger::Loggable;

use super::{
    message::{block::transaction::Transaction, messages_handler, Message},
    stream_handler::{StreamHandler, StreamHandlerTrait},
};

pub struct TxBroadcaster;

impl TxBroadcaster {
    pub fn run(
        stream_handler: &mut Arc<Mutex<StreamHandler>>,
        logger: Arc<Mutex<super::Logger>>,
        tx_broadcaster_rx: Reciever<Transaction>,
    ) -> Result<JoinHandle<()>, Box<dyn Error>> {
        let internal_logger = logger.clone();
        let mut stream_handler = stream_handler.clone();
        match thread::Builder::new()
            .name("tx_broadcaster_thread".to_string())
            .spawn(move || {
                internal_logger.debug("Starting tx broadcaster thread");
                let mut stream: Option<TcpStream> = None;
                for tx in tx_broadcaster_rx.iter() {
                    loop {
                        if stream.is_none() {
                            stream = match stream_handler.request_stream() {
                                Ok(streams) => Some(streams),
                                Err(e) => {
                                    internal_logger.error(&format!(
                                        "Couldn't request stream from stream handler. Error: {}",
                                        e
                                    ));
                                    return;
                                }
                            };
                        }

                        match TxBroadcaster::send_tx(stream.as_ref().unwrap(), tx.clone()) {
                            Ok(_) => {
                                internal_logger.debug("Sent tx");
                                break;
                            }
                            Err(e) => {
                                internal_logger
                                    .error(&format!("Couldn't send tx. Error: {}. Retrying...", e));
                                stream = None;
                            }
                        }
                    }
                }
            }) {
            Ok(handle) => Ok(handle),
            Err(e) => {
                logger.error(&format!(
                    "Couldn't start tx broadcaster thread. Error: {}",
                    e
                ));
                Err(Box::new(e))
            }
        }
    }

    fn send_tx(stream: &TcpStream, tx: Transaction) -> Result<(), Box<dyn Error>> {
        let msg = Message::new_tx_message(tx)?;

        match messages_handler::send_message(msg, stream) {
            Ok(_) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }
}
