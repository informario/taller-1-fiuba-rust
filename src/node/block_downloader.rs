use std::{
    net::TcpStream,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Mutex, PoisonError,
    },
    thread,
};

use crate::{
    logger::Loggable,
    node::message::{messages_handler, Message},
};

use super::{
    message::inv,
    stream_handler::{StreamHandler, StreamHandlerTrait},
    IndexedBlockList, IndexedHeaderList,
};

pub struct BlockDownloader;

impl BlockDownloader {
    pub fn run(
        stream_handler_clone: &mut Arc<Mutex<StreamHandler>>,
        header_reciever_thread_rx: Receiver<IndexedHeaderList>,
        error_sender_thread_tx: Sender<Option<IndexedHeaderList>>,
        block_sender_thread_tx: Sender<IndexedBlockList>,
        logger: Arc<Mutex<super::Logger>>,
    ) -> Result<(), PoisonError<Arc<Mutex<StreamHandler>>>> {
        let mut stream: Option<TcpStream> = None;

        let receiver_clean = header_reciever_thread_rx;
        for block_header_hash in receiver_clean.iter() {
            let index = block_header_hash.index;
            loop {
                if stream.is_none() {
                    match stream_handler_clone.request_stream() {
                        Ok(s) => stream = Some(s),
                        Err(e) => {
                            let err_msg = format!("Error: {}", e);
                            logger.error(&err_msg);
                            return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                        }
                    };
                }
                // extremo de lectura, va a recibir los hashes que le pase el sync thread
                // por su channel correspondiente.
                let error_sender_thread_tx = error_sender_thread_tx.clone();
                let bloques_recibidos = match download_blocks(
                    stream.as_ref().unwrap(),
                    block_header_hash.clone(),
                    error_sender_thread_tx,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        let err_msg = format!(
                            "Thread: {} Error: {}",
                            thread::current().name().unwrap_or_default(),
                            e
                        );
                        logger.error(&err_msg);
                        stream = None;
                        continue;
                    }
                };
                // Si recibe un vector vacio significa que el peer respondio con un not found
                if bloques_recibidos.is_empty() {
                    break;
                }
                match block_sender_thread_tx.send(IndexedBlockList {
                    blocks: bloques_recibidos,
                    index,
                }) {
                    Ok(_) => {
                        break;
                    }
                    Err(e) => {
                        let err_msg = format!(
                            "Thread: {} Error sending blocks into block processing channel: {}",
                            thread::current().name().unwrap_or_default(),
                            e
                        );
                        logger.error(&err_msg);
                        return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                    }
                };
            }
        }

        Ok(())
    }
}

fn download_blocks(
    stream: &TcpStream,
    indexed_block_hashes: IndexedHeaderList,
    error_sender_thread_tx: Sender<Option<IndexedHeaderList>>,
) -> Result<Vec<Vec<u8>>, std::io::Error> {
    let hashes_clone = indexed_block_hashes.clone();
    let block_hashes = indexed_block_hashes.headers;
    let mut inv = Vec::<inv::InvVec>::new();
    let block_count = block_hashes.len();
    // Mandar mensaje getData pidiendo los bloques
    for hash in block_hashes {
        inv.push(inv::InvVec::new(inv::InvType::Block, hash));
    }

    let get_data_msg = match Message::new_get_data_message(inv) {
        Ok(get_data_msg) => get_data_msg,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error creating getdata message: {}", e),
            ))
        }
    };

    match messages_handler::send_message(get_data_msg, stream) {
        Ok(_) => {}
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error sending getdata message: {}", e),
            ))
        }
    };
    // Recibir los bloques
    let mut blocks = Vec::<Vec<u8>>::new();
    for _ in 0..block_count {
        match messages_handler::receive_message_serialized(
            *b"block\x00\x00\x00\x00\x00\x00\x00",
            stream,
        ) {
            Ok(mut block) => {
                if block.is_empty() {
                    match error_sender_thread_tx.send(Some(hashes_clone)) {
                        Ok(_) => return Ok(Vec::new()),
                        Err(e) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Error sending hashes into error channel: {}", e),
                            ))
                        }
                    };
                } else {
                    blocks.push(block.drain(24..).collect());
                }
            }
            Err(_) => {
                match error_sender_thread_tx.send(Some(hashes_clone)) {
                    Ok(_) => return Ok(Vec::new()),
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Error sending hashes into error channel: {}", e),
                        ))
                    }
                };
            }
        };
    }
    match error_sender_thread_tx.send(None) {
        Ok(_) => {}
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error sending 'None' into error channel: {}", e),
            ))
        }
    };
    Ok(blocks)
}
