use crate::{
    config::Config,
    controller::NodeMessages,
    file_utils::{file_exists, get_file_size, read_last_bytes},
    logger::Loggable,
    node::{
        stream_handler::{StreamHandler, StreamHandlerTrait},
        IndexedHeaderList,
    },
};
use std::{
    net::TcpStream,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Mutex, PoisonError,
    },
};

use crate::file_utils;
use crate::node;

use super::{
    message::{
        self, block::block_header::hash_from_serialized, compact_size::CompactSize,
        messages_handler, Message,
    },
    BLOCK_DOWNLOADER_THREADS,
};

pub(crate) struct Sync;
impl Sync {
    pub fn run(
        node_controller_tx_clone: &Arc<Mutex<Sender<NodeMessages>>>,
        stream_handler_clone: &mut Arc<Mutex<StreamHandler>>,
        header_tx_vec: &[Sender<node::IndexedHeaderList>],
        error_receiver_rx: &Receiver<Option<node::IndexedHeaderList>>,
        logger: Arc<Mutex<super::Logger>>,
        config: Config,
    ) -> Result<(), PoisonError<Arc<Mutex<StreamHandler>>>> {
        logger.debug("Sync Thread");
        let mut last_known_header_hash: [u8; 32];
        let mut found_hash = false;
        if config.start_from_genesis {
            last_known_header_hash = config.genesis_block_header_hash;
        } else {
            last_known_header_hash = config.starting_block_header_hash;
            found_hash = true;
        }
        last_known_header_hash.reverse();
        let mut total_headers_downloaded: usize = 0;

        if file_exists("data/headers.dat") {
            if file_exists("data/first_block_height_stored.dat") {
                let bytes = match file_utils::read_file_binary("data/first_block_height_stored.dat")
                {
                    Ok(s) => s,
                    Err(e) => {
                        let err_msg = format!("Error reading first_block_height_stored.dat: {}", e);
                        logger.error(&err_msg);
                        return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                    }
                };
                let first_block_height_stored = match bytes[..].try_into() {
                    Ok(hash) => u64::from_be_bytes(hash),
                    Err(e) => {
                        let err_msg = format!("Error: {}", e);
                        logger.error(&err_msg);
                        return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                    }
                };
                logger.debug(&format!(
                    "First block height stored: {}",
                    first_block_height_stored
                ));
                let mut blocks_stored = 0;
                if file_exists("data/block_offsets.dat") {
                    // Get size of block_offsets.dat to know how many blocks are stored
                    blocks_stored = match file_utils::get_file_size("data/block_offsets.dat") {
                        Ok(s) => s / 8 - 1,
                        Err(e) => {
                            let err_msg = format!("Error: {}", e);
                            logger.error(&err_msg);
                            return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                        }
                    };
                }

                // Resize headers.dat to (first_block_height_stored+blocks_stored) * 80
                match file_utils::resize_file(
                    "data/headers.dat",
                    (first_block_height_stored + blocks_stored) * 80,
                ) {
                    Ok(_) => {}
                    Err(e) => {
                        let err_msg = format!("Error: {}", e);
                        logger.error(&err_msg);
                        return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                    }
                }

                found_hash = true;
            }
            let last_header_stored = match read_last_bytes("data/headers.dat", 80) {
                Ok(s) => s,
                Err(e) => {
                    let err_msg = format!("Error reading last 80 bytes: {}", e);
                    logger.error(&err_msg);
                    return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                }
            };
            let last_header_stored_hash = hash_from_serialized(&last_header_stored);
            match last_header_stored_hash[..].try_into() {
                Ok(hash) => last_known_header_hash = hash,
                Err(e) => {
                    let err_msg = format!("Error: {}", e);
                    logger.error(&err_msg);
                    return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                }
            }

            total_headers_downloaded = match get_file_size("data/headers.dat") {
                Ok(s) => s as usize / 80,
                Err(e) => {
                    let err_msg = format!("Error: {}", e);
                    logger.error(&err_msg);
                    return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                }
            };
            logger.debug(&format!("Last header stored: {:?}", last_known_header_hash));
        }

        let mut stream: Option<TcpStream> = None;

        // loopear hasta que devuelva menos de 2000 headers
        let mut headers_length = 2000;
        while headers_length == 2000 {
            loop {
                let node_controller_tx = match node_controller_tx_clone.lock() {
                    Ok(s) => s,
                    Err(e) => {
                        let err_msg = format!("Error getting controller lock {}", e);
                        logger.error(&err_msg);
                        continue;
                    }
                };
                if stream.is_none() {
                    // Pedir stream a stream_handler
                    stream = match stream_handler_clone.request_stream() {
                        Ok(stream) => Some(stream),
                        Err(e) => {
                            let err_msg = format!("Error: {}", e);
                            logger.error(&err_msg);
                            return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                        }
                    };
                }
                let mut headers = match download_headers_from_hash(
                    last_known_header_hash,
                    stream.as_ref().unwrap(),
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        let err_msg = format!("Error Downloading headers: {}", e);
                        logger.error(&err_msg);
                        stream = None;
                        continue;
                    }
                };
                match file_utils::append_to_file_binary(
                    "data/headers.dat",
                    headers.concat().as_slice(),
                ) {
                    Ok(_) => {}
                    Err(e) => {
                        let err_msg = format!("Error: {}", e);
                        logger.error(&err_msg);
                        return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                    }
                }
                last_known_header_hash = match headers.last() {
                    Some(header) => {
                        let hash = hash_from_serialized(header);
                        match hash[..].try_into() {
                            Ok(hash) => hash,
                            Err(e) => {
                                let err_msg = format!("Error: {}", e);
                                logger.error(&err_msg);
                                return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                            }
                        }
                    }
                    None => break,
                };

                let index: usize;
                if config.start_from_genesis && !found_hash {
                    (found_hash, index) = Self::starting_hash_is_in_headers(
                        &mut headers,
                        &mut last_known_header_hash,
                        &config,
                    );
                    if found_hash {
                        logger.debug(&format!(
                            "Found starting hash in headers: {:?}",
                            last_known_header_hash
                        ));
                        match file_utils::write_file_binary(
                            "data/first_block_height_stored.dat",
                            &u64::to_be_bytes((total_headers_downloaded + index) as u64 + 1),
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                let err_msg = format!("Error: {}", e);
                                logger.error(&err_msg);
                                return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                            }
                        }
                    }
                }
                headers_length = headers.len();
                total_headers_downloaded += headers_length;
                logger.debug(&format!(
                    "Headers downloaded: {}. Total: {}",
                    headers_length, total_headers_downloaded
                ));
                match node_controller_tx
                    .send(NodeMessages::HeadersDownloaded(total_headers_downloaded))
                {
                    Ok(_) => {}
                    Err(e) => logger.error(&format!("Error: {:?}", e)),
                };
                if !found_hash {
                    break;
                }
                if headers.len() > BLOCK_DOWNLOADER_THREADS {
                    let chunk_size =
                        (headers.len() + BLOCK_DOWNLOADER_THREADS - 1) / BLOCK_DOWNLOADER_THREADS;
                    let mut header_chunks = headers.chunks(chunk_size);
                    for (index, header_tx) in header_tx_vec
                        .iter()
                        .enumerate()
                        .take(BLOCK_DOWNLOADER_THREADS)
                    {
                        let headers_assigned = match header_chunks.next() {
                            Some(headers) => headers,
                            None => break,
                        };

                        let mut header_hashes = headers_assigned
                            .iter()
                            .map(|header| {
                                let mut hash = [0u8; 32];
                                hash.copy_from_slice(&header[4..36]);
                                hash
                            })
                            .collect::<Vec<[u8; 32]>>();
                        let last_header_hash = hash_from_serialized(headers.last().unwrap());
                        let last_header_hash: [u8; 32] = match last_header_hash[..].try_into() {
                            Ok(hash) => hash,
                            Err(e) => {
                                let err_msg = format!("Error: {}", e);
                                logger.error(&err_msg);
                                return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                            }
                        };
                        header_hashes.remove(0);
                        header_hashes.push(last_header_hash);
                        match header_tx.send(IndexedHeaderList {
                            headers: header_hashes.to_vec(),
                            index,
                        }) {
                            Ok(_) => {}
                            Err(e) => {
                                let err_msg = format!(
                                    "Error sending hashes into block downloader channel: {}",
                                    e
                                );
                                logger.error(&err_msg);
                                return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                            }
                        };
                    }

                    let mut i = 0;
                    while i < BLOCK_DOWNLOADER_THREADS {
                        match error_receiver_rx.recv() {
                            Ok(error) => {
                                if error.is_some() {
                                    let error = match error {
                                        Some(error) => error.clone(),
                                        None => continue,
                                    };
                                    let mut index = error.index + 1;
                                    // Evitar index out of bounds en el array de canales
                                    if index == BLOCK_DOWNLOADER_THREADS {
                                        index = 0;
                                    }
                                    match header_tx_vec[index].send(error) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            let err_msg = format!("Error resending hashes into block downloader channel: {}", e);
                                            logger.error(&err_msg);
                                            return Err(PoisonError::new(Arc::clone(
                                                stream_handler_clone,
                                            )));
                                        }
                                    };
                                } else {
                                    i += 1;
                                }
                            }
                            Err(e) => {
                                let err_msg = format!(
                                    "Block downloader thread ended before sync thread: {}",
                                    e
                                );
                                logger.error(&err_msg);
                                return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                            }
                        }
                    }
                } else {
                    let header_hashes = headers
                        .iter()
                        .map(|header| {
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&header[4..36]);
                            hash
                        })
                        .collect::<Vec<[u8; 32]>>();
                    match header_tx_vec[0].send(IndexedHeaderList {
                        headers: header_hashes,
                        index: 0,
                    }) {
                        Ok(_) => {}
                        Err(e) => {
                            let err_msg = format!(
                                "Error sending hashes into block downloader channel: {}",
                                e
                            );
                            logger.error(&err_msg);
                            return Err(PoisonError::new(Arc::clone(stream_handler_clone)));
                        }
                    };
                }
                break;
            }
        }
        logger.debug("TERMINA HILO SYNC");

        Ok(())
    }

    fn starting_hash_is_in_headers(
        headers: &mut Vec<[u8; 80]>,
        last_known_header_hash: &mut [u8; 32],
        config: &Config,
    ) -> (bool, usize) {
        let mut index = 0;
        let mut found_hash = false;
        let mut starting_block_header_hash = config.starting_block_header_hash;
        starting_block_header_hash.reverse();
        let headers_clone: &mut Vec<[u8; 80]> = headers;
        for (header_index, header) in headers_clone.iter_mut().enumerate() {
            let mut header_hash = [0u8; 32];
            header_hash.copy_from_slice(&header[4..36]);

            if header_hash == starting_block_header_hash {
                found_hash = true;
                *last_known_header_hash = header_hash.to_owned();
                *headers = headers[header_index..].to_vec();
                index = header_index;
                break;
            }
        }
        (found_hash, index)
    }
}

/// Download headers from a peer
///
/// # Arguments
///
/// * `stream` - The stream to send the messages to
/// * `hash` - The last header hash received. The hash should be in little endian
///
/// # Returns
///
/// * `Result<Vec<[u8; 80]>, std::io::Error>` - The serialized blocks in a vector
fn download_headers_from_hash(
    hash: [u8; 32],
    stream: &TcpStream,
) -> Result<Vec<[u8; 80]>, std::io::Error> {
    let header_hashes_vec: Vec<[u8; 32]> = vec![hash];
    let message = match Message::new_get_headers_message(70015, header_hashes_vec) {
        Ok(message) => message,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error creating getheaders message {}", e),
            ))
        }
    };

    messages_handler::send_message(message, stream)?;
    let two_thousand_headers_buffer =
        messages_handler::receive_message_serialized(*b"headers\x00\x00\x00\x00\x00", stream)?;
    let mut headers = Vec::<[u8; 80]>::new();

    // Validate PoW
    let serialized_payload = &two_thousand_headers_buffer[24..];
    let header_count = match CompactSize::new_from_byte_slice(serialized_payload) {
        Ok(compact_size) => compact_size,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error reading compact size: {}", e),
            ))
        }
    };
    let chunks = serialized_payload[header_count.bytes_consumed()..].chunks(81);
    for header in chunks {
        let header: [u8; 80] = match header[0..80].try_into() {
            Ok(header) => header,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Error converting header to array: {}", e),
                ))
            }
        };

        let deserialized_header = message::block::block_header::BlockHeader::deserialize(&header);
        if !deserialized_header.validate_pow() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Error validating PoW".to_string(),
            ));
        }
        headers.push(header);
    }
    Ok(headers)
}
