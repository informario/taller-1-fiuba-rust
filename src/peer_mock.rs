use std::{
    net::TcpStream,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::node::{
    message::{
        block::{block_header::hash_from_serialized, Block},
        compact_size::CompactSize,
        inv::{InvType, InvVec},
        messages_handler,
    },
    stream_handler,
};
use crate::{logger::Loggable, node::message::Message};

pub(crate) struct PeerMock;
const PROTOCOL_VERSION: i32 = 70015;
const TIME_UNTIL_START: u64 = 40;
const PORT: &str = "18333";

impl PeerMock {
    pub fn run(logger: Arc<Mutex<super::Logger>>) -> Result<(), std::io::Error> {
        logger.info("Starting peer mock");
        loop {
            logger.debug("Peer mock request time started");
            thread::sleep(Duration::from_secs(TIME_UNTIL_START));
            match TcpStream::connect("localhost:".to_owned() + PORT) {
                Ok(stream) => {
                    logger.debug(&format!(
                        "Successfully connected to server in port {}",
                        PORT
                    ));
                    Self::handshake_server(&stream, &logger)?;
                    Self::send_ping(&stream, &logger)?;
                    let headers = Self::send_getheaders(&stream, &logger)?;
                    if headers.len() > 10 {
                        let mut block_hashes = Vec::new();
                        for header in headers.iter().take(10) {
                            block_hashes.push(hash_from_serialized(header)[..].try_into().unwrap());
                        }
                        let blocks = Self::send_getdata(&stream, &logger, block_hashes)?;
                        logger.debug(&format!("Received blocks: {:?}", blocks));
                    }
                    stream.shutdown(std::net::Shutdown::Both)?;
                    break;
                }
                Err(e) => {
                    let err_msg = format!("Failed to connect to server in {}: {}", PORT, e);
                    logger.error(&err_msg);
                    continue;
                }
            }
        }
        Ok(())
    }
    fn handshake_server(
        stream: &TcpStream,
        logger: &Arc<Mutex<super::Logger>>,
    ) -> Result<(), std::io::Error> {
        logger.debug("Peer mock starting handshake");
        match stream_handler::handshake(stream, PROTOCOL_VERSION) {
            Ok(_) => {}
            Err(e) => {
                let err_msg = format!("Error in handshake: {}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
            }
        }
        logger.debug("Peer mock handshake successful");
        Ok(())
    }

    fn send_ping(
        stream: &TcpStream,
        logger: &Arc<Mutex<super::Logger>>,
    ) -> Result<(), std::io::Error> {
        logger.debug("Peer mock sending ping message");
        let message = match Message::new_ping_message() {
            Ok(message) => message,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Error creating version message: {}", e),
                ))
            }
        };
        messages_handler::send_message(message, stream)?;
        logger.debug("Peer mock receiving pong message");
        let pong_message = messages_handler::receive_message_serialized(
            *b"pong\x00\x00\x00\x00\x00\x00\x00\x00",
            stream,
        )?;
        logger.debug(&format!("Received pong message: {:?}", pong_message));
        Ok(())
    }

    fn send_getdata(
        stream: &TcpStream,
        logger: &Arc<Mutex<super::Logger>>,
        block_hashes: Vec<[u8; 32]>,
    ) -> Result<Vec<Block>, std::io::Error> {
        logger.debug("Peer mock sending getdata message");
        let mut inventory = Vec::new();
        for hash in block_hashes.iter() {
            let inv_type = InvType::Block;
            inventory.push(InvVec::new(inv_type, *hash));
        }
        let inv_count = inventory.len();
        let message = match Message::new_get_data_message(inventory) {
            Ok(message) => message,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Error creating version message: {}", e),
                ))
            }
        };
        messages_handler::send_message(message, stream)?;
        logger.debug("Peer mock receiving block messages");
        let mut blocks = Vec::new();
        for _ in 0..inv_count {
            let block_message = messages_handler::receive_message_serialized(
                *b"block\x00\x00\x00\x00\x00\x00\x00",
                stream,
            )?;
            logger.debug(&format!("Received block message: {:?}", block_message));
            let serialized_payload = &block_message[24..];
            let block = match Block::deserialize(serialized_payload) {
                Ok(block) => block,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Error reading block: {}", e),
                    ))
                }
            };
            blocks.push(block);
        }
        Ok(blocks)
    }

    fn send_getheaders(
        stream: &TcpStream,
        logger: &Arc<Mutex<super::Logger>>,
    ) -> Result<Vec<[u8; 80]>, std::io::Error> {
        logger.debug("Peer mock sending getheaders message");
        let hash = [
            214, 122, 21, 172, 97, 102, 197, 230, 169, 118, 55, 57, 87, 143, 88, 115, 207, 203,
            215, 72, 190, 194, 181, 84, 22, 0, 0, 0, 0, 0, 0, 0,
        ]; // First block we are downloading

        // let hash = [
        //     116, 38, 165, 117, 3, 44, 89, 196, 182, 248, 218, 63, 99, 56, 211, 104, 90, 85, 74, 13,
        //     55, 224, 166, 81, 79, 0, 0, 0, 0, 0, 0, 0,
        // ]; // Newer hash
        let message = match Message::new_get_headers_message(70015, vec![hash]) {
            Ok(message) => message,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Error creating version message: {}", e),
                ))
            }
        };
        messages_handler::send_message(message, stream)?;
        logger.debug("Peer mock receiving headers message");
        let headers_message =
            messages_handler::receive_message_serialized(*b"headers\x00\x00\x00\x00\x00", stream)?;

        let serialized_payload = &headers_message[24..];
        let header_count = match CompactSize::new_from_byte_slice(serialized_payload) {
            Ok(compact_size) => compact_size,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Error reading compact size: {}", e),
                ))
            }
        };

        let bytes_consumed = header_count.bytes_consumed();
        let mut headers = Vec::<[u8; 80]>::new();
        if headers_message.len() > 25 {
            let mut first_header = [0; 80];
            first_header.copy_from_slice(&serialized_payload[bytes_consumed..bytes_consumed + 80]);
            logger.debug(&format!("First header downloaded: {:?}", first_header));
            logger.debug(&format!(
                "First header downloaded hash: {:?}",
                hash_from_serialized(&first_header)
            ));
            let mut last_header = [0; 81];
            last_header.copy_from_slice(&headers_message[headers_message.len() - 81..]);
            logger.debug(&format!("Last header downloaded: {:?}", last_header));
            logger.debug(&format!(
                "Last header downloaded hash: {:?}",
                hash_from_serialized(&last_header[0..80])
            ));

            for chunck in serialized_payload[bytes_consumed..].chunks(81) {
                let mut header = [0; 80];
                header.copy_from_slice(&chunck[0..80]);
                headers.push(header);
            }
        }

        Ok(headers)
    }
}
