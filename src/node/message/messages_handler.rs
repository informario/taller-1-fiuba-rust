use std::io::Write;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::{io::Read, net::TcpStream};

use crate::controller::NodeMessages;
use crate::file_utils::{self, get_file_size, read_file_binary_offset};
use crate::logger::{Loggable, Logger};
use crate::node::message::{
    block, filter_clear, filter_load, get_blocks, get_data, get_headers, headers, inv,
    merkle_block, ping, pong, send_headers, tx, ver_ack, version,
};
use crate::node::storage::read_block;
use bitcoin_hashes::Hash;

use super::block::block_header::BlockHeader;
use super::compact_size::CompactSize;
use super::inv::InvType;
use super::{message_header, Message};
use super::{DataTypes, MessageHeader};
const BLOCK_HEADER_HASH_SIZE: u64 = 32;

/// Type of message to be created. Used in the `Message` struct.
/// ```
#[derive(Debug)]
pub enum MessageTypes {
    Version,
    GetHeaders,
    GetBlocks,
    GetData,
    VerAck,
    Block,
    Headers,
    SendHeaders,
    SendCmpct,
    Ping,
    Addr,
    FeeFilter,
    Inv,
    Pong,
    NotFound,
    FilterClear,
    FilterLoad,
    MerkleBlock,
    Tx,
}

impl MessageTypes {
    /// Returns the command bytes for a given message type.
    ///
    /// # Arguments
    ///
    /// command - The command bytes for the message type.
    ///
    /// ```
    pub fn from_command_bytes(command: [u8; 12]) -> Option<MessageTypes> {
        const SEND_CMPCT_COMMAND: [u8; 12] = *b"sendcmpct\x00\x00\x00";
        const ADDR_COMMAND: [u8; 12] = *b"addr\x00\x00\x00\x00\x00\x00\x00\x00";
        const FEE_FILTER_COMMAND: [u8; 12] = *b"feefilter\x00\x00\x00";
        const NOT_FOUND_COMMAND: [u8; 12] = *b"notfound\x00\x00\x00\x00";
        match command {
            version::COMMAND => Some(MessageTypes::Version),
            get_headers::COMMAND => Some(MessageTypes::GetHeaders),
            get_blocks::COMMAND => Some(MessageTypes::GetBlocks),
            get_data::COMMAND => Some(MessageTypes::GetData),
            ver_ack::COMMAND => Some(MessageTypes::VerAck),
            block::COMMAND => Some(MessageTypes::Block),
            headers::COMMAND => Some(MessageTypes::Headers),
            send_headers::COMMAND => Some(MessageTypes::SendHeaders),
            SEND_CMPCT_COMMAND => Some(MessageTypes::SendCmpct),
            ping::COMMAND => Some(MessageTypes::Ping),
            ADDR_COMMAND => Some(MessageTypes::Addr),
            FEE_FILTER_COMMAND => Some(MessageTypes::FeeFilter),
            inv::COMMAND => Some(MessageTypes::Inv),
            pong::COMMAND => Some(MessageTypes::Pong),
            NOT_FOUND_COMMAND => Some(MessageTypes::NotFound),
            filter_clear::COMMAND => Some(MessageTypes::FilterClear),
            filter_load::COMMAND => Some(MessageTypes::FilterLoad),
            merkle_block::COMMAND => Some(MessageTypes::MerkleBlock),
            tx::COMMAND => Some(MessageTypes::Tx),
            _ => None,
        }
    }
}

/// Function used for sending a message over a TCP stream. It takes a `Message` and a `TcpStream` as
/// arguments and returns a `Result` with the result of the operation.
/// The message is serialized and sent over the stream.
///
/// # Arguments
///
/// * `message` - The message to be sent.
/// * `stream` - The TCP stream to send the message over.
///
/// ```
pub fn send_message(message: Message, mut stream: &TcpStream) -> Result<(), std::io::Error> {
    let serialized_message = match message.serialize() {
        Ok(serialized_message) => serialized_message,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Error serializing message",
            ));
        }
    };
    stream.write_all(&serialized_message)?;
    stream.flush()?;

    Ok(())
}

/// Reads the header of a message from a TCP stream,
/// deserializes it and returns it.
///
/// # Arguments
///
/// * `stream` - The TCP stream over which to receive the message.
///
/// ```
fn read_header(mut stream: &TcpStream) -> Result<MessageHeader, std::io::Error> {
    let mut header: Vec<u8> = vec![0; 24];
    stream.read_exact(&mut header)?;
    let deserialized_header: MessageHeader =
        message_header::MessageHeader::deserialize_header(&header)?;
    Ok(deserialized_header)
}

/// Function used for receiving a message over a TCP stream. It takes a `[u8; 12]` and a `TcpStream` as
/// arguments and returns a `Result` with the result of the operation.
/// The message is deserialized and returned with message header included if there are no errors.
///
/// # Arguments
///
/// * `command` - The message command to be received.
/// * `stream` - The TCP stream to send the message over.
///
/// ```
pub fn receive_message_serialized(
    command: [u8; 12],
    mut stream: &TcpStream,
) -> Result<Vec<u8>, std::io::Error> {
    let mut deserialized_header: MessageHeader = read_header(stream)?;
    while deserialized_header.command != command {
        match handle_message(&deserialized_header, stream, None, None) {
            Ok(result) => {
                if let Some(message) = result {
                    return Ok(message);
                }
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Error handling message",
                ));
            }
        };
        deserialized_header = read_header(stream)?;
    }
    let mut payload: Vec<u8> = vec![0; deserialized_header.length as usize];
    stream.read_exact(&mut payload)?;
    let mut message = deserialized_header.serialize();
    message.extend(payload);
    Ok(message)
}

/// Function used for handling a message received over a TCP stream. It takes a `MessageHeader` and a `TcpStream` as
/// arguments and returns a `Result` with the result of the operation.
/// The command field of the header is read and depending on the type
/// of message it receives the function will decide how the node should respond.
///
/// # Arguments
///
/// * `message_header` - The message header to be received.
/// * `stream` - The TCP stream to send and receive messages over.
///
/// ```
pub fn handle_message(
    message_header: &MessageHeader,
    mut stream: &TcpStream,
    logger: Option<&Arc<Mutex<Logger>>>,
    thread_to_peer_listener_sender: Option<Sender<NodeMessages>>,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let message_type = match MessageTypes::from_command_bytes(message_header.command) {
        Some(message_type) => message_type,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid message_type received".to_string(),
            ));
        }
    };
    let mut payload: Vec<u8> = vec![0; message_header.length as usize];
    stream.read_exact(&mut payload)?;
    match message_type {
        MessageTypes::Version => handle_version_message(stream)?,
        MessageTypes::GetHeaders => handle_get_headers(payload, stream)?,
        MessageTypes::GetBlocks => {}
        MessageTypes::GetData => handle_get_data_message(payload, stream)?,
        MessageTypes::VerAck => {}
        MessageTypes::Block => {
            if thread_to_peer_listener_sender.is_some() {
                if let Some(logger) = logger {
                    logger.debug("Received new block message");
                };
                match handle_new_block(payload, &thread_to_peer_listener_sender) {
                    Ok(_) => {}
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Error handling new block",
                        ));
                    }
                };
            }
        }
        MessageTypes::Pong => {}
        MessageTypes::Ping => send_pong(payload, stream)?,
        MessageTypes::Headers => {
            handle_direct_headers_announcement(
                payload,
                stream,
                thread_to_peer_listener_sender,
                logger,
            )?;
        }
        MessageTypes::NotFound => return Ok(Some(handle_not_found()?)),
        MessageTypes::Addr => add_peers(payload)?,
        MessageTypes::SendCmpct => add_block_announcement_config(payload, stream)?,
        MessageTypes::FeeFilter => {}
        MessageTypes::SendHeaders => add_block_announcement_config(payload, stream)?,
        MessageTypes::Inv => {
            if thread_to_peer_listener_sender.is_some() {
                handle_inv_message(payload, stream, logger, thread_to_peer_listener_sender)?
            }
        }
        _ => {}
    };
    Ok(None)
}

pub fn handle_peer_messages(
    stream_option: &mut Option<TcpStream>,
    logger: &Arc<Mutex<Logger>>,
    thread_to_peer_listener_sender: Sender<NodeMessages>,
) -> Result<(), std::io::Error> {
    let stream = match stream_option {
        Some(stream) => stream,
        None => {
            let err_msg = "Stream option is None";
            logger.error(err_msg);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
        }
    };
    let deserialized_header: MessageHeader = read_header(stream)?;
    let command_received = match MessageTypes::from_command_bytes(deserialized_header.command) {
        Some(message_type) => message_type,
        None => {
            let err_msg = "Invalid message_type received";
            logger.error(err_msg);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
        }
    };
    logger.debug(
        format!(
            "Received command while listening for peer messages: {:?}",
            command_received
        )
        .as_str(),
    );
    match handle_message(
        &deserialized_header,
        stream,
        Some(logger),
        Some(thread_to_peer_listener_sender),
    ) {
        Ok(_) => {}
        Err(e) => {
            let err_msg = format!("Error handling message: {}", e);
            logger.error(err_msg.as_str());
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg));
        }
    };
    Ok(())
}

/// Function used for handling a `ping` message received over a TCP stream. It takes a `Vec<u8>` and a `TcpStream` as
/// arguments and returns a `Result` with the result of the operation.
/// The nonce from the payload of the ping message is read and returned
/// in the payload of a new pong message.
///
/// # Arguments
///
/// * `payload` - The payload received.
/// * `stream` - The TCP stream to send and receive messages over.
///
/// ```
fn send_pong(payload: Vec<u8>, stream: &TcpStream) -> Result<(), std::io::Error> {
    let nonce_bytes = match payload[0..8].try_into() {
        Ok(bytes) => bytes,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error extracting nonce from payload of ping message {}", e),
            ));
        }
    };
    let nonce: u64 = u64::from_le_bytes(nonce_bytes);
    let pong_message = match Message::new_pong_message(nonce) {
        Ok(message) => message,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error creating pong message {}", e),
            ));
        }
    };
    send_message(pong_message, stream)
}

fn add_peers(_payload: Vec<u8>) -> Result<(), std::io::Error> {
    Ok(())
}

fn add_block_announcement_config(
    _payload: Vec<u8>,
    _stream: &TcpStream,
) -> Result<(), std::io::Error> {
    Ok(())
}

fn handle_not_found() -> Result<Vec<u8>, std::io::Error> {
    Ok(vec![])
}

fn handle_new_inv_block(
    block_header_hashes: Vec<[u8; 32]>,
    stream: &TcpStream,
) -> Result<(), std::io::Error> {
    let last_block_header_hash_vec =
        file_utils::read_last_bytes("data/headers.dat", BLOCK_HEADER_HASH_SIZE)?;
    let last_block_header_hash: [u8; 32] = match last_block_header_hash_vec.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Error converting last_block_header_hash_vec to array",
            ));
        }
    };

    send_get_headers_message(stream, vec![last_block_header_hash])?;

    send_get_data_message(stream, block_header_hashes, InvType::Block)?;
    Ok(())
}

fn send_get_headers_message(
    stream: &TcpStream,
    block_header_hashes: Vec<[u8; 32]>,
) -> Result<(), std::io::Error> {
    let message = match Message::new_get_headers_message(70015, block_header_hashes) {
        Ok(message) => message,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error creating get_headers message {}", e),
            ));
        }
    };
    send_message(message, stream)?;
    Ok(())
}
fn handle_get_headers(payload: Vec<u8>, stream: &TcpStream) -> Result<(), std::io::Error> {
    let deserialized_payload = match get_headers::deserialize_payload(&payload) {
        Ok(inv_vec) => inv_vec,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error deserializing payload of inv message {}", e),
            ));
        }
    };

    let mut target_hash = [0; 32];
    // If target hashes were given
    if deserialized_payload.len() > 3 {
        target_hash = match deserialized_payload[2] {
            DataTypes::UnsignedInt32bytes(hash) => hash,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Error getting target hash from payload of getheaders message",
                ));
            }
        };
    }
    let mut i: u64 = 0;
    let mut found_target_hash = false;
    let mut headers;
    loop {
        let file_size = get_file_size("data/headers.dat")?;
        let offset = i * 80;
        let amount = if file_size < offset + (2000 * 80) {
            file_size - offset
        } else {
            2000 * 80
        };

        headers = read_file_binary_offset("data/headers.dat", offset, amount)?;
        if found_target_hash || amount == 0 {
            break;
        };
        for j in 0..(amount / 80) as usize {
            let header = &headers[j * 80..(j + 1) * 80];
            let previous_hash: [u8; 32] = match header[4..36].try_into() {
                Ok(previous_hash) => previous_hash,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Error converting previous_hash to array",
                    ));
                }
            };
            if previous_hash == target_hash {
                i += j as u64;
                found_target_hash = true;
                break;
            }
        }
        if !found_target_hash {
            i += amount / 80;
        }
    }
    let message = match Message::new_headers_message(headers) {
        Ok(message) => message,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error creating headers message {}", e),
            ));
        }
    };
    send_message(message, stream)?;

    Ok(())
}

fn send_get_data_message(
    stream: &TcpStream,
    hashes: Vec<[u8; 32]>,
    inv_type: inv::InvType,
) -> Result<(), std::io::Error> {
    let mut inv = Vec::<inv::InvVec>::new();
    for hash in hashes {
        inv.push(inv::InvVec::new(inv_type.to_owned(), hash));
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
    send_message(get_data_msg, stream)?;
    Ok(())
}

fn handle_get_data_message(payload: Vec<u8>, stream: &TcpStream) -> Result<(), std::io::Error> {
    let deserialized_payload: Vec<DataTypes> = match get_data::deserialize_payload(&payload) {
        Ok(deserialize_payload) => deserialize_payload,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error deserializing payload of getdata message {}", e),
            ));
        }
    };

    for item in &deserialized_payload[1..] {
        match item {
            DataTypes::InvVector(inv_vec) => {
                if inv_vec.inv_type == InvType::Block {
                    let block = match read_block(inv_vec.hash) {
                        Ok(block) => block,
                        Err(e) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Error getting block from hash {}", e),
                            ));
                        }
                    };
                    if block.is_empty() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Error getting block from hash",
                        ));
                    }
                    let deserialized_block = match block::Block::deserialize(&block) {
                        Ok(deserialize_block) => deserialize_block,
                        Err(e) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Error deserializing block {}", e),
                            ));
                        }
                    };
                    let block_message = match Message::new_block_message(deserialized_block) {
                        Ok(block_message) => block_message,
                        Err(e) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Error creating block message {}", e),
                            ));
                        }
                    };
                    send_message(block_message, stream)?;
                }
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Error getting inv vector from payload of getdata message",
                ));
            }
        }
    }

    Ok(())
}

fn handle_inv_message(
    payload: Vec<u8>,
    stream: &TcpStream,
    option_logger: Option<&Arc<Mutex<Logger>>>,
    thread_to_peer_listener_sender: Option<Sender<NodeMessages>>,
) -> Result<(), std::io::Error> {
    let deserialized_payload = match inv::deserialize_payload(&payload) {
        Ok(inv_vec) => inv_vec,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error deserializing payload of inv message {}", e),
            ));
        }
    };
    for inv_type in deserialized_payload {
        if let DataTypes::InvVector(inv_vec) = inv_type {
            match inv_vec.inv_type {
                InvType::Block => {
                    if let Some(logger) = option_logger {
                        logger.debug("Handling new block received from peer");
                    }
                    handle_standard_block_relay(
                        vec![inv_vec.hash],
                        stream,
                        &thread_to_peer_listener_sender,
                    )?;
                }
                InvType::Tx => {
                    if let Some(logger) = option_logger {
                        logger.debug("Handling new transaction received from peer");
                    }
                    handle_inv_tx_relay(
                        vec![inv_vec.hash],
                        stream,
                        &thread_to_peer_listener_sender,
                    )?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn handle_inv_tx_relay(
    transaction_id: Vec<[u8; 32]>,
    stream: &TcpStream,
    thread_to_peer_listener_sender: &Option<Sender<NodeMessages>>,
) -> Result<(), std::io::Error> {
    send_get_data_message(stream, transaction_id, InvType::Tx)?;
    match receive_message_serialized(tx::COMMAND, stream) {
        Ok(transaction) => {
            if let Some(sender) = thread_to_peer_listener_sender {
                let deserialized_transaction =
                    match tx::deserialize_payload(&transaction[24..].to_vec()) {
                        Ok(datatypes_vec) => match &datatypes_vec[0] {
                            DataTypes::Transaction(transaction) => transaction.clone(),
                            _ => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "Error deserializing transaction",
                                ));
                            }
                        },
                        Err(e) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Error deserializing transaction: {}", e),
                            ));
                        }
                    };

                match sender.send(NodeMessages::NewTransactionArrived(
                    deserialized_transaction,
                )) {
                    Ok(_) => {}
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "Error sending new transaction to peer listener thread: {}",
                                e
                            ),
                        ));
                    }
                };
            }
        }
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error obtaining new transaction from peer: {}", e),
            ))
        }
    };
    Ok(())
}

fn handle_headers(payload: Vec<u8>) -> Result<Vec<[u8; 32]>, std::io::Error> {
    let deserialized_payload = match headers::deserialize_payload(&payload) {
        Ok(headers) => headers,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error deserializing payload of headers message {}", e),
            ));
        }
    };
    validate_headers_pow(payload)?;
    let mut header_hashes = Vec::<[u8; 32]>::new();
    let mut n = 1;
    let mut counter = 6 * n - 5;
    while counter < deserialized_payload.len() {
        let hash: [u8; 32] = match deserialized_payload[counter] {
            DataTypes::UnsignedInt32bytes(headers) => headers,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Error deserializing message".to_string(),
                ));
            }
        };
        header_hashes.push(hash);
        n += 1;
        counter = 6 * n - 5;
    }

    if header_hashes.len() > 1 {
        header_hashes.remove(0);
    }
    Ok(header_hashes)
}

fn validate_headers_pow(payload: Vec<u8>) -> Result<(), std::io::Error> {
    // Validate PoW
    let header_count = match CompactSize::new_from_byte_slice(&payload) {
        Ok(compact_size) => compact_size,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error reading compact size: {}", e),
            ))
        }
    };
    let chunks = payload[header_count.bytes_consumed()..].chunks(81);
    for header in chunks {
        let header = &header[0..80];
        let deserialized_header = BlockHeader::deserialize(header);
        if !deserialized_header.validate_pow() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Error validating PoW".to_string(),
            ));
        }
    }
    Ok(())
}

fn handle_new_block(
    payload: Vec<u8>,
    thread_to_peer_listener_sender: &Option<Sender<NodeMessages>>,
) -> Result<(), std::io::Error> {
    let deserialized_payload = match block::deserialize_payload(&payload) {
        Ok(block) => block,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error deserializing payload of block message {}", e),
            ));
        }
    };
    let block_datatype = match deserialized_payload.first() {
        Some(block) => block,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No block in block message".to_string(),
            ));
        }
    };
    let block = match block_datatype {
        DataTypes::Block(block) => block,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Error deserializing block message".to_string(),
            ));
        }
    };
    let block_header = block.get_block_header();
    let block_hash: [u8; 32] = block_header.hash().to_byte_array();
    let last_two_block_header_hashes_vec =
        file_utils::read_last_bytes("data/headers.dat", 2 * BLOCK_HEADER_HASH_SIZE)?;
    let last_two_header_chunks =
        last_two_block_header_hashes_vec.chunks(BLOCK_HEADER_HASH_SIZE as usize);
    for hash in last_two_header_chunks {
        if block_hash == hash {
            return Ok(());
        }
    }
    if let Some(sender) = thread_to_peer_listener_sender {
        match sender.send(NodeMessages::NewBlockArrived(block.clone())) {
            Ok(_) => {}
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Error sending NewBlockArrived message to peer listener".to_string(),
                ));
            }
        };
    }

    file_utils::append_to_file_binary("data/headers.dat", &block_hash)?;
    Ok(())
}

fn handle_standard_block_relay(
    block_header_hashes: Vec<[u8; 32]>,
    stream: &TcpStream,
    thread_to_peer_listener_sender: &Option<Sender<NodeMessages>>,
) -> Result<(), std::io::Error> {
    handle_new_inv_block(block_header_hashes, stream)?;
    let message_headers = receive_message_serialized(headers::COMMAND, stream)?;
    let header_hashes = handle_headers(message_headers[24..].to_vec())?;
    let new_block = receive_message_serialized(block::COMMAND, stream)?;
    send_get_data_message(stream, header_hashes.clone(), InvType::Block)?;
    for _ in 0..header_hashes.len() {
        match receive_message_serialized(block::COMMAND, stream) {
            Ok(block) => {
                handle_new_block(block[24..].to_vec(), thread_to_peer_listener_sender)?;
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Error downloading blocks for new headers: {}", e),
                ))
            }
        };
    }
    handle_new_block(new_block[24..].to_vec(), thread_to_peer_listener_sender)?;
    Ok(())
}

fn handle_direct_headers_announcement(
    payload: Vec<u8>,
    stream: &TcpStream,
    thread_to_peer_listener_sender: Option<Sender<NodeMessages>>,
    logger_option: Option<&Arc<Mutex<Logger>>>,
) -> Result<(), std::io::Error> {
    if thread_to_peer_listener_sender.is_some() {
        if logger_option.is_some() {
            let logger = match logger_option {
                Some(logger) => logger,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Error getting logger".to_string(),
                    ))
                }
            };
            logger.debug("Received direct headers announcement from peer");
        }
        let header_hashes = handle_headers(payload)?;
        send_get_data_message(stream, header_hashes, InvType::Block)?;
        let new_block = receive_message_serialized(block::COMMAND, stream)?;
        handle_new_block(new_block[24..].to_vec(), &thread_to_peer_listener_sender)?;
    }
    Ok(())
}

fn handle_version_message(stream: &TcpStream) -> Result<(), std::io::Error> {
    // recibir version del protocolo por config
    let version_message = match Message::new_version_message(70015, 0) {
        Ok(version_message) => version_message,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error creating version message: {}", e),
            ))
        }
    };
    send_message(version_message, stream)?;
    let verack_message = match Message::new_ver_ack_message() {
        Ok(verack_message) => verack_message,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error creating verack message: {}", e),
            ))
        }
    };
    send_message(verack_message, stream)?;
    Ok(())
}
