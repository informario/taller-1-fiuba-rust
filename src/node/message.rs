pub mod block;
pub mod compact_size;
pub mod filter_clear;
pub mod filter_load;
mod get_blocks;
pub mod get_data;
mod get_headers;
pub mod inv;
pub mod merkle_block;
mod ping;
mod pong;
mod send_headers;
pub mod tx;
mod ver_ack;
pub mod version;
use std::error::Error;
mod headers;
use self::block::block_header::BlockHeader;
use self::block::transaction::transaction_input;
use self::block::transaction::transaction_output;
use self::block::transaction::Transaction;
use self::compact_size::CompactSize;
use crate::node::message::inv::InvVec;
use bitcoin_hashes::{sha256, Hash};
use block::*;
use std::mem;
mod message_header;
pub mod messages_handler;

use message_header::MessageHeader;

#[derive(Debug)]
/// A network message.
///
/// This struct contains a header and a payload. The header contains information about the message,
/// such as its type, length, and a checksum to verify its integrity. The payload contains the
/// actual data to be sent.
///
/// ```
pub struct Message {
    pub header: MessageHeader,
    pub payload: Vec<DataTypes>,
}

impl Message {
    /// Creates a new message.
    ///
    /// # Arguments
    ///
    /// * `message_type` - The type of message to be created.
    /// * `params` - A vector of parameters to be used in the message.
    ///
    /// # Examples
    ///
    ///  message::Message::new(message::MessageTypes::Version, vec![message::DataTypes::Int32(70015)]);
    ///
    /// ```
    fn new(p: Vec<DataTypes>, comm: [u8; 12]) -> Result<Message, Box<dyn Error>> {
        let check = checksum(&p)?;
        let length = length(&p)?;

        let h = MessageHeader {
            magic: 0x0709110b,
            command: comm,
            length,
            checksum: check,
        };
        Ok(Message {
            header: h,
            payload: p,
        })
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Message, Box<dyn Error>> {
        let header = message_header::MessageHeader::deserialize_header(&bytes[0..24])?;
        let payload = deserialize_payload(&bytes[24..].to_vec(), header.command)?;
        Ok(Message { header, payload })
    }

    /// Serializes the message into a vector of bytes to be sent over the network.
    ///
    /// ```
    pub fn serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut serialized_message = Vec::new();
        serialized_message.extend(self.header.serialize());
        serialized_message.extend(serialize_payload(&self.payload)?);
        Ok(serialized_message)
    }

    /// Creates a new version message.
    ///
    /// # Arguments
    ///
    /// * `version` - The version of the node. https://developer.bitcoin.org/reference/p2p_networking.html#protocol-versions
    ///
    /// ```
    pub fn new_version_message(version: i32, services: u64) -> Result<Message, Box<dyn Error>> {
        Message::new(
            version::create_payload(vec![
                DataTypes::Int32(version),
                DataTypes::UnsignedInt64(services),
            ])?,
            version::COMMAND,
        )
    }

    pub fn new_headers_message(headers: Vec<u8>) -> Result<Message, Box<dyn Error>> {
        Message::new(headers::create_payload(headers)?, headers::COMMAND)
    }

    /// Creates a new verack message.
    /// ```
    pub fn new_ver_ack_message() -> Result<Message, Box<dyn Error>> {
        Message::new(ver_ack::create_payload(vec![])?, ver_ack::COMMAND)
    }
    /// Creates a new ping message.
    /// ```
    pub fn new_ping_message() -> Result<Message, Box<dyn Error>> {
        Message::new(ping::create_payload(vec![])?, ping::COMMAND)
    }
    /// Creates a new filterclear message.
    /// ```
    pub fn new_filter_clear_message() -> Result<Message, Box<dyn Error>> {
        Message::new(filter_clear::create_payload(vec![])?, filter_clear::COMMAND)
    }
    /// Creates a new sendheaders message.
    /// ```
    pub fn new_send_headers_message() -> Result<Message, Box<dyn Error>> {
        Message::new(send_headers::create_payload(vec![])?, send_headers::COMMAND)
    }

    /// Creates a new getData message.
    ///
    /// # Arguments
    ///
    /// * `inventory` - A vector of inventory vectors.
    ///
    /// ```
    pub fn new_get_data_message(inventory: Vec<InvVec>) -> Result<Message, Box<dyn Error>> {
        let mut params = Vec::new();
        for i in inventory {
            params.push(DataTypes::InvVector(i));
        }
        Message::new(get_data::create_payload(params)?, get_data::COMMAND)
    }
    /// Creates a new inv message.
    ///
    /// # Arguments
    ///
    /// * `inventory` - A vector of inventory vectors.
    ///
    /// ```
    pub fn new_inv_message(inventory: Vec<InvVec>) -> Result<Message, Box<dyn Error>> {
        let mut params = Vec::new();
        for i in inventory {
            params.push(DataTypes::InvVector(i));
        }
        Message::new(inv::create_payload(params)?, inv::COMMAND)
    }
    /// Creates a new tx message.
    ///
    /// # Arguments
    ///
    /// * `transaction` - The transaction to be sent.
    ///
    /// ```
    pub fn new_tx_message(transaction: Transaction) -> Result<Message, Box<dyn Error>> {
        let params = vec![DataTypes::Transaction(transaction)];
        Message::new(tx::create_payload(params)?, tx::COMMAND)
    }

    /// Creates a new getHeaders message.
    ///
    /// # Arguments
    ///
    /// * `version` - The version of the node. https://developer.bitcoin.org/reference/p2p_networking.html#protocol-versions
    /// * `block_header_hashes` - A vector of block header hashes.
    /// * `hash_stop` - The hash of the last block header hash in the vector.
    ///
    /// ```
    pub fn new_get_headers_message(
        version: i32,
        block_header_hashes: Vec<[u8; 32]>,
        //hash_stop: [u8; 32],
    ) -> Result<Message, Box<dyn Error>> {
        let mut params = Vec::new();
        params.push(DataTypes::Int32(version));
        let count: u128 = block_header_hashes.len() as u128; // no se cuenta el stop hash
        params.push(DataTypes::CompactSize(CompactSize::new_from_u128(count)?));
        for i in block_header_hashes {
            params.push(DataTypes::UnsignedInt32bytes(i));
        }
        //params.push(DataTypes::UnsignedInt32bytes(hash_stop));
        Message::new(get_headers::create_payload(params)?, get_headers::COMMAND)
    }

    /// Creates a new pong message.
    ///
    /// # Arguments
    ///
    /// * `nonce` - A random number used to identify the ping message. Should be the same as the nonce in the ping message.
    /// ```
    pub fn new_pong_message(nonce: u64) -> Result<Message, Box<dyn Error>> {
        Message::new(
            pong::create_payload(vec![DataTypes::UnsignedInt64(nonce)])?,
            pong::COMMAND,
        )
    }

    /// Creates a new block message.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to be sent.
    ///
    /// ```
    pub fn new_block_message(block: Block) -> Result<Message, Box<dyn Error>> {
        Message::new(block::create_payload(block)?, block::COMMAND)
    }
}

/// Calculates the checksum of a message payload.
///
/// # Arguments
///
/// * `payload` - A vector of `DataTypes` to be used in the checksum calculation.
///
/// ```
fn checksum(payload: &Vec<DataTypes>) -> Result<u32, Box<dyn Error>> {
    let serialized_payload = serialize_payload(payload)?;
    let first_hash = sha256::Hash::hash(serialized_payload.as_slice());
    let second_hash = sha256::Hash::hash(&first_hash[..]);
    Ok(u32::from_le_bytes(second_hash[0..4].try_into()?))
}

/// Calculates the length in bytes of a message payload.
/// The length is the sum of the size of each field in the payload.
///
/// # Arguments
///
/// * `payload` - A vector of `DataTypes` to be used in the length calculation.
///
/// ```
fn length(payload: &Vec<DataTypes>) -> Result<u32, Box<dyn Error>> {
    let serialized_payload = serialize_payload(payload)?;
    Ok(serialized_payload
        .iter()
        .fold(0, |acc, item| acc + mem::size_of_val(item) as u32))
}

/// Serializes a vector of `DataTypes` into a vector of bytes.
///
/// # Arguments
///
/// * `payload` - A vector of `DataTypes` to be serialized.
///
/// ```
fn serialize_payload(payload: &Vec<DataTypes>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut serialized_payload = Vec::new();
    for field in payload {
        match field {
            DataTypes::UnsignedInt8(i) => {
                serialized_payload.extend(u8::to_le_bytes(*i).iter().cloned())
            }
            DataTypes::Int32(i) => serialized_payload.extend(i32::to_le_bytes(*i).iter().cloned()),
            DataTypes::Int64(i) => serialized_payload.extend(i64::to_le_bytes(*i).iter().cloned()),
            DataTypes::Bool(b) => {
                serialized_payload.extend(u8::to_le_bytes(*b as u8).iter().cloned())
            }
            DataTypes::UnsignedInt32(i) => {
                serialized_payload.extend(u32::to_le_bytes(*i).iter().cloned())
            }
            DataTypes::UnsignedInt64(i) => {
                serialized_payload.extend(u64::to_le_bytes(*i).iter().cloned())
            }
            DataTypes::UnsignedInt16(i) => {
                serialized_payload.extend(u16::to_le_bytes(*i).iter().cloned())
            }
            DataTypes::UnsignedInt128(i) => {
                serialized_payload.extend(u128::to_le_bytes(*i).iter().cloned())
            }
            DataTypes::UnsignedInt32bytes(i) => {
                for byte in i {
                    serialized_payload.extend(u8::to_le_bytes(*byte).iter().cloned())
                }
            }
            DataTypes::UnsignedInt80bytes(i) => {
                for byte in i {
                    serialized_payload.extend(u8::to_le_bytes(*byte).iter().cloned())
                }
                // sufijo 0x00 para block headers
                serialized_payload.push(0);
            }
            DataTypes::String(s) => {
                serialized_payload.extend(s.as_bytes().iter().cloned());
                serialized_payload.push(0);
            }
            DataTypes::InvVector(i) => serialized_payload.extend(i.serialize().iter().cloned()),
            DataTypes::BlockHeader(i) => serialized_payload.extend(i.serialize().iter().cloned()),
            DataTypes::Transaction(i) => serialized_payload.extend(i.serialize()?.iter().cloned()),
            DataTypes::TransactionInput(i) => {
                serialized_payload.extend(i.serialize().iter().cloned())
            }
            DataTypes::TransactionOutput(i) => {
                serialized_payload.extend(i.serialize().iter().cloned())
            }
            DataTypes::CompactSize(i) => serialized_payload.extend(i.serialize().iter().cloned()),
            DataTypes::Block(i) => serialized_payload.extend(i.serialize()?.iter().cloned()),
            DataTypes::UnsignedInt32bytesVec(vec) => {
                for array in vec {
                    for byte in array {
                        serialized_payload.extend(u8::to_le_bytes(*byte).iter().cloned())
                    }
                }
            }
            DataTypes::MerkleFlags(i) => {
                for byte in i {
                    serialized_payload.extend(u8::to_le_bytes(*byte).iter().cloned())
                }
            }
            DataTypes::BloomFilter(i) => {
                for byte in i {
                    serialized_payload.extend(u8::to_le_bytes(*byte).iter().cloned())
                }
            }
        }
    }
    Ok(serialized_payload)
}

#[derive(Debug, Clone, PartialEq)]
/// A data type to be used in a network message.
/// Used in the payload of the `Message` struct to be able to handle different data types
/// in a single payload vector. This is necessary to be able to handle different types of messages in
/// a generic way.
///
/// ```
pub enum DataTypes {
    Int32(i32),
    Int64(i64),
    Bool(bool),
    UnsignedInt32(u32),
    UnsignedInt8(u8),
    UnsignedInt64(u64),
    UnsignedInt16(u16),
    UnsignedInt128(u128),
    UnsignedInt32bytes([u8; 32]),
    UnsignedInt32bytesVec(Vec<[u8; 32]>),
    UnsignedInt80bytes([u8; 80]),
    String(String),
    CompactSize(CompactSize),
    InvVector(InvVec),
    BlockHeader(block_header::BlockHeader),
    Transaction(transaction::Transaction),
    TransactionInput(transaction_input::TransactionInput),
    TransactionOutput(transaction_output::TransactionOutput),
    Block(block::Block),
    MerkleFlags(Vec<u8>),
    BloomFilter(Vec<u8>),
}

/// Deserialize a payload into a vector of `DataTypes`.
/// It takes a `Vec<u8>` as an argument and returns a `Result` with the result of the operation.
/// The payload is deserialized based on the message type.
/// The message type is determined by the command field in the message header.
///
/// # Arguments
///
/// * `payload` - The payload to deserialize.
/// * `message_type` - The message type to deserialize the payload into.
///
/// ```
pub fn deserialize_payload(
    payload: &Vec<u8>,
    message_type: [u8; 12],
) -> Result<Vec<DataTypes>, std::io::Error> {
    match message_type {
        version::COMMAND => version::deserialize_payload(payload),
        get_headers::COMMAND => match get_headers::deserialize_payload(payload) {
            Ok(data) => Ok(data),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                e.to_string(),
            )),
        },
        get_blocks::COMMAND => get_blocks::deserialize_payload(payload),
        get_data::COMMAND => match get_data::deserialize_payload(payload) {
            Ok(data) => Ok(data),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error",
            )),
        },
        ver_ack::COMMAND => match ver_ack::deserialize_payload(payload) {
            Ok(data) => Ok(data),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error",
            )),
        },
        headers::COMMAND => match headers::deserialize_payload(payload) {
            Ok(data) => Ok(data),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error",
            )),
        },
        block::COMMAND => match block::deserialize_payload(payload) {
            Ok(data) => Ok(data),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error",
            )),
        },
        pong::COMMAND => match pong::deserialize_payload(payload) {
            Ok(data) => Ok(data),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error",
            )),
        },
        ping::COMMAND => match ping::deserialize_payload(payload) {
            Ok(data) => Ok(data),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error",
            )),
        },
        send_headers::COMMAND => match send_headers::deserialize_payload(payload) {
            Ok(data) => Ok(data),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error",
            )),
        },
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid message type",
        )),
    }
}
