use crate::node::message::*;

/// Number of parameters expected for get_blocks message.
/* const NUM_PARAMS: usize = 3; */

/// Command for getblocks message.
pub const COMMAND: [u8; 12] = *b"getblocks\x00\x00\x00";

/// Deserializes a getblocks message.
pub fn deserialize_payload(serialized_message: &Vec<u8>) -> Result<Vec<DataTypes>, std::io::Error> {
    // let mut message_payload = Vec::<DataTypes>::new();
    // TODO
    // Ok(message_payload)
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "Not implemented yet. Got serialized message: {:?}",
            serialized_message
        ),
    ))
}
