use crate::node::message::*;

/// Command for verAck message.
pub const COMMAND: [u8; 12] = *b"verack\x00\x00\x00\x00\x00\x00";

/// Struct containing parameters for verAck message.
/// ```
#[derive(Debug, PartialEq)]
struct MessageParams {}

/// https://developer.bitcoin.org/reference/p2p_networking.html#verack
/// The “verack” message acknowledges a previously-received “version” message,
/// informing the connecting node that it can begin to send other messages.
/// The “verack” message has no payload; for an example of a message with no payload,
/// see the message headers section.
///
/// # Arguments
///
/// * `params` - A vector of parameters to be used in the message.
///
/// ```
pub fn create_payload(
    params: Vec<DataTypes>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    parse_params(params)?;
    let payload = Vec::<DataTypes>::new();
    Ok(payload)
}

/// Parses the parameters for a verack message.
/// If the parameters are valid, a `MessageParams` struct is returned. If the parameters are invalid,
/// an error is returned.
///
/// # Arguments
///
/// * `params` - A vector of parameters to be used in the message.
///
/// ```
fn parse_params(params: Vec<DataTypes>) -> Result<MessageParams, Box<dyn std::error::Error>> {
    if !params.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid number of parameters for verAck message. Expected 0, got {}",
                params.len()
            ),
        )
        .into());
    }
    Ok(MessageParams {})
}

/// Deserializes a verAck message payload.
pub fn deserialize_payload(
    serialized_payload: &Vec<u8>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    if !serialized_payload.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid number of bytes for verAck message. Expected 0, got {}",
                serialized_payload.len()
            ),
        )
        .into());
    }
    let message_payload = Vec::<DataTypes>::new();
    Ok(message_payload)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ver_ack_deserialize() {
        use super::*;

        // Test correct payload
        let ver_ack_message = vec![];

        let deserialized_payload = deserialize_payload(&ver_ack_message).unwrap();

        let expected_payload = vec![];

        assert_eq!(deserialized_payload, expected_payload);

        // Test incorrect payload
        let ver_ack_message = vec![0x01, 0x01, 0x01, 0x01, 0x01, 0x00]; // Missing bytes for inv_vec

        assert!(deserialize_payload(&ver_ack_message).is_err());
    }

    #[test]
    fn test_get_message_payload() {
        use super::*;

        // Test correct payload
        let params = vec![];
        let payload = create_payload(params).unwrap();

        let expected_payload = vec![];

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_parse_params() {
        use super::*;

        // Test correct params
        let params = vec![];

        let message_params = parse_params(params).unwrap();

        assert_eq!(message_params, MessageParams {});

        // Test incorrect params
        let params = vec![DataTypes::UnsignedInt64(70015)];
        assert!(parse_params(params).is_err());
    }
}
