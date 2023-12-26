use crate::node::message::*;

/// Command for ping message.
pub const COMMAND: [u8; 12] = *b"ping\x00\x00\x00\x00\x00\x00\x00\x00";

/// Struct containing parameters for ping message.
/// ```
#[derive(Debug, PartialEq)]
struct MessageParams {}

/// Deserializes a ping message payload.
pub fn deserialize_payload(
    serialized_payload: &Vec<u8>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    if !serialized_payload.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid number of bytes for ping message. Expected 0, got {}",
                serialized_payload.len()
            ),
        )
        .into());
    }
    let message_payload = Vec::<DataTypes>::new();
    Ok(message_payload)
}

pub fn create_payload(
    params: Vec<DataTypes>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    parse_params(params)?;
    let payload = vec![
        DataTypes::UnsignedInt64(0), // nonce
    ];
    Ok(payload)
}

fn parse_params(params: Vec<DataTypes>) -> Result<MessageParams, Box<dyn std::error::Error>> {
    if !params.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid number of parameters for ping message. Expected 0, got {}",
                params.len()
            ),
        )
        .into());
    }
    Ok(MessageParams {})
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ping_deserialize() {
        use super::*;

        // Test correct payload
        let ping_message = vec![];

        let deserialized_payload = deserialize_payload(&ping_message).unwrap();

        let expected_payload = vec![];

        assert_eq!(deserialized_payload, expected_payload);

        // Test incorrect payload
        let ping_message = vec![0x01, 0x01, 0x01, 0x01, 0x01, 0x00]; // Missing bytes for inv_vec

        assert!(deserialize_payload(&ping_message).is_err());
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
}
