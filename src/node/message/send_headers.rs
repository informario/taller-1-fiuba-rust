use crate::node::message::*;

/// Command for sendheaders message.
pub const COMMAND: [u8; 12] = *b"sendheaders\x00";

/// Struct containing parameters for sendheaders message.
/// ```
#[derive(Debug, PartialEq)]
struct MessageParams {}

/// https://developer.bitcoin.org/reference/p2p_networking.html#sendheaders
/// The “sendheaders” message tells the receiving peer to send new block announcements
/// using a “headers” message rather than an “inv” message.
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

/// Parses the parameters for a sendheaders message.
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
                "Invalid number of parameters for sendheaders message. Expected 0, got {}",
                params.len()
            ),
        )
        .into());
    }
    Ok(MessageParams {})
}

/// Deserializes a sendheaders message payload.
pub fn deserialize_payload(
    serialized_payload: &Vec<u8>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    if !serialized_payload.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid number of bytes for sendheaders message. Expected 0, got {}",
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
    fn test_send_headers_deserialize() {
        use super::*;

        // Test correct payload
        let send_headers_message = vec![];

        let deserialized_payload = deserialize_payload(&send_headers_message).unwrap();

        let expected_payload = vec![];

        assert_eq!(deserialized_payload, expected_payload);

        // Test incorrect payload
        let send_headers_message = vec![0x01, 0x01, 0x01, 0x01, 0x01, 0x00];

        assert!(deserialize_payload(&send_headers_message).is_err());
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
