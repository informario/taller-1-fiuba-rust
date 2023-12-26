use crate::node::message::*;

/// Command for pong message.
pub const COMMAND: [u8; 12] = *b"pong\x00\x00\x00\x00\x00\x00\x00\x00";

/// Number of parameters expected for pong message.
const NUM_PARAMS: usize = 1;

/// Struct containing parameters for pong message.
/// ```
#[derive(Debug, PartialEq)]
/// Struct containing parameters for version message.
/// ```
struct MessageParams {
    nonce: u64,
}

/// https://developer.bitcoin.org/reference/p2p_networking.html#pong
/// The “pong” message replies to a “ping” message, proving to the pinging node that the ponging node is still alive.
/// Bitcoin Core will, by default, disconnect from any clients which have not responded to a “ping” message within 20 minutes.
/// To allow nodes to keep track of latency, the “pong” message sends back the same nonce received in the “ping” message it is replying to.
///
/// # Arguments
///
/// * `params` - A vector of parameters to be used in the message.
///
/// ```
pub fn create_payload(
    params: Vec<DataTypes>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    let message_params = parse_params(params)?;
    let payload = vec![
        DataTypes::UnsignedInt64(message_params.nonce), // nonce
    ];
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
    if params.len() > NUM_PARAMS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid number of parameters for pong message. Expected 1, got {}",
                params.len()
            ),
        )
        .into());
    }

    let nonce: u64 = match params[0] {
        DataTypes::UnsignedInt64(i) => i,
        _ => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid parameter type for pong message. Expected {}, got {:?}",
                    "UnsignedInt64", params[0]
                ),
            )))
        }
    };

    Ok(MessageParams { nonce })
}

/// Deserializes a pong message payload.
pub fn deserialize_payload(
    serialized_payload: &Vec<u8>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    if !serialized_payload.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid number of bytes for pong message. Expected 0, got {}",
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
    fn test_pong_deserialize() {
        use super::*;

        // Test correct payload
        let pong_message = vec![];

        let deserialized_payload = deserialize_payload(&pong_message).unwrap();

        let expected_payload = vec![];

        assert_eq!(deserialized_payload, expected_payload);

        // Test incorrect payload
        let pong_message = vec![0x01, 0x01, 0x01, 0x01, 0x01, 0x00]; // Missing bytes for inv_vec

        assert!(deserialize_payload(&pong_message).is_err());
    }

    #[test]
    fn test_get_message_payload() {
        use super::*;

        // Test correct payload
        let nonce: u64 = 10000000000000000000;
        let params = vec![DataTypes::UnsignedInt64(nonce)];
        let payload = create_payload(params).unwrap();

        let expected_payload = vec![DataTypes::UnsignedInt64(nonce)];

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_parse_params() {
        use super::*;

        // Test correct params
        let nonce: u64 = 10000000000000000000;
        let params = vec![DataTypes::UnsignedInt64(nonce)];

        let message_params = parse_params(params).unwrap();

        assert_eq!(
            message_params,
            MessageParams {
                nonce: 10000000000000000000,
            }
        );

        // Test incorrect params
        let params = vec![DataTypes::UnsignedInt32(70)];
        assert!(parse_params(params).is_err());
    }
}
