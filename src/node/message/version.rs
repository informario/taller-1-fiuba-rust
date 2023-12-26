use crate::node::message::*;
use chrono::prelude::*;

/// Number of parameters expected for version message.
const NUM_PARAMS: usize = 2;

/// Command for version message.
pub const COMMAND: [u8; 12] = *b"version\x00\x00\x00\x00\x00";

/// Min version payload size
const MIN_PAYLOAD_SIZE: usize = 86;

/// https://developer.bitcoin.org/reference/p2p_networking.html#version
/// The version message provides information about the transmitting node to the receiving node at the
/// beginning of a connection. Until both peers have exchanged version messages, no other messages
/// will be accepted.
///
/// Struct containing parameters for version message.
/// ```
struct MessageParams {
    protocol_version: i32,
    protocol_services: u64,
}

/// Creates a payload for a version message.
/// If the parameters are valid, a vector of `DataTypes` is returned. If the parameters are invalid,
/// an `std::io::Error` is returned.
///
/// # Arguments
///
/// * `params` - A vector of parameters to be used in the message.
///
/// ```
pub fn create_payload(params: Vec<DataTypes>) -> Result<Vec<DataTypes>, std::io::Error> {
    let message_params = parse_params(params)?;

    let payload = vec![
        DataTypes::Int32(message_params.protocol_version), // protocol_version
        DataTypes::UnsignedInt64(message_params.protocol_services), // services
        DataTypes::Int64(Local::now().timestamp()),        // timestamp
        DataTypes::UnsignedInt64(0),                       // addr_recv_services
        DataTypes::UnsignedInt128(0x0100007fffff00000000000000000000), // addr_recv_ip_address
        DataTypes::UnsignedInt16(18333),                   // addr_recv_port
        DataTypes::UnsignedInt64(0),                       // addr_trans_services
        DataTypes::UnsignedInt128(0x0100007fffff00000000000000000000), // addr_trans_ip_address
        DataTypes::UnsignedInt16(18333),                   // addr_trans_port
        DataTypes::UnsignedInt64(0),                       // nonce
        DataTypes::UnsignedInt8(0x00),                     // user_agent
        DataTypes::UnsignedInt32(0),                       // start_height
        DataTypes::UnsignedInt8(1),                        // relay
    ];
    Ok(payload)
}

/// Parses the parameters for a version message.
/// If the parameters are valid, a `MessageParams` struct is returned. If the parameters are invalid,
/// an `std::io::Error` is returned.
///
/// # Arguments
///
/// * `params` - A vector of parameters to be used in the message.
///
/// ```
fn parse_params(params: Vec<DataTypes>) -> Result<MessageParams, std::io::Error> {
    if params.len() > NUM_PARAMS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Too many parameters for version message. Expected {}, got {}",
                NUM_PARAMS,
                params.len()
            ),
        ));
    }
    let version = match params[0] {
        DataTypes::Int32(i) => i,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid parameter type for version message. Expected {}, got {:?}",
                    "UnsignedInt32", params[0]
                ),
            ))
        }
    };
    let services = match params[1] {
        DataTypes::UnsignedInt64(i) => i,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid parameter type for version message. Expected {}, got {:?}",
                    "UnsignedInt64", params[0]
                ),
            ))
        }
    };
    Ok(MessageParams {
        protocol_version: version,
        protocol_services: services,
    })
}

/// Deserializes a version message payload.
pub fn deserialize_payload(serialized_payload: &Vec<u8>) -> Result<Vec<DataTypes>, std::io::Error> {
    if serialized_payload.len() < MIN_PAYLOAD_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid length for version message. Expected {}, got {}",
                86,
                serialized_payload.len()
            ),
        ));
    }
    let calculated_user_agent_size = serialized_payload.len() - MIN_PAYLOAD_SIZE;

    let mut message_payload = Vec::<DataTypes>::new();
    match serialized_payload[0..4].try_into() {
        Ok(val) => message_payload.push(DataTypes::Int32(i32::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to i32",
            ))
        }
    } // protocol_version
    match serialized_payload[4..12].try_into() {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt64(u64::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u64",
            ))
        }
    } // services
    match serialized_payload[12..20].try_into() {
        Ok(val) => message_payload.push(DataTypes::Int64(i64::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to i64",
            ))
        }
    } // timestamp
    match serialized_payload[20..28].try_into() {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt64(u64::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u64",
            ))
        }
    } // addr_recv_services
    match serialized_payload[28..44].try_into() {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt128(u128::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u128",
            ))
        }
    } // addr_recv_ip_address
    match serialized_payload[44..46].try_into() {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt16(u16::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u16",
            ))
        }
    } // addr_recv_port

    match serialized_payload[46..54].try_into() {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt64(u64::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u64",
            ))
        }
    } // addr_trans_services

    match serialized_payload[54..70].try_into() {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt128(u128::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u128",
            ))
        }
    } // addr_trans_ip_address
    match serialized_payload[70..72].try_into() {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt16(u16::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u16",
            ))
        }
    } // addr_trans_port
    match serialized_payload[72..80].try_into() {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt64(u64::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u64",
            ))
        }
    } // nonce

    let user_agent_size: u8;
    match serialized_payload[80..81].try_into() {
        Ok(val) => user_agent_size = u8::from_le_bytes(val),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u8",
            ))
        }
    } // user_agent_size
    message_payload.push(DataTypes::UnsignedInt8(user_agent_size));

    if calculated_user_agent_size > 0 {
        let val = &serialized_payload[81..(81 + calculated_user_agent_size)];
        // Insert to serialized_payload the slice as a string using ascii encoding
        message_payload.push(DataTypes::String(String::from_utf8_lossy(val).to_string()));
        // user_agent
    }

    match serialized_payload[(81 + calculated_user_agent_size)..(85 + calculated_user_agent_size)]
        .try_into()
    {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt32(u32::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u32",
            ))
        }
    } // start_height
    match serialized_payload[(85 + calculated_user_agent_size)..(86 + calculated_user_agent_size)]
        .try_into()
    {
        Ok(val) => message_payload.push(DataTypes::UnsignedInt8(u8::from_le_bytes(val))),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Error converting bytes to u8",
            ))
        }
    } // relay

    // TODO
    Ok(message_payload)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_version_deserialize() {
        use super::*;

        // Test correct payload no user agent
        let version_message = vec![
            127, 17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 167, 223, 78, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1, 141, 32, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1, 141, 32, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let deserialized_version_message = deserialize_payload(&version_message).unwrap();
        let expected_version_message = vec![
            DataTypes::Int32(70015),
            DataTypes::UnsignedInt64(0),
            DataTypes::Int64(1682890663),
            DataTypes::UnsignedInt64(0),
            DataTypes::UnsignedInt128(1329238136988508772919404404731281408),
            DataTypes::UnsignedInt16(8333),
            DataTypes::UnsignedInt64(0),
            DataTypes::UnsignedInt128(1329238136988508772919404404731281408),
            DataTypes::UnsignedInt16(8333),
            DataTypes::UnsignedInt64(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt32(0),
            DataTypes::UnsignedInt8(1),
        ];
        assert_eq!(deserialized_version_message, expected_version_message);

        // Test correct payload with user agent
        let version_message = vec![
            127, 17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 167, 223, 78, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1, 141, 32, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1, 141, 32, 0, 0, 0, 0, 0, 0,
            0, 0, 7, 0x73, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0, 0, 0, 0, 1,
        ];
        let deserialized_version_message = deserialize_payload(&version_message).unwrap();

        let expected_version_message = vec![
            DataTypes::Int32(70015),
            DataTypes::UnsignedInt64(0),
            DataTypes::Int64(1682890663),
            DataTypes::UnsignedInt64(0),
            DataTypes::UnsignedInt128(1329238136988508772919404404731281408),
            DataTypes::UnsignedInt16(8333),
            DataTypes::UnsignedInt64(0),
            DataTypes::UnsignedInt128(1329238136988508772919404404731281408),
            DataTypes::UnsignedInt16(8333),
            DataTypes::UnsignedInt64(0),
            DataTypes::UnsignedInt8(7),
            DataTypes::String(
                String::from_utf8_lossy(&[0x73, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69]).to_string(),
            ),
            DataTypes::UnsignedInt32(0),
            DataTypes::UnsignedInt8(1),
        ];

        assert_eq!(deserialized_version_message, expected_version_message);

        // Test payload with incorrect length
        let version_message = vec![
            127, 17, 1, 0, 0, 0, 0, 0, 0, 0, 167, 223, 78, 100, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255,
            127, 0, 0, 1, 141, 32, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1, 141, 32, 0, 0,
            0, 0, 0, 0, 0, 0, 1,
        ];
        let deserialized_version_message = deserialize_payload(&version_message);
        assert!(deserialized_version_message.is_err());
    }

    #[test]
    fn test_version_payload() {
        use super::*;

        // Test correct payload
        let payload = create_payload(vec![DataTypes::Int32(70015)]).unwrap();

        let expected_payload = vec![
            DataTypes::Int32(70015),
            DataTypes::UnsignedInt64(0),
            DataTypes::Int64(Local::now().timestamp()),
            DataTypes::UnsignedInt64(0),
            DataTypes::UnsignedInt128(1329238136988508772919404404731281408),
            DataTypes::UnsignedInt16(8333),
            DataTypes::UnsignedInt64(0),
            DataTypes::UnsignedInt128(1329238136988508772919404404731281408),
            DataTypes::UnsignedInt16(8333),
            DataTypes::UnsignedInt64(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt32(0),
            DataTypes::UnsignedInt8(1),
        ];

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_parse_params() {
        use super::*;

        // Test correct params
        let params = vec![DataTypes::Int32(70015)];

        let message_params = parse_params(params).unwrap();

        assert_eq!(message_params.protocol_version, 70015);

        // Test incorrect number of params
        let params = vec![DataTypes::Int32(70015), DataTypes::Int32(70015)];
        assert!(parse_params(params).is_err());

        // Test incorrect param type
        let params = vec![DataTypes::UnsignedInt64(70015)];
        assert!(parse_params(params).is_err());
    }
}
