use crate::node::message::*;

/// Number of parameters expected for getheaders message.
/* const NUM_PARAMS: usize = 3; */

/// Command for getheaders message.
pub const COMMAND: [u8; 12] = *b"getheaders\x00\x00";

/// Struct containing the parameters for a getheaders message.
struct MessageParams {
    protocol_version: i32,
    hash_count: CompactSize,
    block_header_hashes: Vec<u8>,
}

/// The “getheaders” message requests a “headers” message that provides block headers starting
/// from a particular point in the block chain. It allows a peer which has been disconnected
/// or started for the first time to get the headers it hasn’t seen yet.
/// If the parameters are valid, a vector of `DataTypes` is returned. If the parameters are invalid,
/// an `std::io::Error` is returned.
///
/// # Arguments
///
/// * `params` - A vector of parameters to be used in the message.
///              The first parameter is the protocol version.
///              The second parameter is the hash count.
///              The third parameter is the block header hashes.
/// ```
pub fn create_payload(params: Vec<DataTypes>) -> Result<Vec<DataTypes>, std::io::Error> {
    // recibe block header hashes a partir de los cuales
    // se descargan los bloques
    let message_params: MessageParams = parse_params(params)?;
    // Payload
    // hash count y block header hashes
    // tienen tamanio variable y dependen de la cantidad
    // de block header hashes que se quieran mandar
    // obtener longitud de hash_count
    let block_header_hashes_vec = match message_params.hash_count {
        CompactSize::OneByte(_) => message_params.block_header_hashes[0..32].to_vec(),
        CompactSize::TwoBytes(_) => message_params.block_header_hashes[0..64].to_vec(),
        CompactSize::FourBytes(_) => message_params.block_header_hashes[0..96].to_vec(),
        CompactSize::EightBytes(_) => message_params.block_header_hashes[0..256].to_vec(),
    };
    let block_header_hashes_slice = block_header_hashes_vec.as_slice();

    let mut payload = vec![
        DataTypes::Int32(message_params.protocol_version), // protocol_version
        DataTypes::CompactSize(message_params.hash_count), // hash count
    ];
    for u8 in block_header_hashes_slice {
        payload.push(DataTypes::UnsignedInt8(*u8)); // block header hashes
    }
    payload.push(DataTypes::UnsignedInt32bytes([0; 32])); // stop hash field to all zeroes to request a maximum-size response.

    Ok(payload)
}

/// Deserializes a getheaders message payload.
/// If the payload is valid, a vector of `DataTypes` is returned. If the payload is invalid,
/// an error is returned.
///
/// # Arguments
///
/// * `serialized_payload` - A slice of bytes representing the payload of a getheaders message.
///
/// ```
pub fn deserialize_payload(
    serialized_payload: &[u8],
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    let mut deserialized_payload = Vec::<DataTypes>::new();
    let protocol_version =
        DataTypes::UnsignedInt32(u32::from_le_bytes(serialized_payload[0..4].try_into()?));
    deserialized_payload.push(protocol_version);
    let count = CompactSize::new_from_byte_slice(&serialized_payload[4..])?;
    deserialized_payload.push(DataTypes::CompactSize(count));
    let mut consumed = count.size() + 4;
    for i in 0..count.to_u128() {
        let mut hash = [0; 32];
        hash.copy_from_slice(
            &serialized_payload[consumed + i as usize * 32..consumed + (i + 1) as usize * 32],
        );
        deserialized_payload.push(DataTypes::UnsignedInt32bytes(hash));
        consumed += 32;
    }
    let mut stop_hash = [0; 32];
    // Copy last 32 bytes of payload to stop_hash
    stop_hash.copy_from_slice(&serialized_payload[consumed..]);
    deserialized_payload.push(DataTypes::UnsignedInt32bytes(stop_hash));
    Ok(deserialized_payload)
}

/// Parses the parameters for a getheaders message.
/// If the parameters are valid, a `MessageParams` struct is returned. If the parameters are invalid,
/// an `std::io::Error` is returned.
///
/// # Arguments
///
/// * `params` - A vector of parameters to be used in the message.
///
/// ```
fn parse_params(params: Vec<DataTypes>) -> Result<MessageParams, std::io::Error> {
    let version: i32;
    let hash_count: CompactSize;
    let mut block_header_hashes: Vec<u8> = vec![];
    // primer parametro la version del protocolo
    match params[0] {
        DataTypes::Int32(i) => version = i,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid parameter type for getheaders message. Expected {}, got {:?}",
                    "UnsignedInt32", params[0]
                ),
            ))
        }
    }
    // segundo parametro el hash count
    // es un compact_size
    match params[1] {
        DataTypes::CompactSize(i) => hash_count = i,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid parameter type for getheaders message. Expected {}, got {:?}",
                    "CompactSize", params[0]
                ),
            ))
        }
    }
    // tercer parametro los block header hashes
    // cada hash ocupa 32 bytes
    for param in &params[2..] {
        match param {
            DataTypes::UnsignedInt32bytes(i) => {
                for byte in i {
                    block_header_hashes.push(*byte);
                }
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Invalid parameter type for getheaders message. Expected {}, got {:?}",
                        "UnsignedInt32", param
                    ),
                ))
            }
        }
    }
    Ok(MessageParams {
        protocol_version: version,
        hash_count,
        block_header_hashes,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    #[test]
    fn test_getheaders_deserialize() {
        let serialized = [
            127, 17, 1, 0, 1, 37, 54, 27, 178, 183, 149, 177, 28, 36, 38, 207, 94, 100, 174, 102,
            209, 211, 169, 15, 51, 164, 166, 60, 141, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let deserialized = super::deserialize_payload(&serialized).unwrap();
        assert_eq!(deserialized.len(), 4);
        assert_eq!(deserialized[0], super::DataTypes::UnsignedInt32(70015));
        assert_eq!(
            deserialized[1],
            super::DataTypes::CompactSize(super::CompactSize::OneByte(1))
        );
        assert_eq!(
            deserialized[2],
            super::DataTypes::UnsignedInt32bytes([
                37, 54, 27, 178, 183, 149, 177, 28, 36, 38, 207, 94, 100, 174, 102, 209, 211, 169,
                15, 51, 164, 166, 60, 141, 24, 0, 0, 0, 0, 0, 0, 0
            ])
        );
        assert_eq!(
            deserialized[3],
            super::DataTypes::UnsignedInt32bytes([0; 32])
        );
    }

    #[test]
    fn test_getheaders_payload() {
        use super::*;

        // Test correct payload
        let payload = create_payload(vec![
            DataTypes::Int32(2),
            DataTypes::CompactSize(CompactSize::OneByte(1)),
            DataTypes::UnsignedInt32bytes([8; 32]),
        ])
        .unwrap();

        let expected_payload = vec![
            DataTypes::Int32(2),
            // 1 block header hash
            DataTypes::CompactSize(CompactSize::OneByte(1)),
            // block header hash of size 32 bytes
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            // 32 bytes stop hash field to all zeroes to request a maximum-size response.
            DataTypes::UnsignedInt32bytes([0; 32]),
        ];
        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_getheaders_multiple_payload() -> Result<(), std::io::Error> {
        use super::*;
        // Test correct payload
        // 0xFD + 2 as uint16_t
        let hash_count: u128 = 0xFD + 2;
        let payload: Vec<DataTypes> = create_payload(vec![
            DataTypes::Int32(2),
            DataTypes::CompactSize(CompactSize::new_from_u128(hash_count).unwrap()),
            DataTypes::UnsignedInt32bytes([8; 32]),
            DataTypes::UnsignedInt32bytes([0; 32]),
        ])
        .unwrap();

        let expected_payload = vec![
            DataTypes::Int32(2),
            // 2 block header hashes
            DataTypes::CompactSize(CompactSize::TwoBytes([255, 0x00])),
            // block header hash of size 32 bytes
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            DataTypes::UnsignedInt8(8),
            // block header hash of size 32 bytes
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            DataTypes::UnsignedInt8(0),
            // 32 bytes stop hash field to all zeroes to request a maximum-size response.
            DataTypes::UnsignedInt32bytes([0; 32]),
        ];

        assert_eq!(payload, expected_payload);
        Ok(())
    }

    #[test]
    // Test correct params
    fn test_parse_params_correct_params() -> Result<(), std::io::Error> {
        use super::*;
        let params = vec![
            DataTypes::Int32(70015),
            DataTypes::CompactSize(CompactSize::OneByte(1)),
            DataTypes::UnsignedInt32bytes([0; 32]),
        ];

        let message_params = parse_params(params)?;

        assert_eq!(message_params.protocol_version, 70015);
        assert_eq!(message_params.hash_count, CompactSize::OneByte(1));
        assert_eq!(message_params.block_header_hashes, [0; 32]);
        Ok(())
    }

    #[test]
    // Test multiple correct params
    fn test_parse_params_multiple_correct_params() -> Result<(), std::io::Error> {
        use super::*;
        let params = vec![
            DataTypes::Int32(70015),
            DataTypes::CompactSize(CompactSize::OneByte(2)),
            DataTypes::UnsignedInt32bytes([8; 32]),
            DataTypes::UnsignedInt32bytes([8; 32]),
        ];

        let message_params = parse_params(params)?;

        assert_eq!(message_params.protocol_version, 70015);
        assert_eq!(message_params.hash_count, CompactSize::OneByte(2));
        let mut hash1 = vec![];
        hash1.write_all(&message_params.block_header_hashes)?;
        assert_eq!(hash1, [8; 64]);
        Ok(())
    }

    #[test]
    // Test incorrect number of params
    fn test_parse_params_incorrect_params() -> Result<(), std::io::Error> {
        use super::*;
        let params = vec![DataTypes::Int32(70015), DataTypes::Int32(70015)];
        assert!(parse_params(params).is_err());
        Ok(())
    }

    #[test]
    // Test incorrect param type
    fn test_parse_params_incorrect_param_type() -> Result<(), std::io::Error> {
        use super::*;
        let params = vec![DataTypes::UnsignedInt64(70015)];
        assert!(parse_params(params).is_err());
        Ok(())
    }
}
