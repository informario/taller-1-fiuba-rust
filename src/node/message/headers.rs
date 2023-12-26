use crate::node::message::*;

/// Command for headers message.
pub const COMMAND: [u8; 12] = *b"headers\x00\x00\x00\x00\x00";

pub fn create_payload(headers: Vec<u8>) -> Result<Vec<DataTypes>, Box<dyn Error>> {
    let mut payload = vec![];
    payload.push(DataTypes::CompactSize(CompactSize::new_from_u128(
        (headers.len() / 80) as u128,
    )?));
    for header in headers.chunks(80) {
        payload.push(DataTypes::BlockHeader(BlockHeader::deserialize(header)));
        payload.push(DataTypes::UnsignedInt8(0));
    }
    Ok(payload)
}

/// Block header struct size
// const HEADER_SIZE: usize = 81;

/// Deserializes a headers payload:
///
/// bytes: Varies, name: count, data type: compactSizeuint
///
/// bytes: Varies, name: block_header, data type: block_header
///
/// Block headers are serialized in the 80-byte format described below:
///
/// bytes: 4, name: version, data type: int32_t
///
/// bytes: 32, name: previous block header hash, data type: char[32]
///
/// bytes: 32, name: merkle root hash, data type: char[32]
///
/// bytes: 4, name: time, data type: uint32_t
///
/// bytes: 4, name: nBits, data type: uint32_t
///
/// bytes: 4, name: nonce, data type: uint32_t
///
/// And they also have a 0x00 suffix.
pub fn deserialize_payload(serialized_payload: &[u8]) -> Result<Vec<DataTypes>, std::io::Error> {
    let mut message_payload = Vec::<DataTypes>::new();
    let mut header_counter = 0;
    // length of the payload
    let length_buffer = &serialized_payload[..9];
    let compact_size_bytes: usize;
    let length_buffer_u128: u128;
    match length_buffer[0] {
        x if x < 0xfd => {
            length_buffer_u128 = u128::from_le_bytes([
                length_buffer[0],
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]);
            compact_size_bytes = 1;
        }
        x if x == 0xfd => {
            length_buffer_u128 = u128::from_le_bytes([
                length_buffer[1],
                length_buffer[2],
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]);
            compact_size_bytes = 3;
        }
        x if x == 0xfe => {
            length_buffer_u128 = u128::from_le_bytes([
                length_buffer[1],
                length_buffer[2],
                length_buffer[3],
                length_buffer[4],
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]);
            compact_size_bytes = 5;
        }
        x if x == 0xff => {
            length_buffer_u128 = u128::from_le_bytes([
                length_buffer[1],
                length_buffer[2],
                length_buffer[3],
                length_buffer[4],
                length_buffer[5],
                length_buffer[6],
                length_buffer[7],
                length_buffer[8],
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]);
            compact_size_bytes = 9;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid compactSize length of payload.".to_string(),
            ))
        }
    };
    // casteo a usize
    let header_count = length_buffer_u128 as usize;
    // Deserialize 80 byte block header + 0x00 suffix
    let mut printed = false;
    while header_counter < header_count {
        // Deserialize version
        match serialized_payload[(81 * header_counter) + compact_size_bytes
            ..(81 * header_counter) + 4 + compact_size_bytes]
            .try_into()
        {
            Ok(version) => message_payload.push(DataTypes::Int32(i32::from_le_bytes(version))),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to i32",
                ))
            }
        }
        // Deserialize previous block header hash
        match serialized_payload[(81 * header_counter) + 4 + compact_size_bytes
            ..(81 * header_counter) + 36 + compact_size_bytes]
            .try_into()
        {
            Ok(previous_block_header_hash) => {
                message_payload.push(DataTypes::UnsignedInt32bytes(previous_block_header_hash));
                if *previous_block_header_hash.first().unwrap() == 0
                    && *previous_block_header_hash.get(1).unwrap() == 0
                    && !printed
                {
                    printed = true;
                }
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to i32",
                ))
            }
        }

        // Deserialize merkle root hash
        match serialized_payload[(81 * header_counter) + 36 + compact_size_bytes
            ..(81 * header_counter) + 68 + compact_size_bytes]
            .try_into()
        {
            Ok(merkle_root_hash) => {
                message_payload.push(DataTypes::UnsignedInt32bytes(merkle_root_hash))
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to i32",
                ))
            }
        }
        // Deserialize time
        match serialized_payload[(81 * header_counter) + 68 + compact_size_bytes
            ..(81 * header_counter) + 72 + compact_size_bytes]
            .try_into()
        {
            Ok(time) => message_payload.push(DataTypes::UnsignedInt32(u32::from_le_bytes(time))),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to u32",
                ))
            }
        }
        // Deserialize nBits
        match serialized_payload[(81 * header_counter) + 72 + compact_size_bytes
            ..(81 * header_counter) + 76 + compact_size_bytes]
            .try_into()
        {
            Ok(nbits) => message_payload.push(DataTypes::UnsignedInt32(u32::from_le_bytes(nbits))),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to u32",
                ))
            }
        }
        // Deserialize nonce
        match serialized_payload[(81 * header_counter) + 76 + compact_size_bytes
            ..(81 * header_counter) + 80 + compact_size_bytes]
            .try_into()
        {
            Ok(nonce) => message_payload.push(DataTypes::UnsignedInt32(u32::from_le_bytes(nonce))),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to u32",
                ))
            }
        }
        header_counter += 1;
    }
    Ok(message_payload)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_headers_deserialize() -> Result<(), std::io::Error> {
        use super::*;

        // Test correct payload
        let time = 1682890663;
        let headers_message = vec![
            1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 167, 223, 78, 100, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let deserialized_headers_message = deserialize_payload(&headers_message)?;
        let expected_headers_message = vec![
            // compactSize count
            //DataTypes::UnsignedInt8(1),
            // version message
            DataTypes::Int32(2),
            // previous block header hash
            DataTypes::UnsignedInt32bytes([0; 32]),
            // merkle root hash
            DataTypes::UnsignedInt32bytes([0; 32]),
            // time
            DataTypes::UnsignedInt32(time),
            // nBits
            DataTypes::UnsignedInt32(0),
            // nonce
            DataTypes::UnsignedInt32(0),
        ];
        assert_eq!(deserialized_headers_message, expected_headers_message);

        Ok(())
    }

    #[test]
    fn test_headers_deserialize_two_headers() -> Result<(), std::io::Error> {
        use super::*;

        // Test correct payload
        let time = 1682890663;
        let headers_message = vec![
            2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 167, 223, 78, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 167, 223, 78, 100, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let deserialized_headers_message = deserialize_payload(&headers_message)?;
        let expected_headers_message = vec![
            // version message
            DataTypes::Int32(2),
            // previous block header hash
            DataTypes::UnsignedInt32bytes([0; 32]),
            // merkle root hash
            DataTypes::UnsignedInt32bytes([0; 32]),
            // time
            DataTypes::UnsignedInt32(time),
            // nBits
            DataTypes::UnsignedInt32(0),
            // nonce
            DataTypes::UnsignedInt32(0),
            // version message
            DataTypes::Int32(2),
            // previous block header hash
            DataTypes::UnsignedInt32bytes([0; 32]),
            // merkle root hash
            DataTypes::UnsignedInt32bytes([0; 32]),
            // time
            DataTypes::UnsignedInt32(time),
            // nBits
            DataTypes::UnsignedInt32(0),
            // nonce
            DataTypes::UnsignedInt32(0),
        ];
        assert_eq!(deserialized_headers_message, expected_headers_message);
        Ok(())
    }

    #[test]
    fn test_headers_deserialize_257_headers() -> Result<(), std::io::Error> {
        use super::*;

        // Test correct payload
        let time = 1682890663;
        let mut headers_message: Vec<u8> = Vec::<u8>::new();
        let size: u128 = 2000;
        let size_bytes = size.to_le_bytes();
        headers_message.push(0xfd);
        headers_message.push(size_bytes[0]);
        headers_message.push(size_bytes[1]);
        let mut expected_headers_message: Vec<DataTypes> = Vec::<DataTypes>::new();
        for _ in 0..size {
            // construct serialized headers
            headers_message.push(2);
            for _ in 0..67 {
                headers_message.resize(headers_message.len() + 1, 0);
            }
            headers_message.push(167);
            headers_message.push(223);
            headers_message.push(78);
            headers_message.push(100);
            for _ in 0..8 {
                headers_message.resize(headers_message.len() + 1, 0);
            }
            // 0x00 suffix
            headers_message.push(0);

            // construct expected headers
            // version message
            expected_headers_message.push(DataTypes::Int32(2));
            // previous block header hash
            expected_headers_message.push(DataTypes::UnsignedInt32bytes([0; 32]));
            // merkle root hash
            expected_headers_message.push(DataTypes::UnsignedInt32bytes([0; 32]));
            // time
            expected_headers_message.push(DataTypes::UnsignedInt32(time));
            // nBits
            expected_headers_message.push(DataTypes::UnsignedInt32(0));
            // nonce
            expected_headers_message.push(DataTypes::UnsignedInt32(0));
        }
        let deserialized_headers_message = deserialize_payload(&headers_message)?;
        assert_eq!(deserialized_headers_message, expected_headers_message);
        Ok(())
    }
}
