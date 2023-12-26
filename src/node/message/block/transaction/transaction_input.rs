use crate::node::message::*;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Struct for transaction input.
/// https://reference.cash/protocol/blockchain/transaction#transaction-input
/// ```
pub struct TransactionInput {
    pub previous_output_tx_hash: [u8; 32],
    pub previous_output_index: u32,
    pub script_length: CompactSize, // CompactSize, 1, 3, 5 or 9 bytes
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(
        previous_output_tx_hash: [u8; 32],
        previous_output_index: u32,
        script_length: CompactSize,
        script_sig: Vec<u8>,
        sequence: u32,
    ) -> Self {
        Self {
            previous_output_tx_hash,
            previous_output_index,
            script_length,
            script_sig,
            sequence,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::<u8>::new();
        serialized.extend(self.previous_output_tx_hash);
        serialized.extend(self.previous_output_index.to_le_bytes().iter().cloned());
        serialized.extend(self.script_length.serialize());
        serialized.extend(self.script_sig.clone());
        serialized.extend(self.sequence.to_le_bytes().iter().cloned());
        serialized
    }

    /// Deserialize a transaction input from a byte slice.
    /// Returns a tuple of the transaction input and the number of bytes consumed.
    /// https://daniel.perez.sh/blog/2020/bitcoin-format/#transaction-input
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing a serialized transaction input.
    ///
    /// ```
    pub fn deserialize(bytes: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        let mut bytes_consumed: usize = 0;
        let mut previous_output_tx_hash = [0u8; 32];
        previous_output_tx_hash.copy_from_slice(&bytes[0..32]);
        let mut previous_output_index = [0u8; 4];
        previous_output_index.copy_from_slice(&bytes[32..36]);
        let script_length = CompactSize::new_from_byte_slice(
            bytes[36..36 + CompactSize::MAX_BYTES_CONSUMED].try_into()?,
        )?;
        bytes_consumed += 36 + script_length.bytes_consumed();

        let mut script_sig = Vec::<u8>::new();

        script_sig
            .extend(&bytes[bytes_consumed..bytes_consumed + script_length.to_u128() as usize]);

        bytes_consumed += script_length.to_u128() as usize;
        let mut sequence = [0u8; 4];
        sequence.copy_from_slice(bytes[bytes_consumed..bytes_consumed + 4].try_into()?);
        bytes_consumed += 4;
        Ok((
            Self {
                previous_output_tx_hash,
                previous_output_index: u32::from_le_bytes(previous_output_index),
                script_length,
                script_sig,
                sequence: u32::from_le_bytes(sequence),
            },
            bytes_consumed,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::message::CompactSize;

    #[test]
    fn test_serialize() {}

    #[test]
    fn test_deserialize() {
        let serialized = vec![
            0x7b, 0x1e, 0xab, 0xe0, 0x20, 0x9b, 0x1f, 0xe7, 0x94, 0x12, 0x45, 0x75, 0xef, 0x80,
            0x70, 0x57, 0xc7, 0x7a, 0xda, 0x21, 0x38, 0xae, 0x4f, 0xa8, 0xd6, 0xc4, 0xde, 0x03,
            0x98, 0xa1, 0x4f, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x49, 0x48, 0x30, 0x45, 0x02, 0x21,
            0x00, 0x89, 0x49, 0xf0, 0xcb, 0x40, 0x00, 0x94, 0xad, 0x2b, 0x5e, 0xb3, 0x99, 0xd5,
            0x9d, 0x01, 0xc1, 0x4d, 0x73, 0xd8, 0xfe, 0x6e, 0x96, 0xdf, 0x1a, 0x71, 0x50, 0xde,
            0xb3, 0x88, 0xab, 0x89, 0x35, 0x02, 0x20, 0x79, 0x65, 0x60, 0x90, 0xd7, 0xf6, 0xba,
            0xc4, 0xc9, 0xa9, 0x4e, 0x0a, 0xad, 0x31, 0x1a, 0x42, 0x68, 0xe0, 0x82, 0xa7, 0x25,
            0xf8, 0xae, 0xae, 0x05, 0x73, 0xfb, 0x12, 0xff, 0x86, 0x6a, 0x5f, 0x01, 0xff, 0xff,
            0xff, 0xff,
        ];

        let (deserialized, bytes_consumed) = TransactionInput::deserialize(&serialized).unwrap();
        let expected_output = TransactionInput::new(
            [
                0x7b, 0x1e, 0xab, 0xe0, 0x20, 0x9b, 0x1f, 0xe7, 0x94, 0x12, 0x45, 0x75, 0xef, 0x80,
                0x70, 0x57, 0xc7, 0x7a, 0xda, 0x21, 0x38, 0xae, 0x4f, 0xa8, 0xd6, 0xc4, 0xde, 0x03,
                0x98, 0xa1, 0x4f, 0x3f,
            ],
            00000000,
            CompactSize::OneByte(0x49),
            vec![
                0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0x89, 0x49, 0xf0, 0xcb, 0x40, 0x00, 0x94, 0xad,
                0x2b, 0x5e, 0xb3, 0x99, 0xd5, 0x9d, 0x01, 0xc1, 0x4d, 0x73, 0xd8, 0xfe, 0x6e, 0x96,
                0xdf, 0x1a, 0x71, 0x50, 0xde, 0xb3, 0x88, 0xab, 0x89, 0x35, 0x02, 0x20, 0x79, 0x65,
                0x60, 0x90, 0xd7, 0xf6, 0xba, 0xc4, 0xc9, 0xa9, 0x4e, 0x0a, 0xad, 0x31, 0x1a, 0x42,
                0x68, 0xe0, 0x82, 0xa7, 0x25, 0xf8, 0xae, 0xae, 0x05, 0x73, 0xfb, 0x12, 0xff, 0x86,
                0x6a, 0x5f, 0x01,
            ],
            u32::from_le_bytes([0xff, 0xff, 0xff, 0xff]),
        );
        assert_eq!(deserialized, expected_output);
        assert_eq!(bytes_consumed, serialized.len());

        let serialized = [
            40, 206, 16, 199, 24, 144, 38, 134, 107, 207, 193, 208, 107, 39, 137, 129, 221, 242,
            30, 192, 227, 100, 226, 142, 41, 67, 101, 181, 195, 40, 205, 67, // prev_txid
            1, 0, 0, 0, // prev_index
            253, 70, 1, // script length
            0, 73, 48, 70, 2, 33, 0, 167, 143, 24, 15, 88, 81, 235, 233, 222, 126, 106, 230, 248,
            142, 207, 54, 237, 159, 22, 94, 93, 241, 225, 126, 236, 22, 178, 46, 99, 151, 220, 11,
            2, 33, 0, 195, 174, 136, 64, 2, 148, 174, 70, 70, 101, 214, 59, 128, 53, 241, 222, 75,
            177, 157, 221, 124, 192, 204, 92, 29, 90, 63, 226, 143, 79, 202, 231, 1, 71, 48, 68, 2,
            32, 111, 3, 92, 228, 54, 250, 48, 112, 56, 191, 75, 172, 21, 168, 185, 127, 173, 179,
            200, 9, 182, 217, 40, 158, 174, 125, 224, 208, 249, 213, 39, 177, 2, 32, 38, 83, 77,
            105, 91, 226, 215, 173, 190, 189, 165, 210, 196, 205, 238, 131, 226, 112, 21, 238, 211,
            42, 95, 249, 80, 236, 241, 54, 161, 219, 133, 118, 1, 71, 48, 68, 2, 32, 26, 10, 106,
            192, 244, 136, 231, 220, 143, 199, 201, 172, 165, 215, 155, 84, 29, 96, 215, 173, 26,
            175, 97, 245, 94, 229, 126, 97, 255, 45, 171, 74, 2, 32, 2, 103, 191, 204, 229, 39,
            129, 13, 122, 245, 74, 48, 235, 251, 12, 237, 55, 26, 162, 75, 247, 121, 30, 231, 36,
            116, 197, 255, 87, 3, 211, 82, 1, 76, 105, 83, 33, 2, 202, 42, 129, 10, 177, 114, 73,
            182, 3, 58, 3, 141, 229, 99, 152, 56, 129, 180, 6, 146, 112, 24, 63, 60, 10, 186, 148,
            86, 83, 228, 66, 22, 33, 3, 244, 128, 241, 182, 72, 208, 213, 22, 120, 4, 173, 77, 88,
            110, 14, 117, 124, 195, 63, 222, 14, 19, 63, 208, 54, 228, 93, 96, 210, 219, 89, 225,
            33, 3, 193, 129, 49, 216, 222, 153, 212, 95, 183, 42, 119, 76, 171, 12, 204, 37, 140,
            210, 171, 217, 96, 86, 16, 218, 32, 185, 162, 50, 200, 138, 60, 182, 83, 174, 255, 255,
            255, 255, // sequence
        ];

        let (deserialized, bytes_consumed) = TransactionInput::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.previous_output_index, 1);
        assert_eq!(
            deserialized.script_length,
            CompactSize::new_from_byte_slice(&[253, 70, 1]).unwrap()
        );
        assert_eq!(
            deserialized.previous_output_tx_hash,
            [
                40, 206, 16, 199, 24, 144, 38, 134, 107, 207, 193, 208, 107, 39, 137, 129, 221,
                242, 30, 192, 227, 100, 226, 142, 41, 67, 101, 181, 195, 40, 205, 67,
            ]
        );
        assert_eq!(
            deserialized.script_sig,
            [
                0, 73, 48, 70, 2, 33, 0, 167, 143, 24, 15, 88, 81, 235, 233, 222, 126, 106, 230,
                248, 142, 207, 54, 237, 159, 22, 94, 93, 241, 225, 126, 236, 22, 178, 46, 99, 151,
                220, 11, 2, 33, 0, 195, 174, 136, 64, 2, 148, 174, 70, 70, 101, 214, 59, 128, 53,
                241, 222, 75, 177, 157, 221, 124, 192, 204, 92, 29, 90, 63, 226, 143, 79, 202, 231,
                1, 71, 48, 68, 2, 32, 111, 3, 92, 228, 54, 250, 48, 112, 56, 191, 75, 172, 21, 168,
                185, 127, 173, 179, 200, 9, 182, 217, 40, 158, 174, 125, 224, 208, 249, 213, 39,
                177, 2, 32, 38, 83, 77, 105, 91, 226, 215, 173, 190, 189, 165, 210, 196, 205, 238,
                131, 226, 112, 21, 238, 211, 42, 95, 249, 80, 236, 241, 54, 161, 219, 133, 118, 1,
                71, 48, 68, 2, 32, 26, 10, 106, 192, 244, 136, 231, 220, 143, 199, 201, 172, 165,
                215, 155, 84, 29, 96, 215, 173, 26, 175, 97, 245, 94, 229, 126, 97, 255, 45, 171,
                74, 2, 32, 2, 103, 191, 204, 229, 39, 129, 13, 122, 245, 74, 48, 235, 251, 12, 237,
                55, 26, 162, 75, 247, 121, 30, 231, 36, 116, 197, 255, 87, 3, 211, 82, 1, 76, 105,
                83, 33, 2, 202, 42, 129, 10, 177, 114, 73, 182, 3, 58, 3, 141, 229, 99, 152, 56,
                129, 180, 6, 146, 112, 24, 63, 60, 10, 186, 148, 86, 83, 228, 66, 22, 33, 3, 244,
                128, 241, 182, 72, 208, 213, 22, 120, 4, 173, 77, 88, 110, 14, 117, 124, 195, 63,
                222, 14, 19, 63, 208, 54, 228, 93, 96, 210, 219, 89, 225, 33, 3, 193, 129, 49, 216,
                222, 153, 212, 95, 183, 42, 119, 76, 171, 12, 204, 37, 140, 210, 171, 217, 96, 86,
                16, 218, 32, 185, 162, 50, 200, 138, 60, 182, 83, 174,
            ]
        );
        assert_eq!(deserialized.sequence, 4294967295);
        assert_eq!(bytes_consumed, 369);
    }
}
