use crate::node::message::*;

/// Structo for transaction output.
/// https://reference.cash/protocol/blockchain/transaction#transaction-output
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionOutput {
    pub value: u64,
    pub script_length: CompactSize,
    pub script: Vec<u8>,
}

impl TransactionOutput {
    pub fn new(value: u64, script_length: CompactSize, script: Vec<u8>) -> Self {
        Self {
            value,
            script_length,
            script,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::<u8>::new();
        serialized.extend(u64::to_le_bytes(self.value));
        serialized.extend(self.script_length.serialize());
        serialized.extend(self.script.clone());
        serialized
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        let mut bytes_consumed: usize = 0;
        let value = u64::from_le_bytes(bytes[0..8].try_into()?);
        bytes_consumed += 8;
        let script_length = CompactSize::new_from_byte_slice(
            bytes[bytes_consumed
                ..(bytes_consumed + CompactSize::MAX_BYTES_CONSUMED).min(bytes.len())]
                .try_into()?,
        )?;
        bytes_consumed += script_length.bytes_consumed();
        let mut script = Vec::<u8>::new();
        script.extend(&bytes[bytes_consumed..bytes_consumed + script_length.to_u128() as usize]);
        bytes_consumed += script_length.to_u128() as usize;
        Ok((
            Self {
                value,
                script_length,
                script,
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
    fn test_deserialize() {
        let bytes = [
            0xf0, 0xca, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xcb, 0xc2,
            0x0a, 0x76, 0x64, 0xf2, 0xf6, 0x9e, 0x53, 0x55, 0xaa, 0x42, 0x70, 0x45, 0xbc, 0x15,
            0xe7, 0xc6, 0xc7, 0x72, 0x88, 0xac,
        ];

        let (transaction_output, bytes_consumed) = TransactionOutput::deserialize(&bytes).unwrap();
        assert_eq!(bytes_consumed, bytes.len());
        let expected_output = TransactionOutput {
            value: u64::from_le_bytes([0xf0, 0xca, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00]),
            script_length: CompactSize::OneByte(25),
            script: vec![
                0x76, 0xa9, 0x14, 0xcb, 0xc2, 0x0a, 0x76, 0x64, 0xf2, 0xf6, 0x9e, 0x53, 0x55, 0xaa,
                0x42, 0x70, 0x45, 0xbc, 0x15, 0xe7, 0xc6, 0xc7, 0x72, 0x88, 0xac,
            ],
        };
        assert_eq!(transaction_output, expected_output);
    }
}
