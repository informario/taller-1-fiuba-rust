pub mod transaction_input;
pub mod transaction_output;
use crate::node::message::block::transaction::transaction_input::TransactionInput;
use crate::node::message::block::transaction::transaction_output::TransactionOutput;
use crate::node::message::block_header::hash_from_serialized;
use crate::node::message::CompactSize;
use crate::node::p2pkh::create_p2pkh_script;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub witnesses: Vec<Vec<Vec<u8>>>,
    pub witness_marker: u8,
    pub witness_flag: u8,
}
impl Witness {
    pub fn new(witnesses: Vec<Vec<Vec<u8>>>, witness_marker: u8, witness_flag: u8) -> Self {
        Self {
            witnesses,
            witness_marker,
            witness_flag,
        }
    }
}

const SIGHASH_ALL: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Struct for transaction.
/// https://reference.cash/protocol/blockchain/transaction
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub input_count: CompactSize,
    pub inputs: Vec<TransactionInput>,
    pub output_count: CompactSize,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u32,
    pub witness: Option<Witness>,
}

impl Transaction {
    pub fn new(
        version: u32,
        input_count: CompactSize,
        inputs: Vec<TransactionInput>,
        output_count: CompactSize,
        outputs: Vec<TransactionOutput>,
        lock_time: u32,
        witness: Option<Witness>,
    ) -> Self {
        Self {
            version,
            input_count,
            inputs,
            output_count,
            outputs,
            lock_time,
            witness,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut serialized = Vec::<u8>::new();
        serialized.extend(self.version.to_le_bytes());
        if Option::is_some(&self.witness) {
            serialized.extend(self.witness.as_ref().unwrap().witness_marker.to_le_bytes());
            serialized.extend(self.witness.as_ref().unwrap().witness_flag.to_le_bytes());
        }
        serialized.extend(self.input_count.serialize());
        for input in &self.inputs {
            serialized.extend(input.serialize());
        }
        serialized.extend(self.output_count.serialize());
        for output in &self.outputs {
            serialized.extend(output.serialize());
        }
        serialized.extend(self.lock_time.to_le_bytes());
        if Option::is_some(&self.witness) {
            for witness in &self.witness.as_ref().unwrap().witnesses {
                for witness_item in witness {
                    serialized.extend(
                        CompactSize::new_from_u128(witness_item.len() as u128)?.serialize(),
                    );
                    serialized.extend(witness_item);
                }
            }
        }
        Ok(serialized)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        let mut i = 0;
        let version = u32::from_le_bytes(bytes[0..4].try_into()?);
        i += 4;
        let mut witness_marker = None;
        let mut witness_flag = 0x00;
        // Check if witness flag is present
        if bytes[4] == 0x00 && bytes[5] == 0x01 {
            witness_marker = Some(bytes[4]);
            witness_flag = bytes[5];
            i += 2;
        }
        let input_count = CompactSize::new_from_byte_slice(
            bytes[i..i + CompactSize::MAX_BYTES_CONSUMED].try_into()?,
        )?;
        i += input_count.bytes_consumed();
        let mut inputs = Vec::<TransactionInput>::new();
        for _ in 0..input_count.to_u128() {
            let (input, bytes_consumed) = TransactionInput::deserialize(&bytes[i..])?;
            inputs.push(input);
            i += bytes_consumed;
        }

        let output_count = CompactSize::new_from_byte_slice(
            bytes[i..i + CompactSize::MAX_BYTES_CONSUMED].try_into()?,
        )?;
        i += output_count.bytes_consumed();
        let mut outputs = Vec::<TransactionOutput>::new();
        for _ in 0..output_count.to_u128() {
            let (output, bytes_consumed) = TransactionOutput::deserialize(&bytes[i..])?;
            outputs.push(output);
            i += bytes_consumed;
        }
        let mut witness = None;
        // Check if witness data is present
        if let Some(..) = witness_marker {
            let mut witnesses = Vec::<Vec<Vec<u8>>>::new();
            for _ in 0..input_count.to_u128() {
                let witness_count = CompactSize::new_from_byte_slice(
                    bytes[i..i + CompactSize::MAX_BYTES_CONSUMED].try_into()?,
                )?;
                i += witness_count.bytes_consumed();
                let mut witness_stack = Vec::<Vec<u8>>::new();
                for _ in 0..witness_count.to_u128() {
                    let witness_length = CompactSize::new_from_byte_slice(
                        bytes[i..i + CompactSize::MAX_BYTES_CONSUMED].try_into()?,
                    )?;
                    i += witness_length.bytes_consumed();
                    witness_stack.push(bytes[i..i + witness_length.to_u128() as usize].to_vec());
                    i += witness_length.to_u128() as usize;
                }
                witnesses.push(witness_stack);
            }
            witness = Some(Witness::new(
                witnesses,
                witness_marker.unwrap(),
                witness_flag,
            ));
        }
        let lock_time = u32::from_le_bytes(bytes[i..i + 4].try_into()?);
        i += 4;
        Ok((
            Self {
                version,
                input_count,
                inputs,
                output_count,
                outputs,
                lock_time,
                witness,
            },
            i,
        ))
    }

    pub fn get_transaction_id(&self) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let serialized = self.serialize()?;
        Ok(hash_from_serialized(&serialized)[..32].try_into()?)
    }

    pub fn sig_hash(
        &self,
        input_index: usize,
        input_address: &str,
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let mut temp_tx = self.clone();
        for i in 0..temp_tx.inputs.len() {
            if i != input_index {
                temp_tx.inputs[i].script_length = CompactSize::new_from_u128(0)?;
                temp_tx.inputs[i].script_sig = vec![];
            } else {
                temp_tx.inputs[i].script_sig = create_p2pkh_script(input_address)?;
                temp_tx.inputs[i].script_length =
                    CompactSize::new_from_u128(temp_tx.inputs[i].script_sig.len() as u128)?;
            }
        }
        let mut serialized = temp_tx.serialize()?;
        serialized.extend(SIGHASH_ALL);
        let hash = hash_from_serialized(&serialized);
        Ok(hash[..32].try_into()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::message::block::transaction::transaction_input::TransactionInput;
    use crate::node::message::block::transaction::transaction_output::TransactionOutput;
    use crate::node::message::CompactSize;

    #[test]
    fn test_deserialize() {
        let serialized = [
            0x02, 0x00, 0x00, 0x00, // Version
            0x00, // Witness marker
            0x01, // Witness flag
            0x01, // Input count
            0x40, 0xd4, 0x3a, 0x99, 0x92, 0x6d, 0x43, 0xeb, 0x0e, 0x61, 0x9b, 0xf0, 0xb3, 0xd8,
            0x3b, 0x4a, 0x31, 0xf6, 0x0c, 0x17, 0x6b, 0xee, 0xcf, 0xb9, 0xd3, 0x5b, 0xf4, 0x5e,
            0x54, 0xd0, 0xf7, 0x42, // Previous output hash
            0x01, 0x00, 0x00, 0x00, // Previous output index
            0x17, // Script length
            0x16, 0x00, 0x14, 0xa4, 0xb4, 0xca, 0x48, 0xde, 0x0b, 0x3f, 0xff, 0xc1, 0x54, 0x04,
            0xa1, 0xac, 0xdc, 0x8d, 0xba, 0xae, 0x22, 0x69, 0x55, // Script
            0xff, 0xff, 0xff, 0xff, // Sequence
            0x01, // Output count
            0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, // Value
            0x17, // Script length
            0xa9, 0x14, 0x4a, 0x11, 0x54, 0xd5, 0x0b, 0x03, 0x29, 0x2b, 0x30, 0x24, 0x37, 0x09,
            0x01, 0x71, 0x94, 0x6c, 0xb7, 0xcc, 0xcc, 0x38, 0x70, // Script
            0x02, // Witness count
            72,   // Witness 1 length
            0x04, 0x50, 0x22, 0x10, 0x08, 0x60, 0x4e, 0xf8, 0xf6, 0xd8, 0xaf, 0xa8, 0x92, 0xde,
            0xe0, 0xf3, 0x12, 0x59, 0xb6, 0xce, 0x02, 0xdd, 0x70, 0xc5, 0x45, 0xcf, 0xcf, 0xed,
            0x81, 0x48, 0x17, 0x99, 0x71, 0x87, 0x6c, 0x54, 0xa0, 0x22, 0x07, 0x6d, 0x77, 0x1d,
            0x6e, 0x91, 0xbe, 0xd2, 0x12, 0x78, 0x3c, 0x9b, 0x06, 0xe0, 0xde, 0x60, 0x0f, 0xab,
            0x2d, 0x51, 0x8f, 0xad, 0x6f, 0x15, 0xa2, 0xb1, 0x91, 0xd7, 0xfb, 0xd2, 0x62, 0xa3,
            0xe0, 0x12, // Witness 1
            33,   // Witness 2 length
            0x39, 0xd2, 0x5a, 0xb7, 0x9f, 0x41, 0xf7, 0x5c, 0xea, 0xf8, 0x82, 0x41, 0x1f, 0xd4,
            0x1f, 0xa6, 0x70, 0xa4, 0xc6, 0x72, 0xc2, 0x3f, 0xfa, 0xf0, 0xe3, 0x61, 0xa9, 0x69,
            0xcd, 0xe0, 0x69, 0x2e, 0x80, // Witness 2
            0x00, 0x00, 0x00, 0x00, // Lock time
        ];
        let (tx, _) = Transaction::deserialize(&serialized).unwrap();
        assert_eq!(tx.version, 2);
        assert_eq!(tx.witness.clone().unwrap().witness_marker, 0);
        assert_eq!(tx.witness.clone().unwrap().witness_flag, 1);
        assert_eq!(tx.input_count.to_u128(), 1);
        assert_eq!(tx.output_count.to_u128(), 1);
        assert_eq!(tx.lock_time, 0);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(
            tx.inputs[0],
            TransactionInput::new(
                [
                    0x40, 0xd4, 0x3a, 0x99, 0x92, 0x6d, 0x43, 0xeb, 0x0e, 0x61, 0x9b, 0xf0, 0xb3,
                    0xd8, 0x3b, 0x4a, 0x31, 0xf6, 0x0c, 0x17, 0x6b, 0xee, 0xcf, 0xb9, 0xd3, 0x5b,
                    0xf4, 0x5e, 0x54, 0xd0, 0xf7, 0x42,
                ],
                1,
                CompactSize::OneByte(23),
                vec![
                    0x16, 0x00, 0x14, 0xa4, 0xb4, 0xca, 0x48, 0xde, 0x0b, 0x3f, 0xff, 0xc1, 0x54,
                    0x04, 0xa1, 0xac, 0xdc, 0x8d, 0xba, 0xae, 0x22, 0x69, 0x55
                ],
                u32::from_le_bytes([0xff, 0xff, 0xff, 0xff]),
            )
        );
        assert_eq!(
            tx.outputs[0],
            TransactionOutput::new(
                u64::from_le_bytes([0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00]),
                CompactSize::OneByte(23),
                vec![
                    0xa9, 0x14, 0x4a, 0x11, 0x54, 0xd5, 0x0b, 0x03, 0x29, 0x2b, 0x30, 0x24, 0x37,
                    0x09, 0x01, 0x71, 0x94, 0x6c, 0xb7, 0xcc, 0xcc, 0x38, 0x70,
                ],
            )
        );
        assert_eq!(
            tx.witness.unwrap().witnesses,
            vec![vec![
                vec![
                    0x04, 0x50, 0x22, 0x10, 0x08, 0x60, 0x4e, 0xf8, 0xf6, 0xd8, 0xaf, 0xa8, 0x92,
                    0xde, 0xe0, 0xf3, 0x12, 0x59, 0xb6, 0xce, 0x02, 0xdd, 0x70, 0xc5, 0x45, 0xcf,
                    0xcf, 0xed, 0x81, 0x48, 0x17, 0x99, 0x71, 0x87, 0x6c, 0x54, 0xa0, 0x22, 0x07,
                    0x6d, 0x77, 0x1d, 0x6e, 0x91, 0xbe, 0xd2, 0x12, 0x78, 0x3c, 0x9b, 0x06, 0xe0,
                    0xde, 0x60, 0x0f, 0xab, 0x2d, 0x51, 0x8f, 0xad, 0x6f, 0x15, 0xa2, 0xb1, 0x91,
                    0xd7, 0xfb, 0xd2, 0x62, 0xa3, 0xe0, 0x12,
                ],
                vec![
                    0x39, 0xd2, 0x5a, 0xb7, 0x9f, 0x41, 0xf7, 0x5c, 0xea, 0xf8, 0x82, 0x41, 0x1f,
                    0xd4, 0x1f, 0xa6, 0x70, 0xa4, 0xc6, 0x72, 0xc2, 0x3f, 0xfa, 0xf0, 0xe3, 0x61,
                    0xa9, 0x69, 0xcd, 0xe0, 0x69, 0x2e, 0x80,
                ]
            ]]
        );
    }

    #[test]
    fn test_sig_hash() {
        let serialized = [
            1, 0, 0, 0, 1, 210, 49, 41, 44, 208, 3, 62, 230, 93, 164, 90, 85, 116, 246, 157, 201,
            55, 83, 100, 221, 41, 30, 180, 22, 87, 194, 100, 71, 103, 64, 51, 84, 1, 0, 0, 0, 0,
            255, 255, 255, 255, 1, 2, 48, 0, 0, 0, 0, 0, 0, 25, 118, 169, 20, 179, 7, 107, 77, 162,
            146, 141, 57, 58, 1, 215, 65, 228, 231, 161, 76, 117, 95, 60, 151, 136, 172, 0, 0, 0,
            0,
        ];

        let (tx, _) = Transaction::deserialize(&serialized).unwrap();
        //println!("tx: {:?}", tx);
        let input_address = "mwqa8tCH4fSy4hjuMe6bo46KHP5tfihVdN";
        let input_index = 0;
        let sighash = tx.sig_hash(input_index, input_address).unwrap();
        //println!("sighash: {:?}", sighash);
        let expected_sighash = [
            186, 234, 116, 65, 203, 212, 131, 174, 149, 112, 52, 43, 244, 214, 191, 82, 233, 208,
            84, 41, 163, 178, 39, 233, 109, 90, 31, 110, 221, 170, 191, 228,
        ];
        assert_eq!(sighash, expected_sighash);
    }
}
