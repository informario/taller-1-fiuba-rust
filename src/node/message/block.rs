pub mod block_header;
pub mod transaction;
use crate::node::message::block::block_header::BlockHeader;
use crate::node::message::transaction::Transaction;
use crate::node::message::*;

/// Command for block message.
pub const COMMAND: [u8; 12] = *b"block\x00\x00\x00\x00\x00\x00\x00";

/// Struct containing parameters for block message.
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
struct MessageParams {
    block: Block,
}

/// Block struct
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    block_header: BlockHeader,
    transaction_count: CompactSize,
    transactions: Vec<Transaction>,
}

impl Block {
    /// Creates a new block message.
    /// If the parameters are valid, a `Block` struct is returned. If the parameters are invalid,
    /// an error is returned.
    ///
    /// # Arguments
    ///
    /// * `params` - A vector of parameters to be used in the message.
    ///
    /// ```
    pub fn new(
        block_header: BlockHeader,
        transaction_count: CompactSize,
        transactions: Vec<Transaction>,
    ) -> Block {
        Self {
            block_header,
            transaction_count,
            transactions,
        }
    }

    /// Returns the block header.
    /// ```
    pub fn get_block_header(&self) -> &BlockHeader {
        &self.block_header
    }

    /// Returns the transaction count.
    /// ```
    pub fn get_transaction_count(&self) -> &CompactSize {
        &self.transaction_count
    }

    /// Returns the transactions.
    /// ```
    pub fn get_transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }

    /// Deserializes a block from a byte slice.
    /// If the bytes are valid, a `Block` struct is returned. If the bytes are invalid,
    /// an error is returned.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing the bytes to be deserialized.
    ///
    /// ```
    pub fn deserialize(bytes: &[u8]) -> Result<Block, Box<dyn std::error::Error>> {
        // Deserialize block header
        let block_header = BlockHeader::deserialize(&bytes[0..80]);

        // Deserialize tx count
        let tx_count = CompactSize::new_from_byte_slice(bytes[80..89].try_into()?)?;

        let mut transactions = Vec::<Transaction>::new();
        // Deserialize transactions
        let mut i = 80 + tx_count.bytes_consumed();
        while i < bytes.len() {
            let (tx, bytes_consumed) = Transaction::deserialize(&bytes[i..])?;
            transactions.push(tx);
            i += bytes_consumed;
        }

        Ok(Block::new(block_header, tx_count, transactions))
    }

    /// Serializes a block into a byte vector.
    /// If the block is valid, a byte vector is returned. If the block is invalid,
    /// an error is returned.
    ///
    /// ```
    pub fn serialize(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::<u8>::new();

        // Serialize block header
        bytes.extend(self.block_header.serialize());

        // Serialize tx count
        bytes.extend(self.transaction_count.serialize());

        // Serialize transactions
        for tx in &self.transactions {
            bytes.extend(tx.serialize()?);
        }

        Ok(bytes)
    }
    pub fn validate_poi(serialized_block: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let block = Self::deserialize(serialized_block)?;
        let block_header = block.block_header;
        let mut txids = Vec::new();
        for tx in block.transactions {
            let first_hash = sha256::Hash::hash(tx.serialize()?.as_slice());
            let second_hash = sha256::Hash::hash(&first_hash[..]);
            txids.push(second_hash);
        }

        while txids.len() > 1 {
            if txids.len() % 2 == 1 {
                txids.push(txids[txids.len() - 1]);
            }
            let iteraciones = txids.len() / 2;
            for i in 0..iteraciones {
                let first_txid: [u8; 32] = txids.remove(i).to_byte_array();
                let second_txid: [u8; 32] = txids.remove(i).to_byte_array();
                let mut paired_txids = Vec::new();
                for byte in first_txid {
                    paired_txids.push(byte);
                }
                for byte in second_txid {
                    paired_txids.push(byte);
                }
                let paired_txids = sha256::Hash::hash(paired_txids.as_slice());
                let paired_txids = sha256::Hash::hash(&paired_txids[..]);
                txids.insert(i, paired_txids);
            }
        }
        let merkle_root_hash: [u8; 32] = txids[0].to_byte_array();
        let expected_merkle_root_hash: [u8; 32] = block_header.get_merkle_root_hash();

        Ok(merkle_root_hash == expected_merkle_root_hash)
    }
}

/// https://developer.bitcoin.org/reference/p2p_networking.html#block
/// The “block” message transmits a single serialized block
/// The payload function receives a vector of parameters and returns a new payload containing a vector of `DataTypes`.
/// If the parameters are valid, a vector of `DataTypes` is returned. If the parameters are invalid,
/// an error is returned.
///
/// # Arguments
///
/// * `block` - A block to be used in the message.
///
/// ```
pub fn create_payload(block: Block) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    // Add block to payload
    let payload = vec![DataTypes::Block(block)];

    Ok(payload)
}

/// Deserializes a block message payload.
/// If the payload is valid, a vector of `DataTypes` is returned. If the payload is invalid,
/// an error is returned.
/// https://daniel.perez.sh/blog/2020/bitcoin-format/
///
/// # Arguments
///
/// * `serialized_payload` - A vector of bytes to be deserialized.
///
/// ```
pub fn deserialize_payload(
    serialized_payload: &[u8],
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    let payload = vec![DataTypes::Block(Block::deserialize(serialized_payload)?)];
    Ok(payload)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_block_deserialize() {
        use super::*;
        use crate::node::message::block_header::BlockHeader;
        use crate::node::message::transaction::transaction_input::TransactionInput;
        use crate::node::message::transaction::transaction_output::TransactionOutput;
        use crate::node::message::transaction::{Transaction, Witness};
        let bytes = vec![
            // Header
            0x02, 0x00, 0x00, 0x00, // Block version: 2
            0xb6, 0xff, 0x0b, 0x1b, 0x16, 0x80, 0xa2, 0x86, 0x2a, 0x30, 0xca, 0x44, 0xd3, 0x46,
            0xd9, 0xe8, 0x91, 0x0d, 0x33, 0x4b, 0xeb, 0x48, 0xca, 0x0c, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // Hash of previous header's header
            0x9d, 0x10, 0xaa, 0x52, 0xee, 0x94, 0x93, 0x86, 0xca, 0x93, 0x85, 0x69, 0x5f, 0x04,
            0xed, 0xe2, 0x70, 0xdd, 0xa2, 0x08, 0x10, 0xde, 0xcd, 0x12, 0xbc, 0x9b, 0x04, 0x8a,
            0xaa, 0xb3, 0x14, 0x71, // Merkle root
            0x24, 0xd9, 0x5a, 0x54, // Unix time: 1415239972
            0x30, 0xc3, 0x1b, 0x18, // Target: 0x1bc330 * 256**(0x18-3)
            0xfe, 0x9f, 0x08, 0x64, // Nonce
            // Txn count
            0x01, // Txn
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

        let deserialized = deserialize_payload(&bytes).unwrap();

        let expected_output = vec![DataTypes::Block(Block::new(
            BlockHeader::new(
                2,
                [
                    0xb6, 0xff, 0x0b, 0x1b, 0x16, 0x80, 0xa2, 0x86, 0x2a, 0x30, 0xca, 0x44, 0xd3,
                    0x46, 0xd9, 0xe8, 0x91, 0x0d, 0x33, 0x4b, 0xeb, 0x48, 0xca, 0x0c, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                [
                    0x9d, 0x10, 0xaa, 0x52, 0xee, 0x94, 0x93, 0x86, 0xca, 0x93, 0x85, 0x69, 0x5f,
                    0x04, 0xed, 0xe2, 0x70, 0xdd, 0xa2, 0x08, 0x10, 0xde, 0xcd, 0x12, 0xbc, 0x9b,
                    0x04, 0x8a, 0xaa, 0xb3, 0x14, 0x71,
                ],
                1_415_239_972,
                0x181bc330,
                0x64089ffe,
            ),
            CompactSize::OneByte(1),
            vec![Transaction::new(
                2,
                CompactSize::OneByte(1),
                vec![TransactionInput::new(
                    [
                        0x40, 0xd4, 0x3a, 0x99, 0x92, 0x6d, 0x43, 0xeb, 0x0e, 0x61, 0x9b, 0xf0,
                        0xb3, 0xd8, 0x3b, 0x4a, 0x31, 0xf6, 0x0c, 0x17, 0x6b, 0xee, 0xcf, 0xb9,
                        0xd3, 0x5b, 0xf4, 0x5e, 0x54, 0xd0, 0xf7, 0x42,
                    ],
                    1,
                    CompactSize::OneByte(23),
                    vec![
                        0x16, 0x00, 0x14, 0xa4, 0xb4, 0xca, 0x48, 0xde, 0x0b, 0x3f, 0xff, 0xc1,
                        0x54, 0x04, 0xa1, 0xac, 0xdc, 0x8d, 0xba, 0xae, 0x22, 0x69, 0x55,
                    ],
                    u32::from_le_bytes([0xff, 0xff, 0xff, 0xff]),
                )],
                CompactSize::OneByte(1),
                vec![TransactionOutput::new(
                    u64::from_le_bytes([0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00]),
                    CompactSize::OneByte(23),
                    vec![
                        0xa9, 0x14, 0x4a, 0x11, 0x54, 0xd5, 0x0b, 0x03, 0x29, 0x2b, 0x30, 0x24,
                        0x37, 0x09, 0x01, 0x71, 0x94, 0x6c, 0xb7, 0xcc, 0xcc, 0x38, 0x70,
                    ],
                )],
                0,
                Some(Witness::new(
                    vec![vec![
                        vec![
                            0x04, 0x50, 0x22, 0x10, 0x08, 0x60, 0x4e, 0xf8, 0xf6, 0xd8, 0xaf, 0xa8,
                            0x92, 0xde, 0xe0, 0xf3, 0x12, 0x59, 0xb6, 0xce, 0x02, 0xdd, 0x70, 0xc5,
                            0x45, 0xcf, 0xcf, 0xed, 0x81, 0x48, 0x17, 0x99, 0x71, 0x87, 0x6c, 0x54,
                            0xa0, 0x22, 0x07, 0x6d, 0x77, 0x1d, 0x6e, 0x91, 0xbe, 0xd2, 0x12, 0x78,
                            0x3c, 0x9b, 0x06, 0xe0, 0xde, 0x60, 0x0f, 0xab, 0x2d, 0x51, 0x8f, 0xad,
                            0x6f, 0x15, 0xa2, 0xb1, 0x91, 0xd7, 0xfb, 0xd2, 0x62, 0xa3, 0xe0, 0x12,
                        ],
                        vec![
                            0x39, 0xd2, 0x5a, 0xb7, 0x9f, 0x41, 0xf7, 0x5c, 0xea, 0xf8, 0x82, 0x41,
                            0x1f, 0xd4, 0x1f, 0xa6, 0x70, 0xa4, 0xc6, 0x72, 0xc2, 0x3f, 0xfa, 0xf0,
                            0xe3, 0x61, 0xa9, 0x69, 0xcd, 0xe0, 0x69, 0x2e, 0x80,
                        ],
                    ]],
                    0,
                    1,
                )),
            )],
        ))];
        assert_eq!(deserialized, expected_output);

        let serialized = [
            0, 0, 0, 32, // version
            160, 78, 177, 251, 158, 174, 49, 47, 218, 50, 143, 209, 139, 184, 102, 207, 43, 117,
            90, 124, 141, 207, 198, 178, 108, 35, 233, 0, 0, 0, 0, 0, // prev_blockhash
            120, 144, 235, 37, 175, 117, 253, 10, 19, 199, 184, 178, 83, 1, 8, 74, 206, 77, 50, 43,
            2, 93, 33, 232, 58, 151, 112, 109, 140, 136, 110, 223, // merkle_root
            178, 68, 7, 88, // timestamp
            51, 75, 1, 28, // bits
            224, 103, 152, 96, // nonce
            2,  // tx_count
            // tx 1
            1, 0, 0, 0, // version
            1, // input count
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, // prev_txid
            255, 255, 255, 255, // prev_index
            44,  // script length
            3, 129, 64, 15, 0, 4, 233, 61, 7, 88, 4, 80, 27, 137, 48, 12, 240, 56, 7, 88, 11, 0, 0,
            0, 0, 0, 0, 0, 10, 99, 107, 112, 111, 111, 108, 8, 47, 115, 101, 103, 119, 105, 116,
            47, // script
            255, 255, 255, 255, // sequence
            2,   // output count
            // output 1
            48, 134, 160, 18, 0, 0, 0, 0,  // value
            25, // script length
            118, 169, 20, 212, 39, 169, 49, 139, 198, 13, 178, 118, 111, 155, 2, 183, 187, 212,
            112, 183, 143, 167, 164, 136, 172, // script
            // output 2
            0, 0, 0, 0, 0, 0, 0, 0,  // value
            38, // script length
            106, 36, 170, 33, 169, 237, 58, 118, 111, 246, 252, 162, 171, 201, 3, 71, 58, 9, 197,
            223, 171, 12, 242, 91, 223, 168, 77, 246, 70, 94, 250, 192, 228, 209, 161, 210, 73,
            139, // script
            0, 0, 0, 0, // locktime
            // tx 2
            1, 0, 0, 0, // version
            2, // input count
            // input 1
            129, 103, 123, 80, 144, 124, 52, 98, 244, 16, 57, 160, 193, 13, 22, 171, 140, 153, 199,
            242, 124, 49, 77, 199, 169, 207, 244, 129, 210, 138, 157, 183, // prev_txid
            3, 0, 0, 0,   // prev_index
            107, // script length
            72, 48, 69, 2, 33, 0, 225, 94, 94, 89, 90, 66, 32, 70, 255, 83, 14, 244, 130, 252, 36,
            140, 171, 150, 225, 114, 123, 158, 60, 189, 232, 58, 57, 71, 43, 22, 182, 109, 2, 32,
            84, 10, 57, 204, 133, 185, 27, 238, 27, 157, 237, 152, 188, 76, 0, 233, 4, 72, 51, 9,
            191, 159, 158, 7, 221, 186, 200, 218, 157, 5, 72, 51, 1, 33, 3, 182, 78, 50, 229, 246,
            46, 3, 112, 20, 40, 251, 30, 49, 81, 233, 165, 127, 20, 156, 103, 112, 143, 97, 100,
            162, 53, 200, 25, 159, 225, 124, 194, // script
            255, 255, 255, 255, // sequence
            // input 2
            159, 177, 176, 99, 38, 73, 26, 230, 211, 251, 93, 214, 187, 242, 72, 195, 179, 233, 21,
            75, 129, 24, 248, 149, 117, 73, 255, 186, 9, 142, 126, 195, // prev_txid
            2, 0, 0, 0,   // prev_index
            106, // script length
            71, 48, 68, 2, 32, 12, 14, 56, 169, 150, 207, 112, 150, 91, 191, 251, 207, 116, 116,
            49, 240, 169, 114, 176, 245, 245, 248, 13, 78, 164, 62, 58, 60, 54, 218, 63, 110, 2,
            32, 28, 236, 11, 143, 45, 53, 46, 73, 39, 75, 97, 94, 26, 46, 136, 212, 202, 98, 74, 3,
            179, 183, 232, 167, 12, 122, 12, 61, 57, 189, 175, 171, 1, 33, 3, 182, 78, 50, 229,
            246, 46, 3, 112, 20, 40, 251, 30, 49, 81, 233, 165, 127, 20, 156, 103, 112, 143, 97,
            100, 162, 53, 200, 25, 159, 225, 124, 194, // script
            255, 255, 255, 255, // sequence
            5,   // output count
            // output 1
            16, 39, 0, 0, 0, 0, 0, 0,  // value
            25, // script length
            118, 169, 20, 61, 218, 44, 180, 130, 29, 75, 78, 117, 215, 235, 212, 33, 253, 150, 7,
            181, 251, 202, 204, 136, 172, // script
            // output 2
            16, 39, 0, 0, 0, 0, 0, 0,  // value
            25, // script length
            118, 169, 20, 61, 218, 44, 180, 130, 29, 75, 78, 117, 215, 235, 212, 33, 253, 150, 7,
            181, 251, 202, 204, 136, 172, // script
            // output 3
            160, 134, 1, 0, 0, 0, 0, 0,  // value
            25, // script length
            118, 169, 20, 19, 211, 90, 211, 55, 221, 128, 160, 85, 117, 126, 94, 160, 164, 91, 89,
            254, 227, 6, 12, 136, 172, // script
            // output 4
            64, 156, 0, 0, 0, 0, 0, 0,  // value
            25, // script length
            118, 169, 20, 19, 211, 90, 211, 55, 221, 128, 160, 85, 117, 126, 94, 160, 164, 91, 89,
            254, 227, 6, 12, 136, 172, // script
            // output 5
            0, 0, 0, 0, 0, 0, 0, 0, // value
            2, // script length
            106, 0, // script
            0, 0, 0, 0, // locktime
        ];

        let block = Block::deserialize(&serialized).unwrap();
        assert_eq!(
            block.block_header,
            BlockHeader::new(
                536870912,
                [
                    160, 78, 177, 251, 158, 174, 49, 47, 218, 50, 143, 209, 139, 184, 102, 207, 43,
                    117, 90, 124, 141, 207, 198, 178, 108, 35, 233, 0, 0, 0, 0, 0,
                ],
                [
                    120, 144, 235, 37, 175, 117, 253, 10, 19, 199, 184, 178, 83, 1, 8, 74, 206, 77,
                    50, 43, 2, 93, 33, 232, 58, 151, 112, 109, 140, 136, 110, 223,
                ],
                1476871346,
                469846835,
                1620600800,
            ),
        );
        assert_eq!(block.transaction_count, CompactSize::OneByte(2));

        assert_eq!(
            block.transactions[0],
            Transaction::new(
                1,
                CompactSize::OneByte(1),
                vec![TransactionInput {
                    previous_output_tx_hash: [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    previous_output_index: 4294967295,
                    script_length: CompactSize::OneByte(44),
                    script_sig: vec![
                        3, 129, 64, 15, 0, 4, 233, 61, 7, 88, 4, 80, 27, 137, 48, 12, 240, 56, 7,
                        88, 11, 0, 0, 0, 0, 0, 0, 0, 10, 99, 107, 112, 111, 111, 108, 8, 47, 115,
                        101, 103, 119, 105, 116, 47,
                    ],
                    sequence: 4294967295,
                }],
                CompactSize::OneByte(2),
                vec![
                    TransactionOutput {
                        value: 312510000,
                        script_length: CompactSize::OneByte(25),
                        script: vec![
                            118, 169, 20, 212, 39, 169, 49, 139, 198, 13, 178, 118, 111, 155, 2,
                            183, 187, 212, 112, 183, 143, 167, 164, 136, 172,
                        ],
                    },
                    TransactionOutput {
                        value: 0,
                        script_length: CompactSize::OneByte(38),
                        script: vec![
                            106, 36, 170, 33, 169, 237, 58, 118, 111, 246, 252, 162, 171, 201, 3,
                            71, 58, 9, 197, 223, 171, 12, 242, 91, 223, 168, 77, 246, 70, 94, 250,
                            192, 228, 209, 161, 210, 73, 139,
                        ],
                    },
                ],
                0,
                None,
            )
        );
    }
}
