use super::{block::block_header::BlockHeader, compact_size::CompactSize};

/// Command for block message.
pub const COMMAND: [u8; 12] = *b"merkleblock\x00";

/// Min params
//const MIN_PARAMS: usize = 1;

/// Struct containing parameters for block message.
/// ```
/*#[derive(Debug, Clone, PartialEq, Eq)]
struct MessageParams {
    block_header: BlockHeader,
    transaction_count: u32,
    hash_count: CompactSize,
    hashes: Vec<[u8;32]>,
    flag_byte_count: CompactSize,
    flags: Vec<u8>,
}*/

/// Block struct
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleBlock {
    pub block_header: BlockHeader,
    pub transaction_count: u32,
    pub hash_count: CompactSize,
    pub hashes: Vec<[u8; 32]>,
    pub flag_byte_count: CompactSize,
    pub flags: Vec<u8>,
}

impl MerkleBlock {
    /// Creates a new merkleblock message.
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
        transaction_count: u32,
        hash_count: CompactSize,
        hashes: Vec<[u8; 32]>,
        flag_byte_count: CompactSize,
        flags: Vec<u8>,
    ) -> MerkleBlock {
        Self {
            block_header,
            transaction_count,
            hash_count,
            hashes,
            flag_byte_count,
            flags,
        }
    }

    /// Deserializes a merkleblock message .
    /// If the message is valid, a merkleblock is returned. If the payload is invalid,
    /// an error is returned.
    /// https://daniel.perez.sh/blog/2020/bitcoin-format/
    ///
    /// # Arguments
    ///
    /// * `bytes` - A slice of bytes to be deserialized.
    ///
    /// ```
    pub fn deserialize(bytes: &[u8]) -> Result<MerkleBlock, Box<dyn std::error::Error>> {
        // Deserialize merkleblock header
        let mut i = 0;
        let block_header = BlockHeader::deserialize(&bytes[i..i + 80]);
        i += 80;
        let transaction_count: u32 = u32::from_le_bytes(bytes[i..i + 4].try_into()?);
        i += 4;
        let hash_count = CompactSize::new_from_byte_slice(
            bytes[i..i + CompactSize::MAX_BYTES_CONSUMED].try_into()?,
        )?;
        i += hash_count.bytes_consumed();
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        for _counter in 0..hash_count.to_u128() {
            let hash: [u8; 32] = bytes[i..i + 32].try_into()?;
            i += 32;
            hashes.push(hash);
        }
        let b0 = bytes[i];
        let flag_byte_count: CompactSize;
        if b0 < 0xfd {
            flag_byte_count = CompactSize::new_from_byte_slice(bytes[i..i + 1].try_into()?)?;
        } else if b0 == 0xfd {
            flag_byte_count = CompactSize::new_from_byte_slice(bytes[i..i + 3].try_into()?)?;
        } else if b0 == 0xfe {
            flag_byte_count = CompactSize::new_from_byte_slice(bytes[i..i + 5].try_into()?)?;
        } else {
            flag_byte_count = CompactSize::new_from_byte_slice(bytes[i..i + 9].try_into()?)?;
        }

        i += flag_byte_count.bytes_consumed();
        let mut flags: Vec<u8> = Vec::new();
        for _counter in 0..flag_byte_count.to_u128() {
            let flag = bytes[i];
            i += 1;
            flags.push(flag);
        }
        Ok(MerkleBlock::new(
            block_header,
            transaction_count,
            hash_count,
            hashes,
            flag_byte_count,
            flags,
        ))
    }

    /// Serializes a block into a byte vector.
    /// If the block is valid, a byte vector is returned. If the block is invalid,
    /// an error is returned.
    ///
    /// ```
    pub fn serialize(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::<u8>::new();
        bytes.extend(self.block_header.serialize());
        bytes.extend(self.transaction_count.to_le_bytes());
        bytes.extend(self.hash_count.serialize());
        for hash in &self.hashes {
            bytes.extend(hash);
        }
        bytes.extend(self.flag_byte_count.serialize());
        bytes.extend(&self.flags);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkleblock_deserialize() {
        let serialized = vec![
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
            0x23, 0x00, 0x00, 0x00, // Txn count
            0x04, // Hash count
            //Hashes
            0xb6, 0xff, 0x0b, 0x1b, 0x16, 0x80, 0xa2, 0x86, 0x2a, 0x30, 0xca, 0x44, 0xd3, 0x46,
            0xd9, 0xe8, 0x91, 0x0d, 0x33, 0x4b, 0xeb, 0x48, 0xca, 0x0c, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xb6, 0xff, 0x0b, 0x1b, 0x16, 0x80, 0xa2, 0x86, 0x2a, 0x30,
            0xca, 0x44, 0xd3, 0x46, 0xd9, 0xe8, 0x91, 0x0d, 0x33, 0x4b, 0xeb, 0x48, 0xca, 0x0c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0xff, 0x0b, 0x1b, 0x16, 0x80,
            0xa2, 0x86, 0x2a, 0x30, 0xca, 0x44, 0xd3, 0x46, 0xd9, 0xe8, 0x91, 0x0d, 0x33, 0x4b,
            0xeb, 0x48, 0xca, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0xff,
            0x0b, 0x1b, 0x16, 0x80, 0xa2, 0x86, 0x2a, 0x30, 0xca, 0x44, 0xd3, 0x46, 0xd9, 0xe8,
            0x91, 0x0d, 0x33, 0x4b, 0xeb, 0x48, 0xca, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, //Flag byte count
            0x01, //Flags
            0x1d,
        ];

        let deserialized = MerkleBlock::deserialize(&serialized).unwrap();
        let reserialized = MerkleBlock::serialize(&deserialized).unwrap();

        assert_eq!(serialized, reserialized);
    }
}
