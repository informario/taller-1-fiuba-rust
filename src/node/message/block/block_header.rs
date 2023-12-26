use bitcoin_hashes::*;

/// Struct for block header.
/// https://developer.bitcoin.org/reference/block_chain.html#block-headers
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    version: i32,
    previous_block_hash: [u8; 32],
    merkle_root_hash: [u8; 32],
    time: u32,
    bits: u32,
    nonce: u32,
}

impl BlockHeader {
    pub fn new(
        version: i32,
        previous_block_hash: [u8; 32],
        merkle_root_hash: [u8; 32],
        time: u32,
        bits: u32,
        nonce: u32,
    ) -> Self {
        Self {
            version,
            previous_block_hash,
            merkle_root_hash,
            time,
            bits,
            nonce,
        }
    }

    /// Serialize block header.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - serialized block header
    ///
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::<u8>::new();
        serialized.extend(self.version.to_le_bytes().iter().cloned());
        serialized.extend(self.previous_block_hash);
        serialized.extend(self.merkle_root_hash);
        serialized.extend(self.time.to_le_bytes().iter().cloned());
        serialized.extend(self.bits.to_le_bytes().iter().cloned());
        serialized.extend(self.nonce.to_le_bytes().iter().cloned());
        serialized
    }

    /// Deserialize block header.
    ///
    /// # Arguments
    ///
    /// * `serialized` - serialized block header
    ///
    /// # Returns
    ///
    /// * `BlockHeader` - deserialized block header
    ///
    /// ```
    pub fn deserialize(serialized: &[u8]) -> Self {
        let mut version = [0u8; 4];
        version.copy_from_slice(&serialized[0..4]);
        let mut previous_block_hash = [0u8; 32];
        previous_block_hash.copy_from_slice(&serialized[4..36]);
        let mut merkle_root_hash = [0u8; 32];
        merkle_root_hash.copy_from_slice(&serialized[36..68]);
        let mut time = [0u8; 4];
        time.copy_from_slice(&serialized[68..72]);
        let mut bits = [0u8; 4];
        bits.copy_from_slice(&serialized[72..76]);
        let mut nonce = [0u8; 4];
        nonce.copy_from_slice(&serialized[76..80]);
        Self {
            version: i32::from_le_bytes(version),
            previous_block_hash,
            merkle_root_hash,
            time: u32::from_le_bytes(time),
            bits: u32::from_le_bytes(bits),
            nonce: u32::from_le_bytes(nonce),
        }
    }

    /// Calculate hash of block header.
    ///
    /// # Returns
    ///
    /// * `sha256::Hash` - hash of block header
    ///
    /// ```
    pub fn hash(&self) -> sha256::Hash {
        let hash: sha256::Hash = sha256::Hash::hash(&self.serialize());
        let hash: sha256::Hash = sha256::Hash::hash(&hash[..]);
        hash
    }

    /// Validate proof of work.
    ///
    /// # Returns
    ///
    /// * `bool` - true if proof of work is valid, false otherwise
    ///
    /// ```
    pub fn validate_pow(&self) -> bool {
        let mut target = Self::target_from_nbits(self.bits);
        target.reverse();
        let hash = self.hash();
        let mut hash_byte_array = *hash.as_byte_array();
        hash_byte_array.reverse();
        hash_byte_array <= target
    }

    /// https://medium.com/@dongha.sohn/bitcoin-6-target-and-difficulty-ee3bc9cc5962
    /// Convert nbits to target.
    /// Target is returned as a 32 byte array in little endian format.
    ///
    /// # Arguments
    ///
    /// * `nbits` - nbits from block header
    ///
    /// # Returns
    ///
    /// * `target` - target from nbits
    ///
    /// ```
    pub fn target_from_nbits(nbits: u32) -> [u8; 32] {
        let exp = (nbits >> 24) as usize;
        let value = nbits & 0x007fffff;
        let value_bytes = value.to_le_bytes();
        let left_index: usize;
        let right_index: usize = exp + 1; // - 3 + 4
        let bytes_to_copy: usize;
        if exp >= 3 {
            left_index = right_index - 4; // -4
            bytes_to_copy = 4;
        } else {
            bytes_to_copy = exp + 1;
            left_index = 0;
        }
        let mut target = [0; 32];
        target[left_index..right_index].copy_from_slice(&value_bytes[4 - bytes_to_copy..4]);
        target
    }
    pub fn get_merkle_root_hash(&self) -> [u8; 32] {
        self.merkle_root_hash
    }
}

/// Calculate hash of serialized block header.
///
/// # Arguments
///
/// * `serialized` - serialized block header
///
/// # Returns
///
/// * `sha256::Hash` - hash of serialized block header
///
/// ```
pub fn hash_from_serialized(serialized: &[u8]) -> sha256::Hash {
    let hash: sha256::Hash = sha256::Hash::hash(serialized);
    let hash: sha256::Hash = sha256::Hash::hash(&hash[..]);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let bytes = [
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
        ];
        let block_header = BlockHeader::deserialize(&bytes);
        assert_eq!(block_header.version, 2);
        assert_eq!(
            block_header.previous_block_hash,
            [
                0xb6, 0xff, 0x0b, 0x1b, 0x16, 0x80, 0xa2, 0x86, 0x2a, 0x30, 0xca, 0x44, 0xd3, 0x46,
                0xd9, 0xe8, 0x91, 0x0d, 0x33, 0x4b, 0xeb, 0x48, 0xca, 0x0c, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            block_header.merkle_root_hash,
            [
                0x9d, 0x10, 0xaa, 0x52, 0xee, 0x94, 0x93, 0x86, 0xca, 0x93, 0x85, 0x69, 0x5f, 0x04,
                0xed, 0xe2, 0x70, 0xdd, 0xa2, 0x08, 0x10, 0xde, 0xcd, 0x12, 0xbc, 0x9b, 0x04, 0x8a,
                0xaa, 0xb3, 0x14, 0x71
            ]
        );
        assert_eq!(block_header.time, 1_415_239_972);
        assert_eq!(block_header.bits, 0x181bc330);
        assert_eq!(block_header.nonce, 0x64089ffe);
    }

    #[test]
    fn test_hash_from_serialized() {
        let serialized = vec![
            1, 0, 0, 0, 67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174,
            186, 121, 151, 32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0, 186, 200, 176, 250,
            146, 124, 10, 200, 35, 66, 135, 227, 60, 95, 116, 211, 141, 53, 72, 32, 226, 71, 86,
            173, 112, 157, 112, 56, 252, 95, 49, 240, 32, 231, 73, 77, 255, 255, 0, 29, 3, 228,
            182, 114,
        ];

        let hash: [u8; 32] = hash_from_serialized(&serialized)[..].try_into().unwrap();

        assert_eq!(
            hash,
            [
                6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85, 40, 210, 112, 44,
                150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_validate_pow() {
        let serialized = vec![
            1, 0, 0, 0, 67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174,
            186, 121, 151, 32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0, 186, 200, 176, 250,
            146, 124, 10, 200, 35, 66, 135, 227, 60, 95, 116, 211, 141, 53, 72, 32, 226, 71, 86,
            173, 112, 157, 112, 56, 252, 95, 49, 240, 32, 231, 73, 77, 255, 255, 0, 29, 3, 228,
            182, 114,
        ];

        let block_header = BlockHeader::deserialize(&serialized);
        assert!(block_header.validate_pow());
    }

    #[test]
    fn test_target_from_nbits() {
        use super::*;

        let nbits = 0x1729d72d;

        let target = BlockHeader::target_from_nbits(nbits);
        assert_eq!(
            target,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2D, 0xD7, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        let nbits = 0x1705dd01;
        let target = BlockHeader::target_from_nbits(nbits);
        assert_eq!(
            target,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xdd, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        let nbits = 0x01003456;
        let target = BlockHeader::target_from_nbits(nbits);
        assert_eq!(target, [0; 32]);

        let nbits = 0x01123456;
        let target = BlockHeader::target_from_nbits(nbits);
        assert_eq!(
            target,
            [
                0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        let nbits = 0x02008000;
        let target = BlockHeader::target_from_nbits(nbits);
        assert_eq!(
            target,
            [
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        let nbits = 0x05009234;
        let target = BlockHeader::target_from_nbits(nbits);
        assert_eq!(
            target,
            [
                0x00, 0x00, 0x34, 0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        let nbits = 0x04923456;
        let target = BlockHeader::target_from_nbits(nbits);
        assert_eq!(
            target,
            [
                0x00, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );
        let nbits = 0x04123456;
        let target = BlockHeader::target_from_nbits(nbits);
        assert_eq!(
            target,
            [
                0x00, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        let nbits = 0x1d00ffff;
        let target = BlockHeader::target_from_nbits(nbits);
        assert_eq!(
            target,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                0x00, 0x00, 0x00, 0x00
            ]
        );
    }
}
