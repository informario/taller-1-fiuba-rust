use std::error::Error;

use super::{compact_size::CompactSize, DataTypes};

pub const COMMAND: [u8; 12] = *b"filterload\x00\x00";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterLoad {
    filter: Vec<u8>,
    n_hash_funcs: u32,
    n_tweak: u32,
    n_flags: u8,
}

impl FilterLoad {
    pub fn new(filter: Vec<u8>, n_hash_funcs: u32, n_tweak: u32, n_flags: u8) -> FilterLoad {
        Self {
            filter,
            n_hash_funcs,
            n_tweak,
            n_flags,
        }
    }
    pub fn serialize(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::<u8>::new();
        //Serialize compactSize nfilterbytes
        let length: CompactSize = CompactSize::new_from_u128(self.filter.len() as u128)?;
        bytes.extend(length.serialize());
        bytes.extend(&self.filter);
        bytes.extend(self.n_hash_funcs.to_le_bytes());
        bytes.extend(self.n_tweak.to_le_bytes());
        bytes.extend(self.n_flags.to_le_bytes());
        Ok(bytes)
    }
    pub fn deserialize(bytes: &[u8]) -> Result<FilterLoad, Box<dyn Error>> {
        let mut i = 0;
        let n_filter_bytes: CompactSize = CompactSize::new_from_byte_slice(
            bytes[i..i + CompactSize::MAX_BYTES_CONSUMED].try_into()?,
        )?;
        i += n_filter_bytes.bytes_consumed();
        let mut filter: Vec<u8> = vec![];
        for _counter in 0..n_filter_bytes.to_u128() {
            let byte = bytes[i];
            i += 1;
            filter.push(byte);
        }
        let n_hash_funcs: u32 = u32::from_le_bytes(bytes[i..i + 4].try_into()?);
        i += 4;
        let n_tweak: u32 = u32::from_le_bytes(bytes[i..i + 4].try_into()?);
        i += 4;
        let n_flags: u8 = u8::from_le_bytes(bytes[i..i + 1].try_into()?);
        Ok(FilterLoad::new(filter, n_hash_funcs, n_tweak, n_flags))
    }
}
pub fn deserialize_payload(serialized_payload: &[u8]) -> Result<Vec<DataTypes>, Box<dyn Error>> {
    let filter_load = FilterLoad::deserialize(serialized_payload)?;
    let message_payload: Vec<DataTypes> = vec![
        DataTypes::BloomFilter(filter_load.filter),
        DataTypes::UnsignedInt32(filter_load.n_hash_funcs),
        DataTypes::UnsignedInt32(filter_load.n_tweak),
        DataTypes::UnsignedInt8(filter_load.n_flags),
    ];
    Ok(message_payload)
}
pub fn create_payload(
    n_filter_bytes: CompactSize,
    filter: Vec<u8>,
    n_hash_funcs: u32,
    n_tweak: u32,
    n_flags: u8,
) -> Result<Vec<DataTypes>, Box<dyn Error>> {
    let payload = vec![
        DataTypes::CompactSize(n_filter_bytes),
        DataTypes::BloomFilter(filter),
        DataTypes::UnsignedInt32(n_hash_funcs),
        DataTypes::UnsignedInt32(n_tweak),
        DataTypes::UnsignedInt8(n_flags),
    ];
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use crate::node::message::filter_load::FilterLoad;

    #[test]
    fn test_filterload_deserialize() {
        let serialized = vec![
            0x02, //filter bytes
            0xb5, 0x0f, //filter
            0x05, 0x00, 0x00, 0x00, //nHashFuncs
            0x03, 0x00, 0x00, 0x00, //nTweak
            0x00, //nFlags
        ];
        let deserialized = FilterLoad::deserialize(&serialized).unwrap();
        let reserialized = FilterLoad::serialize(&deserialized).unwrap();
        assert_eq!(serialized, reserialized);
    }
}
