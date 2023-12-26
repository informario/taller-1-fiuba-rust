/// CompactSize is a variable length integer used in Bitcoin messages.
/// It is used to save space in messages that contain a list of items.
/// It is a variable length integer that can be 1, 2, 4, or 8 bytes long.
/// The first byte determines the length of the integer.
///
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum CompactSize {
    OneByte(u8),
    TwoBytes([u8; 2]),
    FourBytes([u8; 4]),
    EightBytes([u8; 8]),
}
impl CompactSize {
    /// The maximum number of bytes that a CompactSize can be.
    /// ```
    pub const MAX_SIZE: usize = 8;

    /// The maximum number of bytes that a CompactSize can consume.
    /// ```
    pub const MAX_BYTES_CONSUMED: usize = 9;

    /// Creates a new CompactSize from a u128.
    /// If the value is less than 0xfd, a 1 byte CompactSize is returned.
    /// If the value is less than 0xffff, a 2 byte CompactSize is returned.
    /// If the value is less than 0xffffffff, a 4 byte CompactSize is returned.
    /// Otherwise, an 8 byte CompactSize is returned.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to be converted to a CompactSize.
    ///
    /// ```
    pub fn new_from_u128(value: u128) -> Result<CompactSize, Box<dyn std::error::Error>> {
        if value < 0xfd {
            Ok(CompactSize::OneByte(value as u8))
        } else if value < 0xffff {
            Ok(CompactSize::TwoBytes(u16::to_le_bytes(value as u16)))
        } else if value < 0xffffffff {
            Ok(CompactSize::FourBytes(u32::to_le_bytes(value as u32)))
        } else {
            Ok(CompactSize::EightBytes(u64::to_le_bytes(value as u64)))
        }
    }

    /// Returns the number of bytes in the CompactSize.
    /// ```
    pub fn size(&self) -> usize {
        match self {
            CompactSize::OneByte(_) => 1,
            CompactSize::TwoBytes(_) => 2,
            CompactSize::FourBytes(_) => 4,
            CompactSize::EightBytes(_) => 8,
        }
    }

    /// Returns the number of bytes consumed by the CompactSize.
    /// ```
    pub fn bytes_consumed(&self) -> usize {
        match self {
            CompactSize::OneByte(_) => 1,
            CompactSize::TwoBytes(_) => 3,
            CompactSize::FourBytes(_) => 5,
            CompactSize::EightBytes(_) => 9,
        }
    }

    /// Returns the value of the CompactSize as a u128.
    /// ```
    pub fn to_u128(&self) -> u128 {
        match self {
            CompactSize::OneByte(i) => *i as u128,
            CompactSize::TwoBytes(i) => u16::from_le_bytes([i[0], i[1]]) as u128,
            CompactSize::FourBytes(i) => u32::from_le_bytes([i[0], i[1], i[2], i[3]]) as u128,
            CompactSize::EightBytes(i) => {
                u64::from_le_bytes([i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7]]) as u128
            }
        }
    }

    /// Creates a new CompactSize from a byte slice.
    /// The value of the first byte determines the length of the CompactSize.
    /// To be used when deserializing a CompactSize.
    /// The number of bytes consumed is then obtained by calling the bytes_consumed() method.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The byte slice to be converted to a CompactSize.
    ///
    /// ```
    pub fn new_from_byte_slice(bytes: &[u8]) -> Result<CompactSize, Box<dyn std::error::Error>> {
        let mut new_bytes: [u8; 9] = [0; 9];
        new_bytes[0..bytes.len().min(Self::MAX_BYTES_CONSUMED)]
            .copy_from_slice(&bytes[0..bytes.len().min(Self::MAX_BYTES_CONSUMED)]);
        let b0 = new_bytes[0];

        if b0 < 0xfd {
            Ok(CompactSize::OneByte(b0))
        } else if b0 == 0xfd {
            Ok(CompactSize::TwoBytes(new_bytes[1..3].try_into()?))
        } else if b0 == 0xfe {
            Ok(CompactSize::FourBytes(new_bytes[1..5].try_into()?))
        } else {
            //if b0 == 0xff {
            Ok(CompactSize::EightBytes(new_bytes[1..9].try_into()?))
        }
    }

    /// Serializes the CompactSize into a byte vector.
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            CompactSize::OneByte(i) => vec![*i],
            CompactSize::TwoBytes(i) => {
                let mut v = vec![0xfd];
                v.extend_from_slice(i);
                v
            }
            CompactSize::FourBytes(i) => {
                let mut v = vec![0xfe];
                v.extend_from_slice(i);
                v
            }
            CompactSize::EightBytes(i) => {
                let mut v = vec![0xff];
                v.extend_from_slice(i);
                v
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_new_from_byte_slice() {
        let bytes = [253, 70, 1, 0, 73, 48, 70, 2, 33];
        let cs = super::CompactSize::new_from_byte_slice(&bytes).unwrap();
        assert_eq!(cs, super::CompactSize::TwoBytes([70, 1]));

        let bytes = [1, 70, 1, 0, 0, 0, 73, 48, 70, 2, 33];
        let cs = super::CompactSize::new_from_byte_slice(&bytes).unwrap();
        assert_eq!(cs, super::CompactSize::OneByte(1));

        let bytes = [254, 70, 1, 0, 0, 0, 73, 48, 70, 2, 33];
        let cs = super::CompactSize::new_from_byte_slice(&bytes).unwrap();
        assert_eq!(cs, super::CompactSize::FourBytes([70, 1, 0, 0]));

        let bytes = [255, 70, 1, 0, 0, 0, 0, 0, 0, 0, 73, 48, 70, 2, 33];
        let cs = super::CompactSize::new_from_byte_slice(&bytes).unwrap();
        assert_eq!(
            cs,
            super::CompactSize::EightBytes([70, 1, 0, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn test_new_from_u128() {
        let cs = super::CompactSize::new_from_u128(0x1).unwrap();
        assert_eq!(cs, super::CompactSize::OneByte(1));

        let cs = super::CompactSize::new_from_u128(0x100).unwrap();
        assert_eq!(cs, super::CompactSize::TwoBytes([0, 1]));

        let cs = super::CompactSize::new_from_u128(0x10000).unwrap();
        assert_eq!(cs, super::CompactSize::FourBytes([0, 0, 1, 0]));

        let cs = super::CompactSize::new_from_u128(0x100000000).unwrap();
        assert_eq!(cs, super::CompactSize::EightBytes([0, 0, 0, 0, 1, 0, 0, 0]));

        let cs = super::CompactSize::new_from_u128(252).unwrap();
        assert_eq!(cs, super::CompactSize::OneByte(252));
    }

    #[test]
    fn test_to_u128() {
        let cs = super::CompactSize::OneByte(1);
        assert_eq!(cs.to_u128(), 1);

        let cs = super::CompactSize::TwoBytes([0, 1]);
        assert_eq!(cs.to_u128(), 0x100);

        let cs = super::CompactSize::FourBytes([0, 0, 1, 0]);
        assert_eq!(cs.to_u128(), 0x10000);

        let cs = super::CompactSize::EightBytes([0, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(cs.to_u128(), 0x100000000);
    }

    #[test]
    fn test_serialize() {
        let cs = super::CompactSize::OneByte(1);
        assert_eq!(cs.serialize(), vec![1]);

        let cs = super::CompactSize::TwoBytes([0, 1]);
        assert_eq!(cs.serialize(), vec![253, 0, 1]);

        let cs = super::CompactSize::FourBytes([0, 0, 1, 0]);
        assert_eq!(cs.serialize(), vec![254, 0, 0, 1, 0]);

        let cs = super::CompactSize::EightBytes([0, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(cs.serialize(), vec![255, 0, 0, 0, 0, 1, 0, 0, 0]);
    }
}
