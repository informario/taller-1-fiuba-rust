use crate::node::message::*;

/// Command for getData message.
pub const COMMAND: [u8; 12] = *b"inv\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/// InvVector struct size
pub(crate) const INV_VEC_SIZE: usize = 36;

/// Max count size
pub(crate) const MAX_COUNT_SIZE: usize = 9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvType {
    Error = 0,
    Tx = 1,
    Block = 2,
    FilteredBlock = 3,
    CmpctBlock = 4,
    WitnessTx = 0x40000001,
    WitnessBlock = 0x40000002,
    FilteredWitnessBlock = 0x40000003,
}

impl InvType {
    pub fn new(inv_type: u32) -> Result<Self, Box<dyn std::error::Error>> {
        match inv_type {
            0 => Ok(Self::Error),
            1 => Ok(Self::Tx),
            2 => Ok(Self::Block),
            3 => Ok(Self::FilteredBlock),
            4 => Ok(Self::CmpctBlock),
            0x40000001 => Ok(Self::WitnessTx),
            0x40000002 => Ok(Self::WitnessBlock),
            0x40000003 => Ok(Self::FilteredWitnessBlock),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid inventory type: {}", inv_type),
            )
            .into()),
        }
    }

    pub fn to_le_bytes(&self) -> [u8; 4] {
        match self {
            Self::Error => 0u32.to_le_bytes(),
            Self::Tx => 1u32.to_le_bytes(),
            Self::Block => 2u32.to_le_bytes(),
            Self::FilteredBlock => 3u32.to_le_bytes(),
            Self::CmpctBlock => 4u32.to_le_bytes(),
            Self::WitnessTx => 0x40000001u32.to_le_bytes(),
            Self::WitnessBlock => 0x40000002u32.to_le_bytes(),
            Self::FilteredWitnessBlock => 0x40000003u32.to_le_bytes(),
        }
    }

    pub fn from_le_bytes(bytes: [u8; 4]) -> Result<Self, Box<dyn std::error::Error>> {
        let inv_type = u32::from_le_bytes(bytes);
        Self::new(inv_type)
    }
}

/// Struct for storing an inventory vector.
/// https://en.bitcoin.it/wiki/Protocol_documentation#Inventory_Vectors
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvVec {
    pub inv_type: InvType,
    pub hash: [u8; 32],
}

impl InvVec {
    pub fn new(inv_type: InvType, hash: [u8; 32]) -> Self {
        Self { inv_type, hash }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.inv_type.to_le_bytes());
        serialized.extend_from_slice(&self.hash);
        serialized
    }
}

/// Struct containing parameters for getData message.
/// ```
struct MessageParams {
    count: CompactSize,
    inventory: Vec<InvVec>,
}

/// https://developer.bitcoin.org/reference/p2p_networking.html#inv
/// The “inv” message (inventory message) transmits one or more inventories of objects
/// known to the transmitting peer. It can be sent unsolicited to announce new transactions or blocks,
/// or it can be sent in reply to a “getblocks” message or “mempool” message.
/// The receiving peer can compare the inventories from an “inv” message against the inventories it has already seen,
/// and then use a follow-up message to request unseen objects.
///
/// Creates a payload for an inv message.
/// If the parameters are valid, a vector of `DataTypes` is returned. If the parameters are invalid,
/// an `std::io::Error` is returned.
///
/// # Arguments
///
/// * `params` - A vector of parameters to be used in the message. The parameters should be a vector of InvVector DataTypes.
///
/// ```
pub fn create_payload(
    params: Vec<DataTypes>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    let message_params = parse_params(params)?;

    let mut payload = Vec::<DataTypes>::new();

    // Add count
    payload.push(DataTypes::CompactSize(message_params.count));

    // Add inventory
    for inv_vec in message_params.inventory.iter() {
        payload.push(DataTypes::InvVector(inv_vec.clone()));
    }

    Ok(payload)
}

/// Parses the parameters for a inv message.
/// If the parameters are valid, a `MessageParams` struct is returned. If the parameters are invalid,
/// an `std::io::Error` is returned.
///
/// # Arguments
///
/// * `params` - A vector of parameters to be used in the message.
///
/// ```
fn parse_params(params: Vec<DataTypes>) -> Result<MessageParams, Box<dyn std::error::Error>> {
    let mut inventory = Vec::<InvVec>::new();
    let mut count = 0;
    for param in params.iter() {
        match param {
            DataTypes::InvVector(inv_vec) => {
                inventory.push(inv_vec.clone());
                count += 1;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Invalid parameter for inv message. Expected InvVector, got {:?}",
                        param
                    ),
                )
                .into());
            }
        }
    }
    let count = CompactSize::new_from_u128(count)?;
    if count == CompactSize::new_from_u128(0)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid parameter for inv message. Expected at least one InvVector",
        )
        .into());
    }
    Ok(MessageParams { count, inventory })
}

/// Deserializes a inv message payload.
pub fn deserialize_payload(
    serialized_payload: &Vec<u8>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    let count_size = serialized_payload.len() % INV_VEC_SIZE;
    if count_size > MAX_COUNT_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid payload size for inv message. Expected multiple of {} bytes for the inventory items and number of inventory items as max {} bytes, got {}",
                INV_VEC_SIZE,
                MAX_COUNT_SIZE,
                serialized_payload.len()
            ),
        )
        .into());
    }

    let mut message_payload = Vec::<DataTypes>::new();
    for i in (0..(serialized_payload.len() - count_size)).step_by(INV_VEC_SIZE) {
        let inv_vec_slice = &serialized_payload[i + count_size..i + INV_VEC_SIZE + count_size];
        let inv_vec_bytes: [u8; 4] = inv_vec_slice[0..4].try_into()?;
        let inv_vec_rest: [u8; INV_VEC_SIZE - 4] = inv_vec_slice[4..].try_into()?;
        let inv_vec = InvVec::new(InvType::from_le_bytes(inv_vec_bytes)?, inv_vec_rest);
        message_payload.push(DataTypes::InvVector(inv_vec));
    }

    if message_payload.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid payload size for inv message. Expected at least one inventory item, got 0",
        )
        .into());
    }

    Ok(message_payload)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_data_deserialize() {
        use super::*;

        // Test correct payload
        let get_data_message = vec![
            0x01, 0x01, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let deserialized_payload = deserialize_payload(&get_data_message).unwrap();

        let expected_payload = vec![DataTypes::InvVector(InvVec::new(
            InvType::Tx,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        ))];

        assert_eq!(deserialized_payload, expected_payload);

        // Test incorrect payload
        let get_data_message = vec![0x01, 0x01, 0x01, 0x01, 0x01, 0x00]; // Missing bytes for inv_vec

        assert!(deserialize_payload(&get_data_message).is_err());

        let get_data_message = vec![
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]; // Count size too big

        assert!(deserialize_payload(&get_data_message).is_err());
    }

    #[test]
    fn test_get_message_payload() {
        use super::*;

        // Test correct payload
        let params = vec![DataTypes::InvVector(InvVec::new(
            InvType::Block,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        ))];
        let payload = create_payload(params).unwrap();

        let expected_payload = vec![
            DataTypes::CompactSize(CompactSize::OneByte(1)),
            DataTypes::InvVector(InvVec {
                inv_type: InvType::Block,
                hash: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            }),
        ];

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_parse_params() {
        use super::*;

        // Test correct params
        let params = vec![DataTypes::InvVector(InvVec::new(
            InvType::Block,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        ))];

        let message_params = parse_params(params).unwrap();

        assert_eq!(message_params.count, CompactSize::new_from_u128(1).unwrap());
        assert_eq!(message_params.inventory[0].inv_type, InvType::Block);
        assert_eq!(
            message_params.inventory[0].hash,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );

        // Test no params
        let params = vec![];
        assert!(parse_params(params).is_err());

        // Test incorrect param type
        let params = vec![DataTypes::UnsignedInt64(70015)];
        assert!(parse_params(params).is_err());
    }
}
