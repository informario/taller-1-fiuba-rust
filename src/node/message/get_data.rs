use crate::node::message::inv;
use crate::node::message::*;
/// Command for getData message.
pub const COMMAND: [u8; 12] = *b"getdata\x00\x00\x00\x00\x00";

/// Struct containing parameters for getData message.
/// ```
struct MessageParams {
    count: CompactSize,
    inventory: Vec<InvVec>,
}

/// https://developer.bitcoin.org/reference/p2p_networking.html#getdata
/// The “getdata” message requests one or more data objects from another node.
/// The objects are requested by an inventory, which the requesting node typically received previously by way of an “inv” message.
/// The response to a “getdata” message can be a “tx” message, “block” message, “merkleblock” message, “cmpctblock” message, or “notfound” message.
/// Creates a payload for a version message.
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

/// Parses the parameters for a getData message.
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
                        "Invalid parameter for getData message. Expected InvVector, got {:?}",
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
            "Invalid parameter for getData message. Expected at least one InvVector",
        )
        .into());
    }
    Ok(MessageParams { count, inventory })
}

/// Deserializes a getData message payload.
pub fn deserialize_payload(
    serialized_payload: &Vec<u8>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    let mut message_payload = Vec::<DataTypes>::new();
    let inv_count = CompactSize::new_from_byte_slice(serialized_payload)?;
    let bytes_consumed = inv_count.bytes_consumed();
    message_payload.push(DataTypes::CompactSize(inv_count));
    for i in (bytes_consumed..serialized_payload.len()).step_by(inv::INV_VEC_SIZE) {
        let inv_vec_slice = &serialized_payload[i..i + inv::INV_VEC_SIZE];
        let inv_vec_bytes: [u8; 4] = inv_vec_slice[0..4].try_into()?;
        let inv_vec_rest: [u8; inv::INV_VEC_SIZE - 4] = inv_vec_slice[4..].try_into()?;
        let inv_vec = InvVec::new(inv::InvType::from_le_bytes(inv_vec_bytes)?, inv_vec_rest);
        message_payload.push(DataTypes::InvVector(inv_vec));
    }
    Ok(message_payload)
}

#[cfg(test)]
mod tests {

    // #[test]
    // fn test_get_data_deserialize() {
    //     use super::*;

    //     // Test correct payload
    //     let get_data_message = vec![
    //         0x01, 0x01, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     ];

    //     let deserialized_payload = deserialize_payload(&get_data_message).unwrap();

    //     let expected_payload = vec![DataTypes::InvVector(InvVec::new(
    //         inv::InvType::Tx,
    //         [
    //             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //             0x00, 0x00, 0x00, 0x00,
    //         ],
    //     ))];

    //     assert_eq!(deserialized_payload, expected_payload);

    //     // Test incorrect payload
    //     let get_data_message = vec![0x01, 0x01, 0x01, 0x01, 0x01, 0x00]; // Missing bytes for inv_vec

    //     assert!(deserialize_payload(&get_data_message).is_err());

    //     let get_data_message = vec![
    //         0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //         0x00, 0x00, 0x00, 0x00,
    //     ]; // Count size too big

    //     assert!(deserialize_payload(&get_data_message).is_err());
    // }

    #[test]
    fn test_get_message_payload() {
        use super::*;

        // Test correct payload
        let params = vec![DataTypes::InvVector(InvVec::new(
            inv::InvType::Block,
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
                inv_type: inv::InvType::Block,
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
            inv::InvType::Block,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        ))];

        let message_params = parse_params(params).unwrap();

        assert_eq!(message_params.count, CompactSize::new_from_u128(1).unwrap());
        assert_eq!(message_params.inventory[0].inv_type, inv::InvType::Block);
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
