use super::DataTypes;

pub const COMMAND: [u8; 12] = *b"filterclear\x00";
struct MessageParams {}
pub fn create_payload(
    params: Vec<DataTypes>,
) -> Result<Vec<DataTypes>, Box<dyn std::error::Error>> {
    parse_params(params)?;
    let payload = Vec::<DataTypes>::new();
    Ok(payload)
}
fn parse_params(params: Vec<DataTypes>) -> Result<MessageParams, Box<dyn std::error::Error>> {
    if !params.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Invalid number of parameters for filterclear message. Expected 0, got {}",
                params.len()
            ),
        )
        .into());
    }
    Ok(MessageParams {})
}
