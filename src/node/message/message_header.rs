#[derive(Debug)]
/// A header for a network message.
///
/// This struct contains information about the message, such as its type, length, and a checksum to
/// verify its integrity. It is designed to be used in network communication protocols where messages
/// need to be serialized and sent between different endpoints.
/// ```
pub struct MessageHeader {
    /// A magic number identifying the start of the message.
    pub magic: u32,
    /// The command or type of the message.
    pub command: [u8; 12],
    /// The length of the message body in bytes.
    pub length: u32,
    /// A checksum used to verify the integrity of the message.
    pub checksum: u32,
}

impl MessageHeader {
    /// Creates a new `MessageHeader` with the given parameters.
    /// ```
    pub fn new(magic: u32, command: [u8; 12], length: u32, checksum: u32) -> MessageHeader {
        MessageHeader {
            magic,
            command,
            length,
            checksum,
        }
    }
    /// Serializes a `MessageHeader` into a vector of bytes.
    /// The length is the sum of the size of each field in the payload.
    ///
    /// # Arguments
    ///
    /// * `header` - A `MessageHeader` to be serialized.
    ///
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::with_capacity(24);
        serialized.extend(&self.magic.to_le_bytes());
        serialized.extend(&self.command);
        serialized.extend(&self.length.to_le_bytes());
        serialized.extend(&self.checksum.to_le_bytes());
        serialized
    }

    /// Function used to deserialize a message header.
    /// It takes a vector of bytes as an argument and returns a `MessageHeader`.
    /// The message header contains information about the message, such as its length and checksum.
    ///
    /// # Arguments
    ///
    /// * `message` - The vector of bytes to be deserialized.
    /// ```
    pub fn deserialize_header(message: &[u8]) -> Result<MessageHeader, std::io::Error> {
        let magic = match message[0..4].try_into() {
            Ok(val) => u32::from_le_bytes(val),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to u32",
                ))
            }
        };
        let command: [u8; 12] = match message[4..16].try_into() {
            Ok(val) => val,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to [u8; 12]",
                ))
            }
        };

        let length = match message[16..20].try_into() {
            Ok(val) => u32::from_le_bytes(val),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to u32",
                ))
            }
        };

        let checksum = match message[20..24].try_into() {
            Ok(val) => u32::from_le_bytes(val),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Error converting bytes to u32",
                ))
            }
        };

        Ok(MessageHeader {
            magic,
            command,
            length,
            checksum,
        })
    }
}
