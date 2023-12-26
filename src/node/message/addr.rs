use std::error::Error;

use super::compact_size::CompactSize;

pub const COMMAND: [u8; 12] = *b"addr\x00\x00\x00\x00\x00\x00\x00\x00";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addr {
    pub ip_address_count: CompactSize,
    pub ip_addresses: Vec<IpAdress>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAdress {
    pub time: u32,
    pub services: u64,
    pub ip_address: [u8; 16],
    pub port: u16,
}

impl IpAdress {
    pub fn new(time: u32, services: u64, ip_address: [u8; 16], port: u16) -> IpAdress {
        Self {
            time,
            services,
            ip_address,
            port,
        }
    }
    pub fn deserialize(bytes: &[u8]) -> Result<IpAdress, Box<dyn Error>> {
        let time = u32::from_le_bytes(bytes[0..4].try_into()?);
        let services = u64::from_le_bytes(bytes[4..12].try_into()?);
        let mut ip_address: [u8; 16] = [0; 16];
        for i in 0..ip_address.len() {
            ip_address[i] = bytes[12 + i];
        }
        let port = u16::from_le_bytes(bytes[28..30].try_into()?);
        Ok(IpAdress::new(time, services, ip_address, port))
    }
}

impl Addr {
    pub fn new(ip_addresses: Vec<IpAdress>) -> Result<Addr, Box<dyn Error>> {
        let ip_address_count = CompactSize::new_from_u128(ip_addresses.len().try_into()?)?;
        Ok(Self {
            ip_address_count,
            ip_addresses,
        })
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Addr, Box<dyn Error>> {
        let ip_address_count = CompactSize::new_from_byte_slice(
            bytes[0..0 + CompactSize::MAX_BYTES_CONSUMED].try_into()?,
        )?;
        let addr_start = ip_address_count.bytes_consumed();
        let mut ip_addresses: Vec<IpAdress> = vec![];
        for i in (addr_start..bytes.len()).step_by(30) {
            let ip_address = IpAdress::deserialize(&bytes[i..i + 30])?;
            ip_addresses.push(ip_address)
        }
        Self::new(ip_addresses)
    }
    pub fn get_bloom_compatible_adresses(addresses: Addr) -> Result<Addr, Box<dyn Error>> {
        let mut compatible_addresses = vec![];
        for address in addresses.ip_addresses {
            let last_byte_from_services = address.services.to_le_bytes()[0];
            if last_byte_from_services == 0xd {
                compatible_addresses.push(address);
            }
        }
        Addr::new(compatible_addresses)
    }
}
