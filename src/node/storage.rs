use crate::file_utils::*;

use super::message::block::block_header::hash_from_serialized;

const BATCH_READ_SIZE: u64 = 100000;

pub fn read_block(hash: [u8; 32]) -> Result<Vec<u8>, std::io::Error> {
    let block_height = get_block_height(hash)?;
    let first_block_height_stored = get_first_block_height_stored()?;
    if block_height.is_none() || block_height.unwrap() < first_block_height_stored {
        return Ok(Vec::<u8>::new());
    }
    let offseted_block_height = block_height.unwrap() - first_block_height_stored;
    let offset = get_block_storage_offset(offseted_block_height)?;
    let size = get_block_storage_offset(offseted_block_height + 1)? - offset;
    let block = read_file_binary_offset("data/blocks.dat", offset, size)?;
    Ok(block)
}

pub fn get_block_storage_offset(offseted_block_height: u64) -> Result<u64, std::io::Error> {
    let bytes: [u8; 8] =
        match read_file_binary_offset("data/block_offsets.dat", offseted_block_height * 8, 8)?
            .try_into()
        {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid block offset",
                ))
            }
        };

    Ok(u64::from_be_bytes(bytes))
}

pub fn get_first_block_height_stored() -> Result<u64, std::io::Error> {
    let first_block_height = read_file_binary_offset("data/first_block_height_stored.dat", 0, 8)?;
    match first_block_height.try_into() {
        Ok(height) => Ok(u64::from_be_bytes(height)),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid first block height",
        )),
    }
}

pub fn get_block_height(target_hash: [u8; 32]) -> Result<Option<u64>, std::io::Error> {
    // Start measuring time
    let mut block_height = 1;
    for index in 0..(get_file_size("data/headers.dat")? / BATCH_READ_SIZE) + 1 {
        let offset = 80 + index * BATCH_READ_SIZE;
        let amount = if get_file_size("data/headers.dat")? < offset + BATCH_READ_SIZE {
            get_file_size("data/headers.dat")? - offset
        } else {
            BATCH_READ_SIZE
        };
        let headers = read_file_binary_offset("data/headers.dat", offset, amount)?;
        for i in 0..(amount / 80) as usize {
            let header = &headers[i * 80..(i + 1) * 80];
            let last_block_hash = &header[4..36];
            if last_block_hash == target_hash {
                return Ok(Some(block_height));
            }
            block_height += 1;
        }
        let last_header = &headers[(amount / 80 - 1) as usize * 80..amount as usize];
        let last_block_hash = hash_from_serialized(last_header);
        let last_block_hash_bytes: [u8; 32] = match last_block_hash[..].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid block hash",
                ))
            }
        };
        if last_block_hash_bytes == target_hash {
            return Ok(Some(block_height));
        }
    }
    Ok(None)
}

// Tests
#[cfg(test)]
mod tests {
    use crate::node::message::block::{block_header, Block};

    use super::*;

    #[test]
    fn test_get_block_storage_offset() {
        let target_hash = [
            145, 168, 38, 78, 13, 251, 40, 214, 153, 234, 253, 169, 208, 54, 57, 171, 37, 144, 28,
            249, 12, 19, 33, 192, 42, 0, 0, 0, 0, 0, 0, 0,
        ];
        println!("Target hash: {:?}", get_block_height(target_hash).unwrap());
        println!("{}", get_first_block_height_stored().unwrap());
        println!(
            "Block storage offset: {:?}",
            get_block_storage_offset(
                get_block_height(target_hash).unwrap().unwrap()
                    - get_first_block_height_stored().unwrap()
            )
            .unwrap()
        );
        let a = read_last_bytes("data/headers.dat", 80).unwrap();
        let b = block_header::BlockHeader::deserialize(&a[0..80]);
        let hash = hash_from_serialized(&a[0..80]);
        let x: [u8; 32] = hash[..].try_into().unwrap();
        println!("Hash: {:?}", x);
        println!("{}", b.validate_pow());
        println!("Block header: {:?}", b);
        let block = read_block(target_hash).unwrap();
        let deserialized_block = Block::deserialize(&block).unwrap();
        println!("Block: {:?}", deserialized_block);
    }

    #[test]
    fn test_get_first_block_height_stored() {
        let first_block_height = get_first_block_height_stored().unwrap();
        println!("First block height: {:?}", first_block_height);
    }

    #[test]
    fn test_get_block_height() {
        let target_hash = [
            193, 139, 167, 178, 61, 251, 60, 115, 148, 254, 152, 87, 160, 128, 102, 249, 48, 113,
            70, 233, 177, 91, 34, 168, 15, 0, 0, 0, 0, 0, 0, 0,
        ];

        let block_height = get_block_height(target_hash).unwrap();
        println!("Block height: {:?}", block_height);
    }
}
