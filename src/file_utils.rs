use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::io::{Seek, SeekFrom};
use std::path::Path;

/// Resize a file to a specified size.
/// If the file does not exist, create it.
///
/// # Arguments
///
/// * `file_path` - A path to the file to resize.
///
/// * `size` - The size to resize the file to.
///
/// ```
pub fn resize_file(file_path: &str, size: u64) -> io::Result<()> {
    let file = OpenOptions::new().write(true).open(file_path)?;
    file.set_len(size)?;
    Ok(())
}

/// Check if a file exists.
/// Returns `true` if the file exists, `false` otherwise.
///
/// # Arguments
///
/// * `file_path` - A path to the file to check.
///
/// ```
pub fn file_exists<P: AsRef<Path>>(file_path: P) -> bool {
    Path::new(file_path.as_ref()).exists()
}

/// Read last `amount` bytes from a file.
///
/// # Arguments
///
/// * `file_path` - A path to the file to read.
///
/// * `amount` - The number of bytes to read.
///
/// ```
pub fn read_last_bytes<P: AsRef<Path>>(file_path: P, amount: u64) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let file_size = file.metadata()?.len();
    let offset = if file_size > amount {
        file_size - amount
    } else {
        0
    };
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0; amount as usize];
    file.read_exact(&mut data)?;
    Ok(data)
}

/// Write data to a file, replacing the file if it already exists.
/// If the file does not exist, create it.
/// If the file does exist, truncate it.
///
/// # Arguments
///
/// * `file_path` - A path to the file to write to.
/// * `data` - A slice of bytes to write to the file.
///
/// ```
pub fn write_file_binary<P: AsRef<Path>>(file_path: P, data: &[u8]) -> io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(data)?;
    Ok(())
}

/// Append data to the end of a file.
/// If the file does not exist, create it.
/// If the file does exist, append to it.
///
/// # Arguments
///
/// * `file_path` - A path to the file to append to.
///
/// * `data` - A slice of bytes to append to the file.
///
/// ```
pub fn append_to_file_binary<P: AsRef<Path>>(file_path: P, data: &[u8]) -> io::Result<()> {
    // Open the file with the `append` option
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(file_path)?;

    // Write the data to the end of the file
    file.write_all(data)?;

    Ok(())
}

/// Insert data into a file at a specified offset.
/// If the file does not exist, create it.
/// If the file does exist, insert into it at the specified offset.
///
/// # Arguments
///
/// * `file_path` - A path to the file to insert into.
///
/// * `offset` - The offset at which to insert the data.
///
/// * `data` - A slice of bytes to insert into the file.
///
/// ```
pub fn insert_into_file_binary<P: AsRef<Path>>(
    file_path: P,
    offset: u64,
    data: &[u8],
) -> io::Result<()> {
    // Open the file in read/write mode
    let mut file = OpenOptions::new().read(true).write(true).open(file_path)?;

    // Seek to the specified offset
    file.seek(SeekFrom::Start(offset))?;

    // Read the data that comes after the insertion point
    let mut tail = vec![];
    file.read_to_end(&mut tail)?;

    // Move the tail of the file after the insertion point
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)?;
    file.write_all(&tail)?;

    Ok(())
}

/// Read the contents of a file as a vector of bytes.
///
/// # Arguments
///
/// * `file_path` - A path to the file to read.
///
/// ```
pub fn read_file_binary<P: AsRef<Path>>(file_path: P) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

/// Get the size of a file in bytes.
/// Returns `Ok(file_size)` if the file exists, `Err(io::Error)` otherwise.
/// If the file does not exist, the error kind will be `NotFound`.
///
/// # Arguments
///
/// * `file_path` - A path to the file to check.
///
/// ```
pub fn get_file_size<P: AsRef<Path>>(file_path: P) -> io::Result<u64> {
    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len();
    Ok(file_size)
}

/// Read the contents of a file as a vector of bytes, starting at a specified offset.
///
/// # Arguments
///
/// * `file_path` - A path to the file to read.
///
/// * `offset` - The offset at which to start reading.
///
/// * `amount` - The number of bytes to read. If `amount` is 0, read all the data from the offset to the end of the file.
///
/// ```
pub fn read_file_binary_offset<P: AsRef<Path>>(
    file_path: P,
    offset: u64,
    amount: u64,
) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    file.seek(SeekFrom::Start(offset))?;
    if amount > 0 {
        let mut data = vec![0; amount as usize];
        file.read_exact(&mut data)?;
        Ok(data)
    } else {
        // Read all the data from the offset to the end of the file
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}

/// Write a string to a file, replacing the file if it already exists.
/// If the file does not exist, create it.
/// If the file does exist, truncate it.
///
/// # Arguments
///
/// * `file_path` - A path to the file to read.
///
/// * `data` - A string to write to the file.
///
/// ```
pub fn write_file_utf8<P: AsRef<Path>>(file_path: P, data: &str) -> io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

/// Append a string to the end of a file.
/// If the file does not exist, create it.
/// If the file does exist, append to it.
///
/// # Arguments
///
/// * `file_path` - A path to the file to append to.
///
/// * `data` - A string to append to the file.
///
/// ```
pub fn append_to_file_utf8<P: AsRef<Path>>(file_path: P, data: &str) -> io::Result<()> {
    // Open the file with the `append` option
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(file_path)?;

    // Write the data to the end of the file
    file.write_all(data.as_bytes())?;

    Ok(())
}

/// Insert a string into a file at a specified offset.
/// If the file does not exist, create it.
/// If the file does exist, insert into it at the specified offset.
///
/// # Arguments
///
/// * `file_path` - A path to the file to insert into.
///
/// * `offset` - The offset at which to insert the data.
///
/// * `data` - A string to insert into the file.
///
/// ```
pub fn insert_into_file_utf8<P: AsRef<Path>>(
    file_path: P,
    offset: u64,
    data: &str,
) -> io::Result<()> {
    // Open the file in read/write mode
    let mut file = OpenOptions::new().read(true).write(true).open(file_path)?;

    // Seek to the specified offset
    file.seek(SeekFrom::Start(offset))?;

    // Read the data that comes after the insertion point
    let mut tail = vec![];
    file.read_to_end(&mut tail)?;

    // Move the tail of the file after the insertion point
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data.as_bytes())?;
    file.write_all(&tail)?;

    Ok(())
}

/// Read the contents of a file as a string.
/// The file must be UTF-8 encoded.
/// If the file is not UTF-8 encoded, use `read_file_binary` instead.
///
/// # Arguments
///
/// * `file_path` - A path to the file to read.
///
/// ```
pub fn read_file_utf8<P: AsRef<Path>>(file_path: P) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    Ok(data)
}

/// Read the contents of a file as a string, starting at a specified offset.
/// The file must be UTF-8 encoded.
/// If the file is not UTF-8 encoded, use `read_file_binary_offset` instead.
///
/// # Arguments
///
/// * `file_path` - A path to the file to read.
///
/// * `offset` - The offset at which to start reading.  
///
/// * `amount` - The number of bytes to read. If `amount` is 0, read all the data from the offset to the end of the file.
pub fn read_file_utf8_offset<P: AsRef<Path>>(
    file_path: P,
    offset: u64,
    amount: u64,
) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    file.seek(SeekFrom::Start(offset))?;
    if amount > 0 {
        let mut data = vec![0; amount as usize];
        file.read_exact(&mut data)?;
        Ok(String::from_utf8(data).unwrap())
    } else {
        // Read all the data from the offset to the end of the file
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        Ok(data)
    }
}
