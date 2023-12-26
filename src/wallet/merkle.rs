use bitcoin_hashes::{sha256, Hash};
use murmur3::{self, murmur3_32};
use std::error::Error;

use node::message::block::transaction::Transaction;

use crate::node;

pub const FALSE_POSITIVE_RATE: f64 = 0.1;
const OPTIMIZED_CONSTANT: usize = 0xfba4c795;
const LN2SQRD: f64 = 0.480_453_013_918_201_44;
pub const NTWEAK: usize = 3;

//create bloom filter **DONE
//send filterload with merkleblock inventory and filter
//send getdata
//receive merkleblock
//receive tx messages
//validate merkle trees **DONE
//send filterclear
//return whatever should be returned

pub struct PartialMerkleTree {
    pub hashes: Vec<[u8; 32]>,
    pub indexes: Vec<usize>,
    pub flags: Vec<bool>,
    pub tx_index: usize,
    pub expected_merkle_root: [u8; 32],
    pub tx_ammount: usize,
    pub row_sizes: Vec<usize>,
}
pub struct FullMerkleTree {
    pub hashes: Vec<[u8; 32]>,
    pub row_sizes: Vec<usize>,
}

impl PartialMerkleTree {
    pub fn new(tx_index: usize, expected_merkle_root: [u8; 32], tx_ammount: usize) -> Self {
        Self {
            hashes: vec![],
            flags: vec![],
            tx_index,
            expected_merkle_root,
            tx_ammount,
            indexes: vec![],
            row_sizes: vec![],
        }
    }
}
fn get_hash_by_concatenating_two_arrays(first_array: [u8; 32], second_array: [u8; 32]) -> [u8; 32] {
    let mut paired_txids = Vec::new();
    for byte in first_array {
        paired_txids.push(byte);
    }
    for byte in second_array {
        paired_txids.push(byte);
    }
    let paired_txids = sha256::Hash::hash(paired_txids.as_slice());
    let paired_txids = sha256::Hash::hash(&paired_txids[..]);
    paired_txids.to_byte_array()
}
pub fn get_obtained_merkle_root(
    hashes: &[[u8; 32]],
    flags: &[bool],
    tx_ammount: usize,
) -> [u8; 32] {
    let max_height = ((tx_ammount as f64).log2()).ceil() as usize;
    process_node(&mut flags.iter(), &mut hashes.iter(), 0, max_height)
}

pub fn process_node(
    flags: &mut std::slice::Iter<'_, bool>,
    hashes: &mut std::slice::Iter<'_, [u8; 32]>,
    height: usize,
    max_height: usize,
) -> [u8; 32] {
    match flags.next() {
        Some(true) => {
            match height >= max_height {
                //Use the next hash as this node’s TXID, and mark this
                //transaction as matching the filter.
                true => *hashes.next().unwrap(),
                //The hash needs to be computed. Process the left child
                //node to get its hash; process the right child node to
                //get its hash; then concatenate the two hashes as 64
                //raw bytes and hash them to get this node’s hash.
                false => {
                    let izq = process_node(flags, hashes, height + 1, max_height);
                    let der = process_node(flags, hashes, height + 1, max_height);
                    get_hash_by_concatenating_two_arrays(izq, der)
                }
            }
        }
        Some(false) => {
            //Use the next hash as this node’s TXID, but this
            //transaction didn’t match the filter.
            //Use the next hash as this node’s hash. Don’t process
            //any descendant nodes.
            *hashes.next().unwrap()
        }
        None => [0; 32],
    }
}

pub fn create_partial_merkle_tree(
    transactions: &Vec<Transaction>,
    tx_index: usize,
    expected_merkle_root: [u8; 32],
) -> PartialMerkleTree {
    let root_height = ((transactions.len() as f64).log2()).ceil() as usize;
    let full_merkle_tree = create_full_merkle_tree(transactions);
    let mut partial_merkle_tree =
        PartialMerkleTree::new(tx_index, expected_merkle_root, transactions.len());
    let mut match_ancestor: Vec<usize> = vec![];
    let leaf_hashes_len = 2_usize.pow(root_height as u32);
    for i in 0..(root_height + 1) {
        let ancestor =
            (tx_index / (2_usize.pow(i as u32))) + (leaf_hashes_len / (2_usize.pow(i as u32)) - 1);
        match_ancestor.push(ancestor);
    }
    match_ancestor.push(0);
    process_full_tree(
        &full_merkle_tree.hashes,
        root_height,
        root_height,
        0,
        &mut partial_merkle_tree,
        &match_ancestor,
        &full_merkle_tree.row_sizes,
    );
    partial_merkle_tree
}

pub fn check_merkle_tree(tree: PartialMerkleTree) -> bool {
    let obtained_root = get_obtained_merkle_root(&tree.hashes, &tree.flags, tree.tx_ammount);
    obtained_root == tree.expected_merkle_root
}

pub fn process_full_tree(
    tree: &Vec<[u8; 32]>,
    root_height: usize,
    height: usize,
    index: usize,
    partial_tree: &mut PartialMerkleTree,
    match_ancestor: &Vec<usize>,
    row_sizes: &Vec<usize>,
) {
    let mut match_ancestor_is_true = false;
    for position in match_ancestor {
        if *position == index {
            match_ancestor_is_true = true;
        }
    }
    let relative_position_in_my_row = index + 1 - (2_usize.pow((root_height - height) as u32));
    if relative_position_in_my_row > row_sizes[height] {
        return;
    }
    match match_ancestor_is_true {
        true => match height == 0 {
            true => {
                /*Append a 1 to the flag list; append this node’s TXID to the hash list.*/
                partial_tree.indexes.push(index);
                partial_tree.flags.push(true);
                partial_tree.hashes.push(tree[index]);
            }
            false => {
                /*Append a 1 to the flag list; process the left child node. Then, if the
                node has a right child, process the right child. Do not append a hash to
                the hash list for this node. */
                partial_tree.flags.push(true);
                let end_of_my_row = 2_usize.pow((root_height - height + 1) as u32) - 2;
                process_full_tree(
                    tree,
                    root_height,
                    height - 1,
                    end_of_my_row + relative_position_in_my_row * 2 + 1,
                    partial_tree,
                    match_ancestor,
                    row_sizes,
                );
                process_full_tree(
                    tree,
                    root_height,
                    height - 1,
                    end_of_my_row + relative_position_in_my_row * 2 + 2,
                    partial_tree,
                    match_ancestor,
                    row_sizes,
                );
            }
        },
        false => match height == 0 {
            true => {
                /*Append a 0 to the flag list; append this node’s TXID to the hash list. */
                partial_tree.indexes.push(index);
                partial_tree.flags.push(false);
                partial_tree.hashes.push(tree[index]);
            }
            false => {
                /*Append a 0 to the flag list; append this node’s hash to the hash list.
                Do not descend into its child nodes. */
                partial_tree.indexes.push(index);
                partial_tree.flags.push(false);
                partial_tree.hashes.push(tree[index]);
            }
        },
    };

    /*match (height==0) {
        true => todo!(),
        false => todo!(),
    };*/
}

pub fn create_full_merkle_tree(transactions: &Vec<Transaction>) -> FullMerkleTree {
    let max_height = ((transactions.len() as f64).log2()).ceil() as usize;
    let mut full_merkle_tree: Vec<[u8; 32]> = Vec::new();
    let mut previous_row: Vec<[u8; 32]> = Vec::new();
    let mut row_sizes: Vec<usize> = vec![];
    let mut aux = transactions.len();
    for _i in 0..(max_height + 1) {
        row_sizes.push(aux);
        if aux % 2 == 1 {
            aux += 1;
        }
        aux /= 2;
    }

    for tx in transactions {
        previous_row.push(tx.get_transaction_id().unwrap());
    }
    for _i in 0..(2_usize.pow((max_height) as u32) - transactions.len()) {
        previous_row.push([0; 32]);
    }
    for hash in &previous_row {
        full_merkle_tree.push(*hash);
    }
    for i in 0..max_height {
        previous_row = create_hash_row(&mut previous_row, 2_usize.pow((max_height - i - 1) as u32));
        (0..previous_row.len()).for_each(|i| full_merkle_tree.insert(i, previous_row[i]));
    }
    FullMerkleTree {
        hashes: full_merkle_tree,
        row_sizes,
    }
}

pub fn create_hash_row(previous_row: &mut Vec<[u8; 32]>, row_size: usize) -> Vec<[u8; 32]> {
    //let max_height = ((transactions.len() as f64).log2()).ceil() as usize;
    let mut next_row: Vec<[u8; 32]> = Vec::new();
    for i in 0..(previous_row.len() / 2) {
        let primer_array = previous_row[i * 2];
        let segundo_array = previous_row[i * 2 + 1];
        if primer_array == [0; 32] && segundo_array == [0; 32] {
            next_row.push([0; 32]);
        } else if segundo_array == [0; 32] {
            next_row.push(get_hash_by_concatenating_two_arrays(
                primer_array,
                primer_array,
            ));
        } else {
            next_row.push(get_hash_by_concatenating_two_arrays(
                primer_array,
                segundo_array,
            ));
        }
    }
    for _i in previous_row.len()..row_size {
        next_row.push([0; 32]);
    }
    next_row
}

pub fn create_bloom_filter_from_tx(tx: &Transaction) -> Result<Vec<u8>, Box<dyn Error>> {
    let n_filter_bytes: usize = get_n_filter_bytes(FALSE_POSITIVE_RATE, 1);
    let n_hash_funcs: usize = get_n_hash_funcs(n_filter_bytes, 1);
    let mut bloom_filter: Vec<u8> = vec![0; n_filter_bytes];
    let mut seeds: Vec<u32> = vec![];
    for n_hash_num in 0..n_hash_funcs {
        let not_truncated_seed: usize = n_hash_num * OPTIMIZED_CONSTANT + NTWEAK;
        let seed = truncate_to_most_significative_bits(not_truncated_seed)?;
        seeds.push(seed);
    }
    for seed in seeds {
        let first_hash = sha256::Hash::hash(tx.serialize()?.as_slice());
        let txid: [u8; 32] = sha256::Hash::hash(&first_hash[..]).to_byte_array();
        let mut slice: &[u8] = &txid;
        let mut read: &mut dyn std::io::Read = &mut slice;
        let bit_overall_position =
            murmur3_32(&mut read, seed)? as usize % (8_usize * n_filter_bytes);
        let inside_byte_bit_position = bit_overall_position % 8;
        let byte_position = bit_overall_position / 8;
        bloom_filter[byte_position] |= 1 << inside_byte_bit_position;
    }
    Ok(bloom_filter)
}

pub fn get_n_filter_bytes(p: f64, n: usize) -> usize {
    let x = (-(p.ln()) * (n as f64) / (LN2SQRD * 8.0)) as usize;
    if x == 0 {
        return 1_usize;
    };
    x
}
pub fn get_n_hash_funcs(s: usize, n: usize) -> usize {
    let x = (s as f64 * 8.0 / n as f64 * std::f64::consts::LN_2) as usize;
    if x > 50 {
        return 50_usize;
    };
    x
}
fn truncate_to_most_significative_bits(not_truncated: usize) -> Result<u32, Box<dyn Error>> {
    let truncated: u32;
    let bytes: [u8; 8] = not_truncated.to_be_bytes();
    if not_truncated <= 0xffffffff00000000 {
        truncated = not_truncated as u32;
    } else {
        let mut seed_array: [u8; 4] = [0; 4];
        for i in 0..4 {
            if bytes[i] != 0 {
                seed_array = bytes[i..i + 4].try_into()?;
                break;
            }
        }
        truncated = u32::from_be_bytes(seed_array);
    }
    Ok(truncated)
}

#[cfg(test)]
mod tests {
    use crate::wallet::merkle::{
        get_hash_by_concatenating_two_arrays, get_n_filter_bytes, get_n_hash_funcs,
        get_obtained_merkle_root, truncate_to_most_significative_bits,
    };
    //use super::{create_hash_row, PartialMerkleTree, process_full_tree};
    #[test]
    fn test_n_filter_bytes_ammount() {
        assert_eq!(get_n_filter_bytes(0.1, 20000), 11981_usize);
    }
    #[test]
    fn test_n_hash_func_ammount() {
        assert_eq!(get_n_hash_funcs(11981, 20000), 3_usize);
    }

    #[test]
    fn test_truncate_to_most_significative_bits() {
        assert_eq!(truncate_to_most_significative_bits(3_usize).unwrap(), 3_u32);
        assert_eq!(
            truncate_to_most_significative_bits(0x1211108967452301_usize).unwrap(),
            0x67452301_u32
        );
        assert_eq!(
            truncate_to_most_significative_bits(0x8967452301_usize).unwrap(),
            0x67452301_u32
        );
        assert_eq!(
            truncate_to_most_significative_bits(0x967452301_usize).unwrap(),
            0x67452301_u32
        );
        assert_eq!(
            truncate_to_most_significative_bits(0x7452301_usize).unwrap(),
            0x07452301_u32
        );
    }
    //test_create_merkle_tree():
    /*
                      H1234 -> merkle root
                 ╔══════╩═════╗
                H1          H234
                       ╔══════╩═════╗
                      H23           H4
                ╔══════╩═════╗
               H2            H3
    */
    #[test]
    fn test_get_hash() {
        let array0123: [u8; 32] = [
            0xAC, 0x41, 0xEF, 0xCA, 0x49, 0x51, 0xB1, 0x26, 0x00, 0x54, 0xE1, 0x15, 0x5F, 0xD8,
            0xF6, 0xC3, 0xF4, 0x2A, 0x5B, 0x52, 0x1F, 0x11, 0x61, 0xB2, 0x0F, 0x3C, 0x05, 0x3D,
            0x31, 0x59, 0x81, 0x6C,
        ];
        let array4567: [u8; 32] = [
            0xDE, 0x0B, 0x19, 0xC7, 0x60, 0xE0, 0xF2, 0x37, 0x5B, 0x19, 0xD8, 0xF6, 0x0E, 0xDD,
            0xD2, 0x65, 0xA2, 0xF9, 0x42, 0x99, 0xC0, 0xDA, 0x0E, 0x04, 0xC6, 0x3C, 0x09, 0xE7,
            0x64, 0xCA, 0x59, 0xDA,
        ];
        println!(
            "{:02X?}",
            get_hash_by_concatenating_two_arrays(array0123, array4567)
        );
    }
    #[test]
    fn test_create_merkle_tree() {
        let array1: [u8; 32] = [0; 32];
        let array2: [u8; 32] = [1; 32];
        let array3: [u8; 32] = [2; 32];
        let array4: [u8; 32] = [3; 32];
        let _array23: [u8; 32] = [
            0x39, 0xCE, 0x20, 0xBE, 0xDE, 0x82, 0xC9, 0x6B, 0x89, 0x08, 0xBE, 0xC4, 0xA1, 0x57,
            0xB0, 0x9C, 0x54, 0x9B, 0x3D, 0xB9, 0x0B, 0x9B, 0x47, 0x4B, 0xDA, 0x9A, 0xE9, 0xB9,
            0x03, 0x03, 0x10, 0xB4,
        ];
        let _array234: [u8; 32] = [
            0x50, 0x0A, 0x4B, 0x28, 0x2D, 0xB8, 0x15, 0x28, 0x75, 0x60, 0x0C, 0x06, 0x1D, 0x98,
            0x35, 0x60, 0xEF, 0x94, 0x24, 0x8C, 0x4C, 0x4A, 0x40, 0x03, 0x55, 0xE9, 0x6B, 0x90,
            0x8A, 0x0A, 0x12, 0x1A,
        ];
        let array1234: [u8; 32] = [
            0xCE, 0x20, 0x5C, 0x88, 0x5C, 0xCD, 0x96, 0x9F, 0x05, 0xC3, 0x54, 0xB0, 0x21, 0x29,
            0xF7, 0xDE, 0x96, 0x48, 0x8B, 0x00, 0x76, 0x72, 0x08, 0x02, 0xF7, 0x3F, 0xA1, 0xE5,
            0xD1, 0x62, 0x31, 0x1D,
        ];
        let flags: Vec<bool> = [true, false, true, true, true, false, false, false].to_vec();
        let hashes: Vec<[u8; 32]> = [array1, array2, array3, array4].to_vec();
        let tx_ammount = 7;
        let obtained_merkle_root = get_obtained_merkle_root(&hashes, &flags, tx_ammount);
        assert_eq!(obtained_merkle_root, array1234);
    }
}
