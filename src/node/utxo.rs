use crate::node::message::block::Block;
use crate::node::p2pkh::{decode_bitcoin_address, parse_p2pkh_tx_output};
use std::collections::HashMap;

/// UTXO struct
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Utxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub script: Vec<u8>,
}

impl Utxo {
    /// Create a new UTXO
    ///
    /// # Arguments
    ///
    /// * `txid` - Transaction ID
    /// * `vout` - Vout
    /// * `amount` - Amount
    /// * `script` - Script
    ///
    /// ```
    pub fn new(txid: [u8; 32], vout: u32, amount: u64, script: Vec<u8>) -> Utxo {
        Utxo {
            txid,
            vout,
            amount,
            script,
        }
    }
}

/// UTXO set struct
/// Its main purpose is to keep track of the UTXOs.
/// It is implemented as a HashMap of UTXOs, indexed by TxidVout.
/// This allows to search/remove UTXOs by TxidVout in O(1).
///
/// It also provides a HashMap of balances, indexed by script_pubkey.
/// This allows to search balances by script_pubkey in O(1).
///
/// ```
#[derive(Debug, Clone, Default)]
pub struct UtxoSet {
    /// HashMap of UTXOs, indexed by TxidVout
    utxos: HashMap<TxidVout, Utxo>,
    balances: HashMap<[u8; 20], u64>,
}

impl UtxoSet {
    /// Create a new UTXO set
    /// ```
    pub fn new() -> Self {
        UtxoSet {
            utxos: HashMap::new(),
            balances: HashMap::new(),
        }
    }

    /// Add a new UTXO to the set
    ///
    /// # Arguments
    ///
    /// * `utxo` - UTXO
    ///
    /// ```
    pub fn add(&mut self, utxo: Utxo) {
        let txid_vout = TxidVout::new(utxo.txid, utxo.vout);

        self.utxos.insert(txid_vout, utxo);
    }

    /// Remove a UTXO from the set by TxidVout
    ///
    /// # Arguments
    ///
    /// * `txid_vout` - TxidVout
    ///
    /// ```
    pub fn remove_by_txid_vout(&mut self, txid_vout: TxidVout) {
        self.utxos.remove(&txid_vout);
    }

    /// Search a UTXO by TxidVout
    ///
    /// # Arguments
    ///
    /// * `txid_vout` - TxidVout
    ///
    /// ```
    pub fn search_by_txid_vout(&self, txid_vout: TxidVout) -> Option<&Utxo> {
        self.utxos.get(&txid_vout)
    }

    /// Search a UTXO by TxidVout and see if it is from a given address
    /// It returns true if the UTXO is from the given address
    /// It returns false if the UTXO is not from the given address
    ///
    /// # Arguments
    ///
    /// * `txid_vout` - TxidVout
    ///
    /// * `address` - Address
    ///
    /// ```
    pub fn txid_vout_is_from_address(&self, txid_vout: TxidVout, address: &str) -> bool {
        if let Some(utxo) = self.search_by_txid_vout(txid_vout) {
            let script_pubkey = parse_p2pkh_tx_output(&utxo.script);
            if let Some(script_pubkey) = script_pubkey {
                if let Ok(decoded_address) = decode_bitcoin_address(address) {
                    if decoded_address == script_pubkey {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Get a list of UTXO corresponding to script_pubkey
    ///
    /// # Arguments
    ///
    /// * `script_pubkey` - Script pubkey
    ///
    /// ```
    // pub fn search_by_script_pubkey(&self, script_pubkey: [u8; 20]) -> Option<Vec<Utxo>> {
    //     // Iterating over the HashMap
    //     let mut utxos = Vec::new();
    //     for utxo in self.utxos.values() {
    //         if utxo.script_pubkey == script_pubkey {
    //             utxos.push(utxo.clone());
    //         }
    //     }
    //     if utxos.len() == 0 {
    //         return None;
    //     }
    //     Some(utxos)
    // }

    /// Iterate over the UTXOs
    ///
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &Utxo> {
        self.utxos.values()
    }

    /// Update the UTXO set.
    /// It adds the new UTXOs and removes the spent UTXOs.
    ///
    /// # Arguments
    ///
    /// * `utxo_set` - UTXO set
    ///
    /// * `block` - Block
    ///
    /// * `balances` - Balances
    ///
    /// ```
    pub fn update(&mut self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        for tx in block.get_transactions() {
            // Iterate through the outputs of the transaction to find the newUtxos
            // println!(
            //     "Transaction ID: {:?}",
            //     tx.get_transaction_id()?
            //         .iter()
            //         .map(|byte| format!("{:02x}", byte))
            //         .collect::<String>()
            // );
            for (i, output) in tx.outputs.iter().enumerate() {
                // Create a new Utxo and insert it into the utxo_set
                let utxo = Utxo::new(
                    tx.get_transaction_id()?,
                    i as u32,
                    output.value,
                    output.script.clone(),
                );
                self.add(utxo);

                if !self.balances.is_empty() {
                    // Update the balances
                    let script_pubkey = parse_p2pkh_tx_output(&output.script);
                    if let Some(script_pubkey) = script_pubkey {
                        if self.balances.get(&script_pubkey).is_some() {
                            let balance = self.balances.entry(script_pubkey).or_insert(0);
                            *balance += output.value;
                        }
                    }
                }
            }

            // Iterate through the inputs of the transaction to find the spentUtxos
            // and remove them from the utxo_set
            for input in &tx.inputs {
                let txid = input.previous_output_tx_hash;
                let vout = input.previous_output_index;
                if !self.balances.is_empty() {
                    // Update the balances
                    let utxo = self.search_by_txid_vout(TxidVout::new(txid, vout)).cloned();
                    if let Some(utxo) = utxo {
                        let script_pubkey = parse_p2pkh_tx_output(&utxo.script);
                        if let Some(script_pubkey) = script_pubkey {
                            if self.balances.get(&script_pubkey).is_some() {
                                let balance = self.balances.entry(script_pubkey).or_insert(0);
                                *balance -= utxo.amount;
                            }
                        }
                    }
                }
                self.remove_by_txid_vout(TxidVout::new(txid, vout));
            }
        }
        Ok(())
    }

    /// Get the balance of an address
    ///
    /// # Arguments
    ///
    /// * `address` - Address
    ///
    /// ```
    pub fn get_address_balance(
        &mut self,
        address: &str,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let script_pubkey = decode_bitcoin_address(address)?;
        let balance;
        if self.balances.get(&script_pubkey).is_none() {
            balance = get_script_pubkey_balance(&script_pubkey, self.iter())?;
            self.balances.insert(script_pubkey, balance);
        } else {
            balance = self.balances[&script_pubkey];
        }
        Ok(balance)
    }
}

/// TxidVout struct
/// It is used as a key in the UTXO set HashMaps.
/// It is a tuple of txid and vout.
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxidVout {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// TxidVout implementation
/// ```
impl TxidVout {
    /// Create a new TxidVout
    ///
    /// # Arguments
    ///
    /// * `txid` - Transaction ID
    ///
    /// * `vout` - Vout
    ///
    /// ```
    pub fn new(txid: [u8; 32], vout: u32) -> TxidVout {
        TxidVout { txid, vout }
    }
}

/// Get the balance of a script_pubkey from the UTXO set
///
/// # Arguments
///
/// * `script_pubkey` - Script pubkey
///
/// * `utxo_set_iter` - UTXO set iterator
///
/// ```
fn get_script_pubkey_balance<'a, I>(
    script_pubkey: &[u8; 20],
    utxo_set_iter: I,
) -> Result<u64, Box<dyn std::error::Error>>
where
    I: Iterator<Item = &'a Utxo>,
{
    let mut balance = 0;

    for utxo in utxo_set_iter {
        if let Some(sp) = parse_p2pkh_tx_output(&utxo.script) {
            if sp == *script_pubkey {
                balance += utxo.amount;
            }
        }
    }

    Ok(balance)
}

#[cfg(test)]
mod tests {

    use bitcoin_hashes::hex;

    use super::{get_script_pubkey_balance, Utxo};

    #[test]
    fn test_decode_bitcoin_address() {
        let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let decoded_address = super::decode_bitcoin_address(address).unwrap();
        assert_eq!(
            decoded_address,
            [
                98, 233, 7, 177, 92, 191, 39, 213, 66, 83, 153, 235, 246, 240, 251, 80, 235, 184,
                143, 24
            ]
        );

        let address = "mhNY9fvecoDkCfib9qNB3H4cFYt2UsQzpi";
        let decoded_address = super::decode_bitcoin_address(address).unwrap();
        let expected_pubkey_script: [u8; 20] =
            hex::FromHex::from_hex("1458c4e011c3829850488539160871dcc90c5da7").unwrap();

        assert_eq!(decoded_address, expected_pubkey_script);
    }

    #[test]
    fn test_get_script_pubkey_balance() {
        let utxos = vec![
            Utxo {
                txid: [
                    9, 98, 44, 87, 25, 22, 47, 187, 158, 139, 11, 132, 193, 167, 113, 198, 218, 60,
                    20, 173, 205, 110, 238, 18, 150, 197, 206, 221, 130, 35, 97, 54,
                ],
                vout: 1,
                amount: 0,
                script: vec![
                    123, 34, 105, 100, 34, 58, 110, 117, 108, 108, 44, 34, 114, 101, 115, 117, 108,
                    116, 34, 58, 123, 34, 104, 97, 115, 104, 34, 58, 34, 57, 99, 102, 50, 55, 49,
                    98, 56, 54, 97, 50, 54, 102, 55, 49, 49, 56, 52, 97, 100, 100, 48, 99, 97, 49,
                    102, 98, 51, 100, 101, 53, 49, 57, 51, 50, 97, 99, 98, 101, 100, 57, 98, 57,
                    97, 55, 53, 102, 97, 57, 101, 57, 101, 97, 57, 57, 51, 54, 57, 51, 101, 51, 57,
                    100, 99, 34, 44, 34, 99, 104, 97, 105, 110, 105, 100, 34, 58, 49, 44, 34, 112,
                    114, 101, 118, 105, 111, 117, 115, 98, 108, 111, 99, 107, 104, 97, 115, 104,
                    34, 58, 34, 51, 51, 52, 51, 102, 100, 55, 57, 51, 57, 48, 57, 50, 54, 102, 52,
                    97, 97, 97, 48, 52, 100, 98, 55, 98, 99, 99, 56, 51, 54, 97, 49, 54, 54, 53,
                    97, 48, 102, 53, 97, 50, 48, 51, 102, 102, 49, 97, 57, 51, 99, 51, 97, 52, 97,
                    101, 101, 56, 97, 49, 56, 50, 50, 52, 49, 34, 44, 34, 99, 111, 105, 110, 98,
                    97, 115, 101, 118, 97, 108, 117, 101, 34, 58, 49, 50, 53, 48, 48, 48, 48, 48,
                    48, 48, 44, 34, 98, 105, 116, 115, 34, 58, 34, 50, 48, 55, 102, 102, 102, 102,
                    102, 34, 44, 34, 104, 101, 105, 103, 104, 116, 34, 58, 51, 49, 50, 44, 34, 95,
                    116, 97, 114, 103, 101, 116, 34, 58, 34, 48, 48, 48, 48, 48, 48, 48, 48, 48,
                    48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
                    48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
                    48, 48, 48, 48, 48, 48, 48, 48, 48, 102, 102, 102, 102, 55, 102, 34, 44, 34,
                    109, 101, 114, 107, 108, 101, 95, 115, 105, 122, 101, 34, 58, 49, 44, 34, 109,
                    101, 114, 107, 108, 101, 95, 110, 111, 110, 99, 101, 34, 58, 50, 53, 57, 54,
                    57, 57, 54, 49, 54, 50, 125, 44, 34, 101, 114, 114, 111, 114, 34, 58, 110, 117,
                    108, 108, 125,
                ],
            },
            Utxo {
                txid: [
                    123, 22, 105, 16, 85, 146, 143, 60, 121, 115, 35, 117, 132, 9, 57, 171, 95,
                    233, 60, 225, 85, 180, 169, 178, 161, 103, 63, 112, 221, 103, 102, 206,
                ],
                vout: 1,
                amount: 500,
                script: vec![
                    118, 169, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136,
                    172,
                ],
            },
            Utxo {
                txid: [
                    16, 196, 26, 133, 24, 114, 33, 19, 11, 200, 235, 164, 63, 25, 194, 122, 183,
                    92, 252, 116, 206, 77, 162, 42, 169, 17, 162, 142, 121, 70, 125, 183,
                ],
                vout: 2,
                amount: 262144,
                script: vec![
                    0, 20, 229, 53, 25, 255, 171, 44, 224, 119, 224, 157, 218, 224, 128, 66, 148,
                    228, 91, 9, 233, 147,
                ],
            },
            Utxo {
                txid: [
                    67, 207, 213, 231, 21, 253, 180, 54, 161, 252, 230, 155, 69, 46, 9, 140, 86,
                    190, 73, 147, 109, 70, 217, 3, 186, 50, 25, 183, 196, 46, 122, 8,
                ],
                vout: 0,
                amount: 4312,
                script: vec![
                    169, 20, 151, 74, 132, 202, 215, 185, 204, 238, 183, 94, 46, 48, 172, 18, 253,
                    5, 19, 253, 94, 220, 135,
                ],
            },
            Utxo {
                txid: [
                    22, 187, 51, 22, 105, 83, 231, 243, 127, 192, 170, 93, 31, 163, 224, 232, 252,
                    198, 199, 2, 2, 64, 184, 108, 127, 0, 28, 47, 147, 58, 135, 27,
                ],
                vout: 3,
                amount: 5905864,
                script: vec![
                    118, 169, 20, 59, 87, 39, 165, 145, 100, 191, 8, 93, 52, 130, 89, 169, 160, 17,
                    139, 222, 166, 41, 22, 136, 172,
                ],
            },
            Utxo {
                txid: [
                    22, 187, 51, 22, 105, 83, 231, 243, 127, 192, 170, 93, 31, 163, 224, 232, 252,
                    198, 199, 2, 2, 64, 184, 108, 127, 0, 28, 47, 147, 58, 135, 27,
                ],
                vout: 0,
                amount: 0,
                script: vec![
                    106, 76, 80, 84, 50, 91, 212, 96, 81, 111, 24, 6, 154, 205, 139, 56, 22, 227,
                    109, 11, 154, 200, 49, 202, 79, 214, 164, 160, 212, 224, 211, 11, 55, 19, 181,
                    111, 74, 210, 123, 168, 253, 11, 22, 232, 126, 245, 8, 12, 48, 14, 117, 25, 91,
                    121, 69, 26, 25, 112, 211, 253, 19, 179, 226, 226, 128, 27, 170, 198, 156, 95,
                    0, 37, 20, 48, 0, 11, 0, 37, 20, 11, 0, 28, 48,
                ],
            },
            Utxo {
                txid: [
                    37, 174, 154, 9, 156, 205, 86, 222, 201, 18, 22, 118, 6, 196, 206, 41, 30, 82,
                    75, 8, 59, 93, 85, 197, 172, 79, 87, 202, 61, 5, 82, 23,
                ],
                vout: 1,
                amount: 1057431,
                script: vec![
                    0, 20, 219, 20, 189, 199, 38, 90, 50, 227, 79, 27, 176, 58, 158, 89, 177, 50,
                    22, 109, 237, 169,
                ],
            },
            Utxo {
                txid: [
                    16, 196, 26, 133, 24, 114, 33, 19, 11, 200, 235, 164, 63, 25, 194, 122, 183,
                    92, 252, 116, 206, 77, 162, 42, 169, 17, 162, 142, 121, 70, 125, 183,
                ],
                vout: 5,
                amount: 10000,
                script: vec![
                    0, 20, 223, 51, 231, 169, 222, 53, 214, 135, 160, 64, 26, 125, 112, 19, 192,
                    181, 222, 104, 163, 54,
                ],
            },
            Utxo {
                txid: [
                    254, 148, 88, 115, 38, 234, 253, 178, 11, 4, 106, 130, 82, 251, 191, 147, 206,
                    139, 183, 56, 194, 170, 199, 156, 98, 104, 208, 240, 85, 9, 42, 104,
                ],
                vout: 0,
                amount: 1494083,
                script: vec![
                    0, 20, 178, 21, 129, 24, 90, 16, 55, 48, 211, 113, 215, 47, 25, 46, 191, 42,
                    139, 213, 211, 181,
                ],
            },
            Utxo {
                txid: [
                    141, 207, 188, 167, 100, 78, 148, 61, 60, 205, 199, 25, 125, 155, 73, 245, 54,
                    150, 247, 23, 153, 26, 193, 130, 229, 102, 252, 158, 27, 241, 85, 100,
                ],
                vout: 0,
                amount: 1058705,
                script: vec![
                    0, 20, 19, 5, 58, 26, 209, 173, 39, 228, 92, 103, 65, 135, 45, 214, 16, 144,
                    106, 181, 7, 151,
                ],
            },
            Utxo {
                txid: [
                    16, 196, 26, 133, 24, 114, 33, 19, 11, 200, 235, 164, 63, 25, 194, 122, 183,
                    92, 252, 116, 206, 77, 162, 42, 169, 17, 162, 142, 121, 70, 125, 183,
                ],
                vout: 1,
                amount: 262144,
                script: vec![
                    0, 20, 207, 192, 101, 42, 85, 235, 192, 173, 224, 126, 40, 28, 122, 91, 151,
                    253, 16, 246, 208, 166,
                ],
            },
            Utxo {
                txid: [
                    97, 212, 61, 252, 98, 124, 129, 70, 48, 215, 155, 71, 118, 67, 9, 65, 164, 192,
                    67, 180, 226, 226, 120, 13, 34, 185, 153, 96, 7, 219, 20, 79,
                ],
                vout: 0,
                amount: 0,
                script: vec![
                    106, 76, 80, 84, 50, 91, 230, 95, 83, 47, 0, 83, 19, 115, 59, 137, 227, 151, 4,
                    204, 178, 150, 0, 214, 212, 217, 163, 212, 13, 138, 250, 227, 209, 163, 144,
                    235, 82, 126, 153, 234, 254, 188, 120, 209, 243, 21, 201, 90, 221, 52, 149,
                    234, 252, 233, 33, 214, 174, 193, 62, 225, 112, 235, 238, 43, 192, 30, 77, 209,
                    207, 83, 0, 37, 20, 48, 0, 11, 0, 37, 19, 114, 0, 17, 48,
                ],
            },
            Utxo {
                txid: [
                    83, 96, 161, 37, 70, 195, 120, 103, 207, 41, 230, 150, 157, 119, 126, 51, 61,
                    1, 100, 206, 18, 185, 180, 115, 34, 33, 246, 200, 14, 83, 8, 173,
                ],
                vout: 1,
                amount: 1902037261,
                script: vec![
                    169, 20, 42, 19, 85, 156, 58, 140, 97, 107, 66, 255, 113, 93, 142, 63, 116,
                    205, 192, 237, 30, 27, 135,
                ],
            },
            Utxo {
                txid: [
                    9, 98, 44, 87, 25, 22, 47, 187, 158, 139, 11, 132, 193, 167, 113, 198, 218, 60,
                    20, 173, 205, 110, 238, 18, 150, 197, 206, 221, 130, 35, 97, 54,
                ],
                vout: 2,
                amount: 2548486,
                script: vec![
                    118, 169, 20, 187, 148, 178, 184, 206, 23, 25, 32, 27, 240, 52, 109, 121, 238,
                    15, 96, 201, 210, 112, 0, 136, 172,
                ],
            },
            Utxo {
                txid: [
                    123, 22, 105, 16, 85, 146, 143, 60, 121, 115, 35, 117, 132, 9, 57, 171, 95,
                    233, 60, 225, 85, 180, 169, 178, 161, 103, 63, 112, 221, 103, 102, 206,
                ],
                vout: 0,
                amount: 0,
                script: vec![
                    106, 76, 80, 84, 50, 91, 248, 243, 52, 73, 151, 123, 104, 177, 53, 79, 32, 105,
                    178, 171, 223, 242, 93, 25, 218, 20, 200, 104, 61, 129, 245, 234, 216, 12, 143,
                    230, 229, 0, 2, 4, 242, 59, 131, 159, 13, 38, 102, 160, 48, 94, 28, 93, 161,
                    15, 9, 117, 225, 174, 45, 44, 217, 108, 86, 101, 121, 67, 37, 23, 67, 147, 0,
                    37, 20, 48, 0, 11, 0, 37, 14, 118, 0, 28, 48,
                ],
            },
            Utxo {
                txid: [
                    231, 97, 1, 71, 224, 55, 245, 254, 108, 128, 170, 85, 161, 4, 142, 18, 109,
                    176, 173, 104, 8, 151, 90, 223, 33, 136, 201, 62, 243, 128, 147, 137,
                ],
                vout: 2,
                amount: 7000,
                script: vec![
                    118, 169, 20, 38, 166, 69, 21, 124, 19, 64, 16, 199, 10, 238, 119, 15, 151,
                    224, 222, 198, 104, 108, 12, 136, 172,
                ],
            },
            Utxo {
                txid: [
                    37, 174, 154, 9, 156, 205, 86, 222, 201, 18, 22, 118, 6, 196, 206, 41, 30, 82,
                    75, 8, 59, 93, 85, 197, 172, 79, 87, 202, 61, 5, 82, 23,
                ],
                vout: 0,
                amount: 77000,
                script: vec![
                    0, 20, 93, 87, 106, 129, 244, 96, 231, 161, 237, 37, 79, 233, 191, 255, 7, 90,
                    179, 188, 69, 101,
                ],
            },
            Utxo {
                txid: [
                    97, 212, 61, 252, 98, 124, 129, 70, 48, 215, 155, 71, 118, 67, 9, 65, 164, 192,
                    67, 180, 226, 226, 120, 13, 34, 185, 153, 96, 7, 219, 20, 79,
                ],
                vout: 3,
                amount: 30295101,
                script: vec![
                    118, 169, 20, 186, 39, 249, 158, 0, 124, 127, 96, 90, 131, 5, 227, 24, 193,
                    171, 222, 60, 210, 32, 172, 136, 172,
                ],
            },
            Utxo {
                txid: [
                    16, 196, 26, 133, 24, 114, 33, 19, 11, 200, 235, 164, 63, 25, 194, 122, 183,
                    92, 252, 116, 206, 77, 162, 42, 169, 17, 162, 142, 121, 70, 125, 183,
                ],
                vout: 3,
                amount: 262144,
                script: vec![
                    0, 20, 252, 224, 165, 190, 228, 126, 32, 136, 75, 60, 86, 130, 225, 7, 81, 232,
                    117, 28, 100, 175,
                ],
            },
            Utxo {
                txid: [
                    53, 10, 93, 70, 131, 235, 153, 180, 213, 184, 191, 15, 229, 104, 171, 4, 34,
                    87, 142, 48, 62, 222, 182, 210, 175, 124, 101, 48, 179, 56, 4, 124,
                ],
                vout: 0,
                amount: 1219937,
                script: vec![
                    0, 20, 115, 215, 248, 58, 0, 222, 97, 173, 141, 182, 166, 135, 49, 99, 7, 141,
                    90, 192, 203, 116,
                ],
            },
            Utxo {
                txid: [
                    123, 22, 105, 16, 85, 146, 143, 60, 121, 115, 35, 117, 132, 9, 57, 171, 95,
                    233, 60, 225, 85, 180, 169, 178, 161, 103, 63, 112, 221, 103, 102, 206,
                ],
                vout: 2,
                amount: 500,
                script: vec![
                    118, 169, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136,
                    172,
                ],
            },
            Utxo {
                txid: [
                    9, 98, 44, 87, 25, 22, 47, 187, 158, 139, 11, 132, 193, 167, 113, 198, 218, 60,
                    20, 173, 205, 110, 238, 18, 150, 197, 206, 221, 130, 35, 97, 54,
                ],
                vout: 0,
                amount: 0,
                script: vec![
                    106, 36, 170, 33, 169, 237, 6, 135, 42, 65, 80, 101, 195, 156, 95, 248, 208,
                    229, 32, 196, 57, 7, 64, 234, 255, 54, 68, 231, 27, 130, 230, 16, 58, 168, 162,
                    243, 21, 17,
                ],
            },
            Utxo {
                txid: [
                    255, 150, 255, 245, 94, 210, 222, 143, 62, 146, 20, 236, 48, 115, 1, 97, 98,
                    232, 217, 46, 64, 196, 143, 122, 188, 31, 129, 169, 104, 126, 175, 127,
                ],
                vout: 1,
                amount: 4969,
                script: vec![
                    0, 20, 200, 235, 241, 103, 154, 125, 231, 94, 38, 105, 187, 89, 247, 174, 196,
                    103, 90, 237, 184, 97,
                ],
            },
            Utxo {
                txid: [
                    2, 76, 88, 58, 31, 150, 197, 121, 204, 132, 246, 209, 66, 218, 94, 96, 138, 20,
                    147, 147, 209, 245, 57, 215, 64, 222, 87, 111, 200, 146, 87, 139,
                ],
                vout: 0,
                amount: 1131633,
                script: vec![
                    0, 20, 56, 238, 150, 229, 187, 55, 148, 30, 208, 64, 183, 192, 236, 155, 107,
                    82, 115, 36, 144, 25,
                ],
            },
            Utxo {
                txid: [
                    75, 60, 103, 166, 42, 34, 169, 223, 119, 118, 72, 34, 41, 158, 218, 202, 221,
                    85, 40, 28, 204, 76, 38, 129, 64, 165, 17, 73, 152, 127, 70, 26,
                ],
                vout: 0,
                amount: 57589,
                script: vec![
                    118, 169, 20, 209, 163, 137, 14, 154, 170, 121, 135, 64, 36, 170, 192, 62, 134,
                    30, 136, 171, 208, 166, 26, 136, 172,
                ],
            },
            Utxo {
                txid: [
                    239, 122, 83, 201, 171, 65, 85, 28, 54, 230, 68, 65, 13, 61, 196, 135, 1, 72,
                    222, 109, 119, 160, 23, 194, 241, 194, 41, 121, 247, 230, 165, 255,
                ],
                vout: 0,
                amount: 1379554,
                script: vec![
                    0, 20, 158, 126, 66, 158, 177, 248, 226, 154, 70, 46, 51, 128, 35, 125, 213,
                    94, 192, 155, 104, 226,
                ],
            },
            Utxo {
                txid: [
                    22, 187, 51, 22, 105, 83, 231, 243, 127, 192, 170, 93, 31, 163, 224, 232, 252,
                    198, 199, 2, 2, 64, 184, 108, 127, 0, 28, 47, 147, 58, 135, 27,
                ],
                vout: 2,
                amount: 500,
                script: vec![
                    118, 169, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136,
                    172,
                ],
            },
            Utxo {
                txid: [
                    255, 150, 255, 245, 94, 210, 222, 143, 62, 146, 20, 236, 48, 115, 1, 97, 98,
                    232, 217, 46, 64, 196, 143, 122, 188, 31, 129, 169, 104, 126, 175, 127,
                ],
                vout: 0,
                amount: 2525753858,
                script: vec![
                    0, 32, 53, 166, 33, 167, 67, 132, 61, 0, 128, 208, 13, 144, 214, 239, 158, 245,
                    189, 169, 38, 19, 42, 25, 144, 73, 61, 62, 96, 157, 71, 138, 116, 147,
                ],
            },
            Utxo {
                txid: [
                    123, 22, 105, 16, 85, 146, 143, 60, 121, 115, 35, 117, 132, 9, 57, 171, 95,
                    233, 60, 225, 85, 180, 169, 178, 161, 103, 63, 112, 221, 103, 102, 206,
                ],
                vout: 3,
                amount: 114721163,
                script: vec![
                    118, 169, 20, 139, 139, 162, 224, 107, 210, 202, 219, 218, 248, 230, 234, 6,
                    195, 97, 199, 250, 52, 28, 55, 136, 172,
                ],
            },
            Utxo {
                txid: [
                    97, 212, 61, 252, 98, 124, 129, 70, 48, 215, 155, 71, 118, 67, 9, 65, 164, 192,
                    67, 180, 226, 226, 120, 13, 34, 185, 153, 96, 7, 219, 20, 79,
                ],
                vout: 1,
                amount: 10000,
                script: vec![
                    118, 169, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136,
                    172,
                ],
            },
            Utxo {
                txid: [
                    141, 207, 188, 167, 100, 78, 148, 61, 60, 205, 199, 25, 125, 155, 73, 245, 54,
                    150, 247, 23, 153, 26, 193, 130, 229, 102, 252, 158, 27, 241, 85, 100,
                ],
                vout: 1,
                amount: 77000,
                script: vec![
                    0, 20, 93, 87, 106, 129, 244, 96, 231, 161, 237, 37, 79, 233, 191, 255, 7, 90,
                    179, 188, 69, 101,
                ],
            },
            Utxo {
                txid: [
                    254, 148, 88, 115, 38, 234, 253, 178, 11, 4, 106, 130, 82, 251, 191, 147, 206,
                    139, 183, 56, 194, 170, 199, 156, 98, 104, 208, 240, 85, 9, 42, 104,
                ],
                vout: 1,
                amount: 997284,
                script: vec![
                    0, 20, 43, 90, 94, 92, 189, 216, 125, 73, 7, 165, 229, 182, 177, 196, 61, 35,
                    242, 130, 16, 251,
                ],
            },
            Utxo {
                txid: [
                    22, 187, 51, 22, 105, 83, 231, 243, 127, 192, 170, 93, 31, 163, 224, 232, 252,
                    198, 199, 2, 2, 64, 184, 108, 127, 0, 28, 47, 147, 58, 135, 27,
                ],
                vout: 1,
                amount: 500,
                script: vec![
                    118, 169, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136,
                    172,
                ],
            },
            Utxo {
                txid: [
                    2, 76, 88, 58, 31, 150, 197, 121, 204, 132, 246, 209, 66, 218, 94, 96, 138, 20,
                    147, 147, 209, 245, 57, 215, 64, 222, 87, 111, 200, 146, 87, 139,
                ],
                vout: 1,
                amount: 600000,
                script: vec![
                    169, 20, 46, 82, 226, 226, 109, 2, 34, 198, 48, 171, 255, 162, 72, 95, 152,
                    168, 57, 63, 119, 93, 135,
                ],
            },
            Utxo {
                txid: [
                    206, 161, 11, 82, 245, 63, 98, 148, 1, 101, 195, 41, 71, 0, 142, 30, 50, 164,
                    169, 104, 236, 164, 102, 81, 122, 227, 146, 211, 209, 98, 83, 21,
                ],
                vout: 0,
                amount: 228000,
                script: vec![
                    0, 20, 93, 87, 106, 129, 244, 96, 231, 161, 237, 37, 79, 233, 191, 255, 7, 90,
                    179, 188, 69, 101,
                ],
            },
            Utxo {
                txid: [
                    206, 161, 11, 82, 245, 63, 98, 148, 1, 101, 195, 41, 71, 0, 142, 30, 50, 164,
                    169, 104, 236, 164, 102, 81, 122, 227, 146, 211, 209, 98, 83, 21,
                ],
                vout: 1,
                amount: 1045176,
                script: vec![
                    0, 20, 130, 239, 190, 92, 224, 53, 246, 121, 73, 141, 193, 140, 43, 123, 215,
                    178, 149, 83, 177, 71,
                ],
            },
            Utxo {
                txid: [
                    97, 212, 61, 252, 98, 124, 129, 70, 48, 215, 155, 71, 118, 67, 9, 65, 164, 192,
                    67, 180, 226, 226, 120, 13, 34, 185, 153, 96, 7, 219, 20, 79,
                ],
                vout: 2,
                amount: 10000,
                script: vec![
                    118, 169, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136,
                    172,
                ],
            },
            Utxo {
                txid: [
                    172, 21, 39, 148, 196, 149, 190, 6, 173, 96, 12, 148, 8, 151, 187, 106, 130, 5,
                    57, 153, 131, 107, 235, 210, 47, 24, 12, 250, 85, 216, 37, 81,
                ],
                vout: 1,
                amount: 4956085726,
                script: vec![
                    0, 20, 114, 135, 180, 199, 220, 164, 172, 39, 224, 37, 156, 1, 11, 166, 72,
                    216, 19, 1, 241, 213,
                ],
            },
            Utxo {
                txid: [
                    149, 204, 235, 22, 65, 43, 101, 61, 167, 176, 228, 10, 124, 206, 119, 171, 12,
                    217, 32, 79, 219, 169, 61, 210, 163, 184, 230, 168, 92, 250, 14, 107,
                ],
                vout: 0,
                amount: 4312,
                script: vec![
                    169, 20, 151, 74, 132, 202, 215, 185, 204, 238, 183, 94, 46, 48, 172, 18, 253,
                    5, 19, 253, 94, 220, 135,
                ],
            },
            Utxo {
                txid: [
                    231, 97, 1, 71, 224, 55, 245, 254, 108, 128, 170, 85, 161, 4, 142, 18, 109,
                    176, 173, 104, 8, 151, 90, 223, 33, 136, 201, 62, 243, 128, 147, 137,
                ],
                vout: 0,
                amount: 5689500,
                script: vec![
                    169, 20, 164, 131, 127, 200, 203, 108, 21, 24, 8, 84, 144, 221, 0, 198, 164,
                    130, 110, 107, 17, 134, 135,
                ],
            },
            Utxo {
                txid: [
                    172, 21, 39, 148, 196, 149, 190, 6, 173, 96, 12, 148, 8, 151, 187, 106, 130, 5,
                    57, 153, 131, 107, 235, 210, 47, 24, 12, 250, 85, 216, 37, 81,
                ],
                vout: 0,
                amount: 3651405,
                script: vec![
                    0, 20, 6, 133, 201, 158, 151, 151, 174, 250, 169, 204, 108, 73, 160, 139, 230,
                    194, 30, 244, 213, 92,
                ],
            },
            Utxo {
                txid: [
                    239, 122, 83, 201, 171, 65, 85, 28, 54, 230, 68, 65, 13, 61, 196, 135, 1, 72,
                    222, 109, 119, 160, 23, 194, 241, 194, 41, 121, 247, 230, 165, 255,
                ],
                vout: 1,
                amount: 4740182696,
                script: vec![
                    0, 20, 190, 156, 200, 75, 183, 174, 96, 97, 93, 92, 163, 191, 67, 203, 73, 2,
                    105, 35, 200, 201,
                ],
            },
            Utxo {
                txid: [
                    149, 204, 235, 22, 65, 43, 101, 61, 167, 176, 228, 10, 124, 206, 119, 171, 12,
                    217, 32, 79, 219, 169, 61, 210, 163, 184, 230, 168, 92, 250, 14, 107,
                ],
                vout: 1,
                amount: 1601260,
                script: vec![
                    0, 32, 243, 167, 4, 143, 247, 3, 228, 100, 113, 30, 49, 164, 226, 210, 90, 40,
                    94, 46, 170, 156, 150, 140, 125, 0, 154, 64, 251, 237, 74, 87, 40, 224,
                ],
            },
            Utxo {
                txid: [
                    16, 196, 26, 133, 24, 114, 33, 19, 11, 200, 235, 164, 63, 25, 194, 122, 183,
                    92, 252, 116, 206, 77, 162, 42, 169, 17, 162, 142, 121, 70, 125, 183,
                ],
                vout: 0,
                amount: 543108,
                script: vec![
                    81, 32, 140, 165, 72, 113, 14, 253, 193, 3, 48, 44, 59, 238, 238, 197, 20, 144,
                    217, 158, 157, 192, 36, 237, 130, 119, 53, 204, 210, 123, 112, 209, 86, 101,
                ],
            },
            Utxo {
                txid: [
                    231, 97, 1, 71, 224, 55, 245, 254, 108, 128, 170, 85, 161, 4, 142, 18, 109,
                    176, 173, 104, 8, 151, 90, 223, 33, 136, 201, 62, 243, 128, 147, 137,
                ],
                vout: 1,
                amount: 172270862,
                script: vec![
                    169, 20, 234, 134, 73, 232, 151, 222, 79, 115, 108, 118, 50, 150, 12, 151, 146,
                    190, 97, 245, 91, 227, 135,
                ],
            },
            Utxo {
                txid: [
                    16, 196, 26, 133, 24, 114, 33, 19, 11, 200, 235, 164, 63, 25, 194, 122, 183,
                    92, 252, 116, 206, 77, 162, 42, 169, 17, 162, 142, 121, 70, 125, 183,
                ],
                vout: 4,
                amount: 10000,
                script: vec![
                    0, 20, 10, 126, 144, 92, 151, 97, 152, 57, 4, 215, 27, 184, 76, 151, 148, 130,
                    75, 222, 216, 54,
                ],
            },
            Utxo {
                txid: [
                    16, 196, 26, 133, 24, 114, 33, 19, 11, 200, 235, 164, 63, 25, 194, 122, 183,
                    92, 252, 116, 206, 77, 162, 42, 169, 17, 162, 142, 121, 70, 125, 183,
                ],
                vout: 6,
                amount: 7126,
                script: vec![
                    0, 20, 116, 33, 137, 98, 138, 145, 200, 101, 34, 86, 120, 123, 27, 13, 226,
                    122, 75, 201, 188, 41,
                ],
            },
            Utxo {
                txid: [
                    75, 60, 103, 166, 42, 34, 169, 223, 119, 118, 72, 34, 41, 158, 218, 202, 221,
                    85, 40, 28, 204, 76, 38, 129, 64, 165, 17, 73, 152, 127, 70, 26,
                ],
                vout: 1,
                amount: 1560,
                script: vec![
                    0, 20, 166, 245, 185, 65, 3, 97, 77, 125, 215, 128, 171, 223, 216, 239, 199,
                    22, 48, 245, 141, 169,
                ],
            },
            Utxo {
                txid: [
                    83, 96, 161, 37, 70, 195, 120, 103, 207, 41, 230, 150, 157, 119, 126, 51, 61,
                    1, 100, 206, 18, 185, 180, 115, 34, 33, 246, 200, 14, 83, 8, 173,
                ],
                vout: 0,
                amount: 1473487,
                script: vec![
                    169, 20, 71, 21, 238, 192, 139, 131, 232, 27, 192, 145, 199, 60, 167, 21, 236,
                    85, 58, 52, 146, 72, 135,
                ],
            },
            Utxo {
                txid: [
                    53, 10, 93, 70, 131, 235, 153, 180, 213, 184, 191, 15, 229, 104, 171, 4, 34,
                    87, 142, 48, 62, 222, 182, 210, 175, 124, 101, 48, 179, 56, 4, 124,
                ],
                vout: 1,
                amount: 228000,
                script: vec![
                    0, 20, 93, 87, 106, 129, 244, 96, 231, 161, 237, 37, 79, 233, 191, 255, 7, 90,
                    179, 188, 69, 101,
                ],
            },
        ];

        let balance = get_script_pubkey_balance(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            utxos.iter(),
        )
        .unwrap();
        assert_eq!(balance, 22000);
    }
}
