use std::error::Error;

use secp256k1::Secp256k1;

use crate::{
    node::message::{
        block::transaction::{
            transaction_input::TransactionInput, transaction_output::TransactionOutput, Transaction,
        },
        compact_size::CompactSize,
    },
    wallet::decode_wif_compressed,
};

const P2PKH_SCRIPT_LENGTH: usize = 25;

pub fn create_p2pkh_transaction(
    input_tx_ids: Vec<[u8; 32]>,
    input_tx_indexes: Vec<u32>,
    input_tx_addresses: Vec<String>,
    input_tx_private_keys: Vec<String>,
    output_addresses: Vec<String>,
    output_values: Vec<u64>,
) -> Result<Transaction, Box<dyn Error>> {
    // Validate
    if input_tx_ids.len() != input_tx_indexes.len() {
        return Err("Invalid input_tx_indexes length".into());
    }
    if output_addresses.len() != output_values.len() {
        return Err("Invalid output_addresses length".into());
    }

    let version = 1;
    let input_count = CompactSize::new_from_u128(input_tx_ids.len() as u128)?;
    let output_count = CompactSize::new_from_u128(output_addresses.len() as u128)?;
    let lock_time: u32 = 0;
    let mut transaction_inputs = Vec::new();
    let mut transaction_outputs = Vec::new();

    // Create transaction inputs
    for i in 0..input_tx_ids.len() {
        let transaction_input = TransactionInput::new(
            input_tx_ids[i],
            input_tx_indexes[i],
            CompactSize::new_from_u128(0)?,
            Vec::new(),
            u32::max_value(),
        );
        transaction_inputs.push(transaction_input);
    }

    // Create transaction outputs
    for i in 0..output_addresses.len() {
        let script = create_p2pkh_script(&output_addresses[i])?;
        let transaction_output = TransactionOutput::new(
            output_values[i],
            CompactSize::new_from_u128(script.len() as u128)?,
            script,
        );
        transaction_outputs.push(transaction_output);
    }

    // Create transaction
    let mut transaction = Transaction::new(
        version,
        input_count,
        transaction_inputs,
        output_count,
        transaction_outputs,
        lock_time,
        None,
    );

    // Sign transaction inputs
    for i in 0..input_tx_ids.len() {
        sign_input(
            &mut transaction,
            i,
            &input_tx_private_keys[i],
            &input_tx_addresses[i],
        )?;
    }
    Ok(transaction)
}

/// Sign a transaction input from a given transaction using a private key and address
/// It modifies the transaction in place
/// It doesn't verify if the signature is valid
///
/// # Arguments
///
/// * `tx` - The transaction to sign
///
/// * `input_index` - The index of the input to sign
///
/// * `input_private_key` - The private key of the input
///
/// * `input_address` - The address of the input
///
/// ```
fn sign_input(
    tx: &mut Transaction,
    input_index: usize,
    input_private_key: &str,
    input_address: &str,
) -> Result<(), Box<dyn Error>> {
    let secp = Secp256k1::new();
    let private_key = decode_wif_compressed(input_private_key)?;
    let z = tx.sig_hash(input_index, input_address)?;
    let message = secp256k1::Message::from_slice(&z)?;
    let der = secp.sign_ecdsa(&message, &private_key).serialize_der();
    let mut signature = der.to_vec();
    signature.push(0x01);
    let sec = secp256k1::PublicKey::from_secret_key(&secp, &private_key);
    let mut script = vec![];
    let signature_len = CompactSize::new_from_u128(signature.len() as u128)?;
    script.extend(signature_len.serialize());
    script.extend(signature);
    let sec_len = CompactSize::new_from_u128(sec.serialize().len() as u128)?;
    script.extend(sec_len.serialize());
    script.extend(sec.serialize().to_vec());
    tx.inputs[input_index].script_length = CompactSize::new_from_u128(script.len() as u128)?;
    tx.inputs[input_index].script_sig = script;
    Ok(())
}

/// Create a P2PKH script from a Bitcoin address (base58)
/// It returns the script if the address is valid.
/// Otherwise it returns an error.
///
/// # Arguments
///
/// * `address` - Address
///
/// ```
pub fn create_p2pkh_script(address: &str) -> Result<Vec<u8>, bs58::decode::Error> {
    let pubkey_hash = decode_bitcoin_address(address)?;
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&pubkey_hash);
    script.extend_from_slice(&[0x88, 0xac]);
    Ok(script)
}

/// Decode a Bitcoin address to a script_pubkey (base58)
/// It returns the script_pubkey if the address is valid.
///
/// # Arguments
///
/// * `address` - Address
///
/// ```
pub fn decode_bitcoin_address(address: &str) -> Result<[u8; 20], bs58::decode::Error> {
    let decoded = bs58::decode(address).into_vec()?;
    let payload = &decoded[1..decoded.len() - 4];
    let mut script_pubkey = [0u8; 20];
    script_pubkey.copy_from_slice(payload);
    Ok(script_pubkey)
}

/// Parse a P2PKH transaction output
/// It returns the script_pubkey if the output is a P2PKH output.
/// Otherwise it returns None.
///
/// # Arguments
///
/// * `script` - Script
///
/// ```
pub fn parse_p2pkh_tx_output(script: &Vec<u8>) -> Option<[u8; 20]> {
    let mut script_pubkey = [0u8; 20];
    let length = script.len();
    if length != P2PKH_SCRIPT_LENGTH {
        return None;
    }
    if script[0] != 0x76 {
        return None;
    }
    if script[1] != 0xa9 {
        return None;
    }
    if script[2] != 0x14 {
        return None;
    }
    if script[23] != 0x88 {
        return None;
    }
    if script[24] != 0xac {
        return None;
    }
    script_pubkey.copy_from_slice(&script[3..23]);

    Some(script_pubkey)
}

#[cfg(test)]
mod tests {
    use super::{create_p2pkh_transaction, parse_p2pkh_tx_output, sign_input};
    use crate::node::{message::block::transaction::Transaction, utxo::Utxo};
    use bitcoin_hashes::hex::FromHex;
    #[test]
    fn test_parse_p2pkh_tx_output() {
        let utxo = Utxo {
            txid: [
                123, 22, 105, 16, 85, 146, 143, 60, 121, 115, 35, 117, 132, 9, 57, 171, 95, 233,
                60, 225, 85, 180, 169, 178, 161, 103, 63, 112, 221, 103, 102, 206,
            ],
            vout: 2,
            amount: 500,
            script: vec![
                118, 169, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 172,
            ],
        };
        let script = utxo.script;

        let script_pubkey = parse_p2pkh_tx_output(&script).unwrap();
        assert_eq!(
            script_pubkey,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_sign_input() {
        let private_key = "cRQqHEFDJuPPMjb6gTXuRx4eB9JdFKyNbFBeyk5b2J6Czf4aGmVu";
        let address = "mwqa8tCH4fSy4hjuMe6bo46KHP5tfihVdN";

        let serialized = [
            1, 0, 0, 0, 1, 210, 49, 41, 44, 208, 3, 62, 230, 93, 164, 90, 85, 116, 246, 157, 201,
            55, 83, 100, 221, 41, 30, 180, 22, 87, 194, 100, 71, 103, 64, 51, 84, 1, 0, 0, 0, 107,
            72, 48, 69, 2, 33, 0, 230, 35, 194, 243, 21, 20, 170, 82, 78, 105, 160, 203, 195, 21,
            235, 116, 119, 85, 53, 121, 191, 165, 39, 129, 223, 111, 104, 226, 178, 187, 17, 145,
            2, 32, 26, 39, 69, 164, 121, 112, 246, 212, 165, 248, 213, 252, 19, 205, 200, 91, 37,
            118, 190, 44, 179, 225, 17, 229, 171, 148, 250, 222, 244, 56, 113, 22, 1, 33, 2, 156,
            229, 196, 14, 212, 79, 124, 75, 188, 23, 137, 106, 43, 34, 134, 138, 142, 196, 226,
            177, 203, 147, 187, 84, 39, 184, 70, 77, 54, 21, 35, 90, 255, 255, 255, 255, 1, 2, 48,
            0, 0, 0, 0, 0, 0, 25, 118, 169, 20, 179, 7, 107, 77, 162, 146, 141, 57, 58, 1, 215, 65,
            228, 231, 161, 76, 117, 95, 60, 151, 136, 172, 0, 0, 0, 0,
        ];

        let (tx, _) = Transaction::deserialize(&serialized).unwrap();

        let mut tx_clone = tx;
        sign_input(&mut tx_clone, 0, private_key, address).unwrap();

        let expected_sig = [
            72, 48, 69, 2, 33, 0, 230, 35, 194, 243, 21, 20, 170, 82, 78, 105, 160, 203, 195, 21,
            235, 116, 119, 85, 53, 121, 191, 165, 39, 129, 223, 111, 104, 226, 178, 187, 17, 145,
            2, 32, 26, 39, 69, 164, 121, 112, 246, 212, 165, 248, 213, 252, 19, 205, 200, 91, 37,
            118, 190, 44, 179, 225, 17, 229, 171, 148, 250, 222, 244, 56, 113, 22, 1, 33, 2, 156,
            229, 196, 14, 212, 79, 124, 75, 188, 23, 137, 106, 43, 34, 134, 138, 142, 196, 226,
            177, 203, 147, 187, 84, 39, 184, 70, 77, 54, 21, 35, 90,
        ];

        assert_eq!(tx_clone.inputs[0].script_sig, expected_sig);
        assert_eq!(
            tx_clone.inputs[0].script_length.to_u128() as usize,
            expected_sig.len()
        );
    }

    #[test]
    fn test_create_p2pkh_tx() {
        let mut id = <[u8; 32]>::from_hex(
            "543340674764c25716b41e29dd645337c99df674555aa45de63e03d02c2931d2",
        )
        .unwrap();
        id.reverse();
        let input_tx_ids = vec![id];
        let input_tx_indexes = vec![1];
        let input_tx_addresses = vec!["mwqa8tCH4fSy4hjuMe6bo46KHP5tfihVdN".to_owned()];
        let input_tx_private_keys =
            vec!["cRQqHEFDJuPPMjb6gTXuRx4eB9JdFKyNbFBeyk5b2J6Czf4aGmVu".to_owned()];
        let output_addresses = vec!["mwqa8tCH4fSy4hjuMe6bo46KHP5tfihVdN".to_owned()];
        let output_values = vec![12290];
        let tx = create_p2pkh_transaction(
            input_tx_ids,
            input_tx_indexes,
            input_tx_addresses,
            input_tx_private_keys,
            output_addresses,
            output_values,
        )
        .unwrap();

        let expected_serialized = [
            1, 0, 0, 0, 1, 210, 49, 41, 44, 208, 3, 62, 230, 93, 164, 90, 85, 116, 246, 157, 201,
            55, 83, 100, 221, 41, 30, 180, 22, 87, 194, 100, 71, 103, 64, 51, 84, 1, 0, 0, 0, 107,
            72, 48, 69, 2, 33, 0, 230, 35, 194, 243, 21, 20, 170, 82, 78, 105, 160, 203, 195, 21,
            235, 116, 119, 85, 53, 121, 191, 165, 39, 129, 223, 111, 104, 226, 178, 187, 17, 145,
            2, 32, 26, 39, 69, 164, 121, 112, 246, 212, 165, 248, 213, 252, 19, 205, 200, 91, 37,
            118, 190, 44, 179, 225, 17, 229, 171, 148, 250, 222, 244, 56, 113, 22, 1, 33, 2, 156,
            229, 196, 14, 212, 79, 124, 75, 188, 23, 137, 106, 43, 34, 134, 138, 142, 196, 226,
            177, 203, 147, 187, 84, 39, 184, 70, 77, 54, 21, 35, 90, 255, 255, 255, 255, 1, 2, 48,
            0, 0, 0, 0, 0, 0, 25, 118, 169, 20, 179, 7, 107, 77, 162, 146, 141, 57, 58, 1, 215, 65,
            228, 231, 161, 76, 117, 95, 60, 151, 136, 172, 0, 0, 0, 0,
        ];

        let (expected_tx, _) = Transaction::deserialize(&expected_serialized).unwrap();
        // Assert one by one
        assert_eq!(tx.version, expected_tx.version, "Version mismatch");
        assert_eq!(
            tx.inputs.len(),
            expected_tx.inputs.len(),
            "Input count mismatch"
        );
        assert_eq!(
            tx.input_count, expected_tx.input_count,
            "Input count mismatch"
        );
        assert_eq!(
            tx.inputs[0].previous_output_tx_hash, expected_tx.inputs[0].previous_output_tx_hash,
            "Input tx hash mismatch"
        );
        assert_eq!(
            tx.inputs[0].previous_output_index, expected_tx.inputs[0].previous_output_index,
            "Input tx index mismatch"
        );
        assert_eq!(
            tx.inputs[0].script_length, expected_tx.inputs[0].script_length,
            "Input script length mismatch"
        );
        assert_eq!(
            tx.inputs[0].script_sig.len(),
            expected_tx.inputs[0].script_sig.len(),
            "Input script length mismatch"
        );
        assert_eq!(
            tx.inputs[0].script_sig, expected_tx.inputs[0].script_sig,
            "Input script mismatch"
        );
        assert_eq!(
            tx.inputs[0].sequence, expected_tx.inputs[0].sequence,
            "Input sequence mismatch"
        );
        assert_eq!(
            tx.outputs.len(),
            expected_tx.outputs.len(),
            "Output count mismatch"
        );
        assert_eq!(
            tx.output_count, expected_tx.output_count,
            "Output count mismatch"
        );
        assert_eq!(
            tx.outputs[0].value, expected_tx.outputs[0].value,
            "Output value mismatch"
        );
        assert_eq!(
            tx.outputs[0].script_length, expected_tx.outputs[0].script_length,
            "Output script length mismatch"
        );
        assert_eq!(
            tx.outputs[0].script, expected_tx.outputs[0].script,
            "Output script mismatch"
        );
        assert_eq!(tx.lock_time, expected_tx.lock_time, "Lock time mismatch");
    }
}
