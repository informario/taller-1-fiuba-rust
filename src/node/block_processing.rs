use std::{
    collections::HashMap,
    error::Error,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Mutex,
    },
};

use crate::{
    controller::NodeMessages,
    file_utils::{self, file_exists},
    logger::Loggable,
    node::p2pkh::{decode_bitcoin_address, parse_p2pkh_tx_output},
    node::utxo::UtxoSet,
    node::BLOCK_DOWNLOADER_THREADS,
};

use super::{
    message::{
        self,
        block::{self, transaction::Transaction},
    },
    peer_listener::PeerListenerOutput,
    utxo::TxidVout,
    IndexedBlockList,
};

pub struct BlockProcessing;
impl BlockProcessing {
    pub fn run(
        intial_block_download_rx: &Receiver<IndexedBlockList>,
        utxo_set: Arc<Mutex<UtxoSet>>,
        logger: Arc<Mutex<super::Logger>>,
        active_wallet_address: Arc<Mutex<String>>,
        wallet_addresses: Arc<Mutex<Vec<String>>>,
        node_controller_tx: Arc<Mutex<std::sync::mpsc::Sender<super::NodeMessages>>>,
        peer_listener_output_rx: std::sync::mpsc::Receiver<super::PeerListenerOutput>,
    ) -> Result<(), std::io::Error> {
        logger.debug("Starting Processing Thread");

        // Initial block download
        let mut concatenated_block_list: Vec<Option<Vec<Vec<u8>>>> =
            vec![None; BLOCK_DOWNLOADER_THREADS];
        let mut counter = 0;
        for indexed_block_list in intial_block_download_rx.iter() {
            match node_controller_tx.lock(){
                Ok(node_controller_tx) => {
                    match node_controller_tx.send(NodeMessages::BlocksDownloaded(indexed_block_list.blocks.len())){
                        Ok(_) => {}
                        Err(e) => logger.error(&format!("Error: {:?}", e)),
                    };
                },
                Err(e) => {
                    let err_msg = format!("Error getting controller lock {}", e);
                    logger.error(&err_msg);
                }
            };
            concatenated_block_list[indexed_block_list.index] = Some(indexed_block_list.blocks);
            counter += 1;
            if counter == BLOCK_DOWNLOADER_THREADS {
                for block_list in concatenated_block_list.iter() {
                    if block_list.is_none() {
                        let err_msg = "Error en el processing thread: Blocks is none".to_string();
                        logger.error(&err_msg);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            err_msg,
                        ));
                    }
                    let blocks_list_ref = match block_list.as_ref() {
                        Some(blocks_list_ref) => blocks_list_ref,
                        None => {
                            let err_msg =
                                "Error en el processing thread: Blocks as ref".to_string();
                            logger.error(&err_msg);
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                err_msg,
                            ));
                        }
                    };
                    for block in blocks_list_ref {
                        proccess_block(
                            block,
                            &logger,
                            &node_controller_tx,
                            &utxo_set,
                            &active_wallet_address,
                        )?;
                    }
                }

                counter = 0;
                concatenated_block_list = vec![None; BLOCK_DOWNLOADER_THREADS];
            }
        }
        // Post initial block download
        let mut txs_interested_in: HashMap<[u8; 32], Transaction> = HashMap::new();
        for output in peer_listener_output_rx {
            match output {
                PeerListenerOutput::Block(block) => {
                    logger.debug("Nuevo bloque recibido");
                    let serialized_block = match block.serialize() {
                        Ok(serialized_block) => serialized_block,
                        Err(e) => {
                            let err_msg = format!("Error serializando bloque: {}", e);
                            logger.error(&err_msg);
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                err_msg,
                            ));
                        }
                    };

                    proccess_block(
                        &serialized_block,
                        &logger,
                        &node_controller_tx,
                        &utxo_set,
                        &active_wallet_address,
                    )?;
                    let block_transactions = block.get_transactions();
                    for transaction in block_transactions {
                        let transaction_hash = match transaction.get_transaction_id() {
                            Ok(transaction_hash) => transaction_hash,
                            Err(e) => {
                                let err_msg =
                                    format!("Error obteniendo hash de transacción: {}", e);
                                logger.error(&err_msg);
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    err_msg,
                                ));
                            }
                        };
                        if txs_interested_in.contains_key(&transaction_hash) {
                            match node_controller_tx.lock() {
                                Ok(node_controller_tx) => {
                                    match node_controller_tx.send(
                                        super::NodeMessages::NewTransactionConfirmed(
                                            transaction.clone(),
                                        ),
                                    ) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            let err_msg = format!("Error enviando nueva transaccion a node controller: {}",e);
                                            logger.error(&err_msg);
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::InvalidData,
                                                err_msg,
                                            ));
                                        }
                                    };
                                }
                                Err(e) => {
                                    let err_msg = format!(
                                        "Error obteniendo lock de node controller tx: {}",
                                        e
                                    );
                                    logger.error(&err_msg);
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        err_msg,
                                    ));
                                }
                            };
                        }
                    }
                }
                PeerListenerOutput::Transaction(transaction) => {
                    let locked_wallet_addresses = match wallet_addresses.lock() {
                        Ok(wallet_addresses) => wallet_addresses.clone(),
                        Err(e) => {
                            let err_msg =
                                format!("Error obteniendo lock de wallet addresses: {}", e);
                            logger.error(&err_msg);
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                err_msg,
                            ));
                        }
                    };
                    let locked_utxo_set = match utxo_set.lock() {
                        Ok(utxo_set) => utxo_set,
                        Err(e) => {
                            let err_msg = format!("Error obteniendo lock de UTXO set: {}", e);
                            logger.error(&err_msg);
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                err_msg,
                            ));
                        }
                    };
                    for address in &locked_wallet_addresses {
                        match tx_involves_wallet_address(&transaction, &locked_utxo_set, address) {
                            Ok(involves) => {
                                if involves {
                                    let tx_id = match transaction.get_transaction_id() {
                                        Ok(tx_id) => tx_id,
                                        Err(e) => {
                                            let err_msg = format!(
                                                "Error obteniendo ID de transacción: {}",
                                                e
                                            );
                                            logger.error(&err_msg);
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::InvalidData,
                                                err_msg,
                                            ));
                                        }
                                    };
                                    if txs_interested_in.contains_key(&tx_id) {
                                        continue;
                                    }
                                    txs_interested_in.insert(tx_id, transaction.clone());
                                    logger.debug(&format!(
                                        "New transaction interested in: {:?}",
                                        transaction
                                    ));

                                    // mandar a interfaz esta transaccion
                                    match node_controller_tx.lock() {
                                        Ok(node_controller_tx) => {
                                            match node_controller_tx.send(
                                                super::NodeMessages::NewTransactionArrived(
                                                    transaction.clone(),
                                                ),
                                            ) {
                                                Ok(_) => {}
                                                Err(e) => {
                                                    let err_msg = format!("Error enviando nueva transaccion a node controller: {}",e);
                                                    logger.error(&err_msg);
                                                    return Err(std::io::Error::new(
                                                        std::io::ErrorKind::InvalidData,
                                                        err_msg,
                                                    ));
                                                }
                                            };
                                        }
                                        Err(e) => {
                                            let err_msg = format!(
                                                "Error obteniendo lock de node controller tx: {}",
                                                e
                                            );
                                            logger.error(&err_msg);
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::InvalidData,
                                                err_msg,
                                            ));
                                        }
                                    };
                                }
                            }
                            Err(e) => {
                                let err_msg = format!(
                                    "Error chequeando si transacción involucra dirección de wallet: {}",
                                    e
                                );
                                logger.error(&err_msg);
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    err_msg,
                                ));
                            }
                        };
                    }
                }
            }
        }

        Ok(())
    }
}

fn proccess_block(
    block: &[u8],
    logger: &Arc<Mutex<super::Logger>>,
    node_controller_tx: &Arc<Mutex<Sender<NodeMessages>>>,
    utxo_set: &Arc<Mutex<UtxoSet>>,
    active_wallet_address: &Arc<Mutex<String>>,
) -> Result<(), std::io::Error> {
    // Validar merkle root
    match block::Block::validate_poi(block) {
        Ok(_) => {}
        Err(_) => {
            let err_msg = "Error: proof of inclusion invalido".to_string();
            logger.error(&err_msg);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err_msg,
            ));
        }
    };
    let deserialized_block = match message::block::Block::deserialize(block) {
        Ok(deserialized_block) => deserialized_block,
        Err(e) => {
            let err_msg = format!("Error deserializando bloque: {}", e);
            logger.error(&err_msg);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err_msg,
            ));
        }
    };
    let mut locked_utxo_set = match utxo_set.lock() {
        Ok(locked_utxo_set) => locked_utxo_set,
        Err(e) => {
            let err_msg = format!("Error obteniendo lock de UTXO set: {}", e);
            logger.error(&err_msg);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err_msg,
            ));
        }
    };
    let active_wallet_address = match active_wallet_address.lock() {
        Ok(active_wallet_address) => active_wallet_address,
        Err(e) => {
            let err_msg = format!("Error obteniendo lock de active wallet address: {}", e);
            logger.error(&err_msg);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err_msg,
            ));
        }
    };

    let mut active_wallet_balance: u64 = 0;

    if active_wallet_address.to_string() != *"" {
        match locked_utxo_set.get_address_balance(&active_wallet_address.to_string()) {
            Ok(balance) => active_wallet_balance = balance,
            Err(e) => {
                let err_msg = format!("Error obteniendo balance de active wallet address: {}", e);
                logger.error(&err_msg);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    err_msg,
                ));
            }
        };
    }
    match locked_utxo_set.update(&deserialized_block) {
        Ok(_) => {}
        Err(e) => {
            let err_msg = format!("Error actualizando UTXO set: {}", e);
            logger.error(&err_msg);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err_msg,
            ));
        }
    };
    if active_wallet_address.to_string() != *"" {
        match locked_utxo_set.get_address_balance(&active_wallet_address.to_string()) {
            Ok(new_active_wallet_balance) => {
                if active_wallet_balance != new_active_wallet_balance {
                    logger.debug(&format!(
                        "Nuevo balance de active wallet address: {}",
                        new_active_wallet_balance
                    ));
                    match node_controller_tx.lock() {
                        Ok(node_controller_tx) => {
                            match node_controller_tx.send(super::NodeMessages::AccountBalance(
                                new_active_wallet_balance,
                            )) {
                                Ok(_) => {}
                                Err(e) => {
                                    let err_msg =
                                        format!("Error enviando mensaje a node controller: {}", e);
                                    logger.error(&err_msg);
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        err_msg,
                                    ));
                                }
                            };
                        }
                        Err(e) => {
                            let err_msg =
                                format!("Error obteniendo lock de node controller tx: {}", e);
                            logger.error(&err_msg);
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                err_msg,
                            ));
                        }
                    };
                }
            }
            Err(e) => {
                let err_msg = format!("Error obteniendo balance de active wallet address: {}", e);
                logger.error(&err_msg);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    err_msg,
                ));
            }
        };
    }
    let mut current_offset = 0;
    if file_exists("data/block_offsets.dat") {
        current_offset = match file_utils::read_last_bytes("data/block_offsets.dat", 8) {
            Ok(current_offset) => {
                let mut bytes: [u8; 8] = [0; 8];
                bytes.copy_from_slice(&current_offset);
                u64::from_be_bytes(bytes)
            }
            Err(e) => {
                let err_msg = format!("Error leyendo ultimo offset: {}", e);
                logger.error(&err_msg);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    err_msg,
                ));
            }
        };
    } else {
        file_utils::append_to_file_binary("data/block_offsets.dat", &[0; 8])?;
    }
    let block_size = block.len() as u64;
    let new_offset = current_offset + block_size;
    let new_offset_bytes = new_offset.to_be_bytes();
    file_utils::append_to_file_binary("data/block_offsets.dat", &new_offset_bytes)?;
    file_utils::append_to_file_binary("data/blocks.dat", block)?;

    Ok(())
}

fn tx_involves_wallet_address(
    transaction: &Transaction,
    utxo_set: &UtxoSet,
    address: &str,
) -> Result<bool, Box<dyn Error>> {
    for tx_in in &transaction.inputs {
        let txid_vout = TxidVout {
            txid: tx_in.previous_output_tx_hash,
            vout: tx_in.previous_output_index,
        };
        if utxo_set.txid_vout_is_from_address(txid_vout, address) {
            return Ok(true);
        }
    }
    let address_script_pubkey_hash = decode_bitcoin_address(address)?;

    for tx_out in &transaction.outputs {
        if let Some(script_pubkey_hash) = parse_p2pkh_tx_output(&tx_out.script) {
            if script_pubkey_hash == address_script_pubkey_hash {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
