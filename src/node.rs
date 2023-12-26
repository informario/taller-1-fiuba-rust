pub mod storage;
pub mod stream_handler;
use crate::config::Config;
use crate::controller::NodeMessages;
use crate::logger::{Loggable, Logger};
use crate::wallet::merkle;
use std::error::Error;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
pub mod p2pkh;
pub mod sync;
use crate::node::sync::Sync;
pub mod block_processing;
use crate::node::block_processing::BlockProcessing;
pub mod block_downloader;
use crate::node::block_downloader::BlockDownloader;
pub mod message;
use self::message::block::transaction::Transaction;
use self::message::block::Block;
use self::message::inv::InvVec;
use self::message::messages_handler::{receive_message_serialized, send_message};
use self::message::{block, Message};
use self::node_server::NodeServer;
use self::stream_handler::{StreamHandler, StreamHandlerTrait};
use self::tx_broadcaster::TxBroadcaster;
use self::utxo::UtxoSet;
pub mod peer_discoverer;
pub mod tx_broadcaster;
use self::peer_listener::{PeerListener, PeerListenerOutput};
pub mod node_server;
pub mod peer_listener;
pub mod utxo;
const BLOCK_DOWNLOADER_THREADS: usize = 8;

// Node posee streams a los demás peers
// para poder intercambiar mensajes
// y posee un block downloader
// que se encarga de descargar mensajes
// de los peers
pub struct Node {
    utxo_set: Arc<Mutex<utxo::UtxoSet>>,
    config: Config,
    logger: Arc<Mutex<Logger>>,
    node_controller_tx: Arc<Mutex<Sender<NodeMessages>>>,
    wallet_addresses: Arc<Mutex<Vec<String>>>,
    active_wallet_address: Arc<Mutex<String>>,
}

#[derive(Debug, Clone)]
pub struct IndexedHeaderList {
    headers: Vec<[u8; 32]>,
    index: usize,
}

#[derive(Debug)]
pub struct IndexedBlockList {
    blocks: Vec<Vec<u8>>,
    index: usize,
}

impl Node {
    /// Create a new node
    pub fn new(
        config: Config,
        logger: Arc<Mutex<Logger>>,
        node_controller_tx: Sender<NodeMessages>,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            utxo_set: Arc::new(Mutex::new(UtxoSet::new())),
            config,
            logger,
            node_controller_tx: Arc::new(Mutex::new(node_controller_tx)),
            wallet_addresses: Arc::new(Mutex::new(vec![])),
            active_wallet_address: Arc::new(Mutex::new("".to_string())),
        })
    }

    /// Run the node
    pub fn run(
        &mut self,
        controller_node_rx: Receiver<NodeMessages>,
    ) -> Result<(), Box<dyn Error>> {
        self.logger.info("Running node");

        // Delete headers.dat
        // if file_exists("data/headers.dat") {
        //     self.logger.info("Deleting headers.dat");
        //     std::fs::remove_file("data/headers.dat")?;
        // }
        // // Delete blocks.dat
        // if file_exists("data/blocks.dat") {
        //     self.logger.info("Deleting blocks.dat");
        //     std::fs::remove_file("data/blocks.dat")?;
        // }
        // // Delete block_offsets.dat
        // if file_exists("data/block_offsets.dat") {
        //     self.logger.info("Deleting block_offsets.dat");
        //     std::fs::remove_file("data/block_offsets.dat")?;
        // }

        // // Delete first_block_height_stored.dat
        // if file_exists("data/first_block_height_stored.dat") {
        //     self.logger.info("Deleting first_block_height_stored.dat");
        //     std::fs::remove_file("data/first_block_height_stored.dat")?;
        // }

        let mut stream_handler = Arc::new(Mutex::new(stream_handler::StreamHandler::new(
            self.config.clone(),
            self.logger.clone(),
        )?));

        // Tx broadcaster thread
        let (tx_broadcaster_tx, tx_broadcaster_rx): (Sender<Transaction>, Receiver<Transaction>) =
            channel();

        let tx_broadcaster_logger = self.logger.clone();
        let tx_broadcaster_handle = match TxBroadcaster::run(
            &mut stream_handler,
            tx_broadcaster_logger,
            tx_broadcaster_rx,
        ) {
            Ok(handle) => handle,
            Err(e) => {
                self.logger.error(&format!("Error: {}", e));
                return Err(*Box::new(e));
            }
        };
        let (node_peer_listener_tx, node_peer_listener_rx): (
            Sender<NodeMessages>,
            Receiver<NodeMessages>,
        ) = channel();
        let (node_node_server_tx, node_node_server_rx): (
            Sender<NodeMessages>,
            Receiver<NodeMessages>,
        ) = channel();
        let node_server_peer_listener_tx = node_peer_listener_tx.clone();
        // Initialize controller_node_rx thread
        let controller_node_rx_handle = match self.controller_node_rx_thread(
            controller_node_rx,
            tx_broadcaster_tx,
            node_peer_listener_tx,
            node_node_server_tx,
            &stream_handler,
        ) {
            Ok(handle) => handle,
            Err(e) => {
                self.logger.error(&format!("Error: {}", e));
                return Err(*Box::new(e));
            }
        };

        let (block_sender_tx, block_receiver_rx): (
            Sender<IndexedBlockList>,
            Receiver<IndexedBlockList>,
        ) = channel();
        let mut handles = vec![];

        let (error_sender_tx, error_receiver_rx): (
            Sender<Option<IndexedHeaderList>>,
            Receiver<Option<IndexedHeaderList>>,
        ) = channel();

        let mut header_tx_vec = Vec::<Sender<IndexedHeaderList>>::new();
        let mut header_rx_vec = Vec::<Receiver<IndexedHeaderList>>::new();
        for _ in 0..BLOCK_DOWNLOADER_THREADS {
            let (tx, rx) = channel();
            header_rx_vec.push(rx);
            header_tx_vec.push(tx);
        }
        // Sync Thread
        let mut stream_handler_clone = Arc::clone(&stream_handler);
        let node_controller_tx_clone = Arc::clone(&self.node_controller_tx);
        let logger_clone = Arc::clone(&self.logger);
        let config_clone = self.config.clone();
        let sync_thread_handle = match thread::Builder::new()
            .name("sync_thread".to_string())
            .spawn(move || {
                match Sync::run(
                    &node_controller_tx_clone,
                    &mut stream_handler_clone,
                    &header_tx_vec,
                    &error_receiver_rx,
                    logger_clone,
                    config_clone,
                ) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e),
                }
            }) {
            Ok(handle) => handle,
            Err(e) => return Err(Box::new(e)),
        };
        handles.push(sync_thread_handle);
        self.logger.debug("ARRANCAN LOS BLOCK DOWNLOADER THREADS");
        // Block Downloader threads
        for i in 0..BLOCK_DOWNLOADER_THREADS {
            let block_sender_thread_tx = block_sender_tx.clone();
            let error_sender_thread_tx = error_sender_tx.clone();
            let header_reciever_thread_rx = header_rx_vec.remove(0);
            let mut stream_handler_clone = Arc::clone(&stream_handler);
            let logger_clone = Arc::clone(&self.logger);
            let block_downloader_thread_handle = thread::Builder::new()
                .name(format!("block_downloader_{}", i))
                .spawn(move || {
                    match BlockDownloader::run(
                        &mut stream_handler_clone,
                        header_reciever_thread_rx,
                        error_sender_thread_tx,
                        block_sender_thread_tx,
                        logger_clone,
                    ) {
                        Ok(_) => Ok(()),
                        Err(e) => Err(e),
                    }
                })?;
            handles.push(block_downloader_thread_handle);
        }

        let (peer_listener_output_tx, peer_listener_output_rx): (
            Sender<PeerListenerOutput>,
            Receiver<PeerListenerOutput>,
        ) = channel();

        let utxo_set_clone = Arc::clone(&self.utxo_set);
        let logger_clone = Arc::clone(&self.logger);
        let active_wallet_address_clone = Arc::clone(&self.active_wallet_address);
        let node_controller_tx_clone = Arc::clone(&self.node_controller_tx);
        let wallet_addresses_clone = Arc::clone(&self.wallet_addresses);
        let block_processing_thread_handle = match thread::Builder::new()
            .name("processing_thread".to_string())
            .spawn(move || {
                BlockProcessing::run(
                    &block_receiver_rx,
                    utxo_set_clone,
                    logger_clone,
                    active_wallet_address_clone,
                    wallet_addresses_clone,
                    node_controller_tx_clone,
                    peer_listener_output_rx,
                )
            }) {
            Ok(handle) => handle,
            Err(e) => {
                self.logger.error(&format!("Error creando thread: {}", e));
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Error creando thread",
                )));
            }
        };

        drop(block_sender_tx);
        let mut contador = 1;
        for handle in handles {
            match handle.join() {
                Ok(_) => {}
                Err(e) => self
                    .logger
                    .error(&format!("Error en hilo {}: {:?}", contador, e)),
            }
            contador += 1;
        }

        let logger_clone = self.logger.clone();
        let config_clone = self.config.clone();
        let mut peer_listener_stream_handler_clone = Arc::clone(&stream_handler);
        let peer_listener_thread_handle = match thread::Builder::new()
            .name("peer_listener_main_thread".to_string())
            .spawn(move || {
                PeerListener::run(
                    &mut peer_listener_stream_handler_clone,
                    logger_clone,
                    config_clone,
                    node_peer_listener_rx,
                    peer_listener_output_tx,
                )
            }) {
            Ok(handle) => handle,
            Err(e) => {
                self.logger.error(&format!("Error creando thread: {}", e));
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Error creando thread",
                )));
            }
        };
        // Start server
        let logger_clone = self.logger.clone();
        let config_clone = self.config.clone();
        let node_server_thread_handle = match thread::Builder::new()
            .name("node_server_main_thread".to_string())
            .spawn(move || {
                NodeServer::run(
                    logger_clone,
                    node_server_peer_listener_tx,
                    node_node_server_rx,
                    config_clone,
                )
            }) {
            Ok(handle) => handle,
            Err(e) => {
                self.logger.error(&format!("Error creando thread: {}", e));
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Error creando thread",
                )));
            }
        };
        // Join tx_broadcaster_handle
        match tx_broadcaster_handle.join() {
            Ok(_) => {}
            Err(e) => self
                .logger
                .error(&format!("Error en hilo de tx_broadcaster: {:?}", e)),
        }

        // Join block_processing_thread_handle
        match block_processing_thread_handle.join() {
            Ok(_) => {}
            Err(e) => self.logger.error(&format!(
                "Error en hilo de procesamiento de bloques: {:?}",
                e
            )),
        }
        // Join peer_listener_thread_handle
        match peer_listener_thread_handle.join() {
            Ok(_) => {}
            Err(e) => self
                .logger
                .error(&format!("Error en hilo de peer listener: {:?}", e)),
        }
        // Join node_server_thread_handle
        match node_server_thread_handle.join() {
            Ok(_) => {}
            Err(e) => self
                .logger
                .error(&format!("Error en hilo de node server: {:?}", e)),
        }

        // Join controller_node_rx_handle
        match controller_node_rx_handle.join() {
            Ok(_) => {}
            Err(e) => self
                .logger
                .error(&format!("Error en hilo de controller_node_rx: {:?}", e)),
        }
        self.logger.debug("TERMINA HILO MAIN EN NODE.RS");
        Ok(())
    }

    fn controller_node_rx_thread(
        &mut self,
        controller_node_rx: Receiver<NodeMessages>,
        tx_broadcaster_tx: Sender<Transaction>,
        node_peer_listener_tx: Sender<NodeMessages>,
        node_node_server_tx: Sender<NodeMessages>,
        stream_handle: &Arc<Mutex<StreamHandler>>,
    ) -> Result<JoinHandle<()>, Box<dyn Error>> {
        let utxo_set = Arc::clone(&self.utxo_set);
        let logger = Arc::clone(&self.logger);
        let node_controller_tx = self.node_controller_tx.clone();
        let mut stream_handle_clone = stream_handle.clone();
        let wallet_addresses = Arc::clone(&self.wallet_addresses);
        let active_wallet_address = Arc::clone(&self.active_wallet_address);
        match thread::Builder::new()
            .name("controller_interfaz_receiver_thread".to_string())
            .spawn(move || {
                for message in controller_node_rx.iter() {
                    match message {
                        NodeMessages::WalletAddresses(addresses) => {
                            logger.debug(&format!("WalletAddresses: {:?}", addresses));
                            match wallet_addresses.lock() {
                                Ok(mut wallet_addresses) => {
                                    *wallet_addresses = addresses;
                                }
                                Err(e) => {
                                    logger.error(&format!(
                                        "Error obteniendo lock de wallet_addresses: {}",
                                        e
                                    ));
                                }
                            }
                        }
                        NodeMessages::ActiveWalletAddress(address) => {
                            logger.debug(&format!("ActiveWalletAddress: {}", address));
                            match active_wallet_address.lock() {
                                Ok(mut active_wallet_address) => {
                                    *active_wallet_address = address.clone();
                                }
                                Err(e) => {
                                    logger.error(&format!(
                                        "Error obteniendo lock de active_wallet_address: {}",
                                        e
                                    ));
                                }
                            }

                            let mut utxo_set = match utxo_set.lock() {
                                Ok(utxo_set) => utxo_set,
                                Err(e) => {
                                    logger.error(&format!("Error: {}", e));
                                    continue;
                                }
                            };

                            let balance = match utxo_set.get_address_balance(&address) {
                                Ok(balance) => balance,
                                Err(e) => {
                                    logger.error(&format!("Error: {}", e));
                                    continue;
                                }
                            };
                            logger.debug(&format!("Balance: {:?}", balance));
                            match node_controller_tx.lock() {
                                Ok(node_controller_tx) => {
                                    match node_controller_tx
                                        .send(NodeMessages::AccountBalance(balance))
                                    {
                                        Ok(_) => {}
                                        Err(e) => {
                                            logger.error(&format!(
                                                "Error enviando mensaje a controller: {}",
                                                e
                                            ));
                                        }
                                    }
                                }
                                Err(e) => {
                                    logger.error(&format!(
                                        "Error obteniendo lock de node_controller_tx: {}",
                                        e
                                    ));
                                }
                            }
                        }
                        NodeMessages::SendTransaction(tx) => {
                            logger.debug(&format!("SendTransaction: {:?}", tx));
                            match tx_broadcaster_tx.send(tx) {
                                Ok(_) => {}
                                Err(e) => {
                                    logger.error(&format!("Error: {}", e));
                                }
                            }
                        }
                        NodeMessages::EndConnection() => {
                            match node_peer_listener_tx.send(NodeMessages::EndConnection()) {
                                Ok(_) => {}
                                Err(e) => {
                                    logger.error(&format!(
                                        "Error enviando mensaje a peer_listener: {}",
                                        e
                                    ));
                                }
                            };
                            match node_node_server_tx.send(NodeMessages::EndConnection()) {
                                Ok(_) => {}
                                Err(e) => {
                                    logger.error(&format!(
                                        "Error enviando mensaje a node_server: {}",
                                        e
                                    ));
                                }
                            };
                        }
                        NodeMessages::GetMerkleTree(txid_and_block) => {
                            /////Parsear String/////
                            if txid_and_block.len() != 128 {
                                logger.error("Error, longitud incorrecta en tx o block");
                                match node_controller_tx
                                    .lock()
                                    .unwrap()
                                    .send(NodeMessages::TxNotFound())
                                {
                                    Ok(_) => {}
                                    Err(e) => {
                                        logger.error(&format!("Error: {}", e));
                                    }
                                };
                            } else {
                                let txidstr = &txid_and_block.as_str()[0..64];
                                let blockstr = &txid_and_block.as_str()[64..128];
                                let mut txid: [u8; 32] = [0; 32];
                                let mut block: [u8; 32] = [0; 32];
                                match parse_string(&mut txid, txidstr, &mut block, blockstr) {
                                    Ok(_) => {
                                        txid.reverse();
                                        block.reverse();
                                        match download_block_and_send_tree(
                                            &mut txid,
                                            &mut block,
                                            &mut stream_handle_clone,
                                            &node_controller_tx,
                                            &logger,
                                        ) {
                                            Ok(_) => {}
                                            Err(e) => {
                                                logger.error(&format!("Error: {}", e));
                                            }
                                        };
                                    }
                                    Err(_) => {
                                        match node_controller_tx
                                            .lock()
                                            .unwrap()
                                            .send(NodeMessages::TxNotFound())
                                        {
                                            Ok(_) => {}
                                            Err(e) => {
                                                logger.error(&format!("Error: {}", e));
                                            }
                                        };
                                    }
                                };
                            }
                        }
                        _ => {}
                    }
                }
            }) {
            Ok(handle) => Ok(handle),
            Err(e) => {
                self.logger.error(&format!("Error: {}", e));
                Err(Box::new(e))
            }
        }
    }
}

fn parse_string(
    txid: &mut [u8; 32],
    txidstr: &str,
    block: &mut [u8; 32],
    blockstr: &str,
) -> Result<(), Box<dyn Error>> {
    for i in (0..txidstr.len()).step_by(2) {
        match u8::from_str_radix(&txidstr[i..i + 2], 16) {
            Ok(s) => txid[i / 2] = s,
            Err(e) => return Err(Box::new(e)),
        };
    }
    for i in (0..blockstr.len()).step_by(2) {
        match u8::from_str_radix(&blockstr[i..i + 2], 16) {
            Ok(s) => block[i / 2] = s,
            Err(e) => return Err(Box::new(e)),
        }
    }
    Ok(())
}

fn download_block_and_send_tree(
    txid: &mut [u8; 32],
    block: &mut [u8; 32],
    stream_handle: &mut Arc<Mutex<StreamHandler>>,
    node_controller_tx: &Arc<Mutex<Sender<NodeMessages>>>,
    logger: &Arc<Mutex<Logger>>,
) -> Result<(), Box<dyn Error>> {
    //////Obtener bloque asi puedo tener la tx//////
    let stream = stream_handle.request_stream()?;
    let inv_vec_block: Vec<InvVec> = vec![InvVec::new(message::inv::InvType::Block, *block)];
    let getdata_block_message = Message::new_get_data_message(inv_vec_block)?;
    match send_message(getdata_block_message, &stream) {
        Ok(_) => {}
        Err(e) => {
            logger.error(&format!("Error: {}", e));
        }
    }
    let serialized_block = receive_message_serialized(block::COMMAND, &stream)?;
    let block = Block::deserialize(&serialized_block[24..])?;
    let merkle_root = block.get_block_header().get_merkle_root_hash();
    //////Encontrar mi tx correspondiente///////
    let mut transaction = None;
    let mut x = 0;
    let transactions_vec = block.get_transactions();
    for t in transactions_vec {
        let transaction_id = t.get_transaction_id()?;
        if transaction_id == *txid {
            transaction = Some(t);
            break;
        }
        x += 1;
    }
    if transaction.is_none() {
        match node_controller_tx
            .lock()
            .unwrap()
            .send(NodeMessages::TxNotFound())
        {
            Ok(_) => {}
            Err(e) => {
                logger.error(&format!("Error: {}", e));
            }
        };
    }
    if transaction.is_some() {
        let tree = merkle::create_partial_merkle_tree(transactions_vec, x, merkle_root);
        match node_controller_tx
            .lock()
            .unwrap()
            .send(NodeMessages::MerkleTree(tree))
        {
            Ok(_) => {}
            Err(e) => {
                logger.error(&format!("Error: {}", e));
            }
        };
    };
    Ok(())
}
