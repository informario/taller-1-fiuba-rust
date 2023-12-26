use std::{
    net::TcpStream,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use crate::{
    interfaz::send_stack,
    logger::{Loggable, Logger},
    node::message::block::{transaction::Transaction, Block},
    wallet::merkle::PartialMerkleTree,
};
pub enum Message {
    UpdateActiveAccountBalance(String),
    SendTransaction(send_stack::TransactionInterfaceEntry),
    NewTransaction(String),
    ConfirmTransaction(String),
    AddAccount(String),
    GetBalance(String),
    UpdateAccountList(Vec<String>),
    AccountSelected(String),
    CheckPoi(String),
    PoiResult(bool),
    TxNotFound(),
    HeadersDownloaded(usize),
    BlocksDownloaded(usize),
}
pub enum InterfaceMessage {
    UpdateOverview(Message),
    UpdateTransactions(Message),
    UpdateCheckPoi(Message),
    Error(Message),
    UpdateAccountSelector(Message),
}

pub enum WalletMessages {
    GetAccountList(),
    ActiveAccount(String),
    AccountNamesList(Vec<String>),
    AddressesList(Vec<String>),
    AddAccount(String),
    CreateTransaction(send_stack::TransactionInterfaceEntry),
    TransactionCreated(Transaction),
    ChangeActiveAccount(String),
    GetProofOfInclusion(PartialMerkleTree),
    ProofOfInclusionResult(bool),
}

pub enum NodeMessages {
    AccountBalance(u64),
    EndConnection(),
    WalletAddresses(Vec<String>),
    ActiveWalletAddress(String),
    SendTransaction(Transaction),
    NewTransactionArrived(Transaction), // Transaction hash
    NewTransactionConfirmed(Transaction),
    NewBlockArrived(Block),
    GetMerkleTree(String),
    MerkleTree(PartialMerkleTree),
    TxNotFound(),
    NewPeer(TcpStream),
    HeadersDownloaded(usize),
    BlocksDownloaded(usize)
}

pub struct Controller {
    logger: Arc<Mutex<Logger>>,
    pub interfaz_sender: gtk::glib::Sender<InterfaceMessage>,
    pub interfaz_receiver: Option<std::sync::mpsc::Receiver<Message>>,
    pub node_sender: std::sync::mpsc::Sender<NodeMessages>,
    pub node_receiver: Option<std::sync::mpsc::Receiver<NodeMessages>>,
    pub wallet_sender: std::sync::mpsc::Sender<WalletMessages>,
    pub wallet_receiver: Option<std::sync::mpsc::Receiver<WalletMessages>>,
    pub downloaded_blocks:Arc<Mutex<usize>>,
}

impl Controller {
    pub fn new(
        logger: Arc<Mutex<Logger>>,
        interfaz_sender: gtk::glib::Sender<InterfaceMessage>,
        interfaz_receiver: Option<std::sync::mpsc::Receiver<Message>>,
        node_sender: std::sync::mpsc::Sender<NodeMessages>,
        node_receiver: Option<std::sync::mpsc::Receiver<NodeMessages>>,
        wallet_sender: std::sync::mpsc::Sender<WalletMessages>,
        wallet_receiver: Option<std::sync::mpsc::Receiver<WalletMessages>>,

    ) -> Self {
        Self {
            logger,
            interfaz_sender,
            interfaz_receiver,
            node_sender,
            node_receiver,
            wallet_sender,
            wallet_receiver,
            downloaded_blocks:Arc::new(Mutex::new(0)),
        }
    }

    pub fn start(&mut self) -> Result<(), std::io::Error> {
        match self.wallet_sender.send(WalletMessages::GetAccountList()) {
            Ok(_) => {}
            Err(e) => self.logger.error(&format!("Error: {:?}", e)),
        };
        let mut handles = vec![];

        let interfaz_receiver = match self.interfaz_receiver.take() {
            Some(receiver) => receiver,
            None => {
                self.logger.error("Error: interfaz_receiver is None");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "interfaz_receiver is None",
                ));
            }
        };

        //let wallet_sender_clone = std::mem::replace(&mut self.wallet_sender, None).unwrap();
        let wallet_sender_clone = self.wallet_sender.clone();
        // let node_sender_clone = self.node_sender.clone();

        let interfaz_reciever_thread_logger = self.logger.clone();
        let node_sender_clone = self.node_sender.clone();
        let interfaz_receiver_thread_handle = match thread::Builder::new()
            .name("controller_interfaz_receiver_thread".to_string())
            .spawn(move || {
                for message in interfaz_receiver.iter() {
                    match message {
                        Message::SendTransaction(tx_entry) => {
                            interfaz_reciever_thread_logger
                                .debug(&format!("SendTransaction: {:?}", tx_entry));
                            match wallet_sender_clone
                                .send(WalletMessages::CreateTransaction(tx_entry))
                            {
                                Ok(_) => {}
                                Err(e) => interfaz_reciever_thread_logger
                                    .error(&format!("Error: {:?}", e)),
                            }
                        }
                        Message::AddAccount(text) => {
                            interfaz_reciever_thread_logger.debug(&format!("AddAccount: {}", text));
                            match wallet_sender_clone.send(WalletMessages::AddAccount(text)) {
                                Ok(_) => {}
                                Err(e) => interfaz_reciever_thread_logger
                                    .error(&format!("Error: {:?}", e)),
                            }
                        }
                        Message::AccountSelected(text) => {
                            interfaz_reciever_thread_logger
                                .debug(&format!("AccountSelected: {}", text));
                            match wallet_sender_clone
                                .send(WalletMessages::ChangeActiveAccount(text))
                            {
                                Ok(_) => {}
                                Err(e) => interfaz_reciever_thread_logger
                                    .error(&format!("Error: {:?}", e)),
                            }
                        }
                        Message::CheckPoi(string) => {
                            interfaz_reciever_thread_logger.debug(&format!("CheckPoi: {}", string));
                            match node_sender_clone.send(NodeMessages::GetMerkleTree(string)) {
                                Ok(_) => {}
                                Err(e) => interfaz_reciever_thread_logger
                                    .error(&format!("Error: {:?}", e)),
                            };
                        }

                        _ => {}
                    }
                }
            }) {
            Ok(handle) => handle,
            Err(e) => {
                self.logger.error(&format!("Error: {:?}", e));
                return Err(*Box::new(e));
            }
        };
        match self.wallet_communication_thread() {
            Ok(handle) => {
                handles.push(handle);
            }
            Err(e) => {
                return Err(*Box::new(e));
            }
        }
        handles.push(interfaz_receiver_thread_handle);

        match self.node_communication_thread() {
            Ok(handle) => {
                handles.push(handle);
            }
            Err(e) => return Err(*Box::new(e)),
        }
        for handle in handles {
            match handle.join() {
                Ok(_) => {}
                Err(e) => self.logger.error(&format!("Error en hilo: {:?}", e)),
            }
        }

        self.logger.debug("TERMINA HILO CONTROLLER.RS");
        Ok(())
    }

    fn wallet_communication_thread(&mut self) -> Result<JoinHandle<()>, std::io::Error> {
        let wallet_receiver = match self.wallet_receiver.take() {
            Some(receiver) => receiver,
            None => {
                return Err(*Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Wallet receiver not initialized",
                )))
            }
        };
        let interfaz_sender_clone = self.interfaz_sender.clone();
        let wallet_reciever_logger = self.logger.clone();
        let node_sender_clone = self.node_sender.clone();
        match thread::Builder::new()
            .name("wallet_reciever_thread".to_string())
            .spawn(move || {
                for message in wallet_receiver.iter() {
                    match message {
                        WalletMessages::AccountNamesList(account_name_list) => {
                            wallet_reciever_logger
                                .debug(&format!("AccountNamesList: {:?}", account_name_list));
                            let _ = interfaz_sender_clone.send(
                                InterfaceMessage::UpdateAccountSelector(
                                    Message::UpdateAccountList(account_name_list),
                                ),
                            );
                        }
                        WalletMessages::AddressesList(addresses_list) => {
                            wallet_reciever_logger
                                .debug(&format!("AddressesList: {:?}", addresses_list));
                            let _ = node_sender_clone
                                .send(NodeMessages::WalletAddresses(addresses_list));
                        }
                        WalletMessages::ActiveAccount(active_account) => {
                            wallet_reciever_logger
                                .debug(&format!("ActiveAccount: {:?}", active_account));
                            let _ = node_sender_clone
                                .send(NodeMessages::ActiveWalletAddress(active_account));
                        }
                        WalletMessages::TransactionCreated(tx) => {
                            wallet_reciever_logger.debug(&format!("TransactionCreated: {:?}", tx));
                            match node_sender_clone.send(NodeMessages::SendTransaction(tx)) {
                                Ok(_) => {}
                                Err(e) => wallet_reciever_logger.error(&format!("Error: {:?}", e)),
                            }
                        }
                        WalletMessages::ProofOfInclusionResult(result) => {
                            match interfaz_sender_clone
                                .send(InterfaceMessage::UpdateCheckPoi(Message::PoiResult(result)))
                            {
                                Ok(_) => {}
                                Err(e) => wallet_reciever_logger.error(&format!("Error: {:?}", e)),
                            }
                        }
                        _ => {}
                    }
                }
            }) {
            Ok(handle) => Ok(handle),
            Err(e) => Err(*Box::new(e)),
        }
    }

    fn node_communication_thread(&mut self) -> Result<JoinHandle<()>, std::io::Error> {
        let node_receiver = match self.node_receiver.take() {
            Some(receiver) => receiver,
            None => {
                return Err(*Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Node receiver not initialized",
                )))
            }
        };
        // let interfaz_sender_clone = self.interfaz_sender.clone();
        let node_reciever_logger = self.logger.clone();
        let interfaz_sender_clone = self.interfaz_sender.clone();
        let wallet_sender_clone = self.wallet_sender.clone();
        let downloaded_blocks_clone = self.downloaded_blocks.clone();
        /*let wallet_sender_clone = match self.walle {
            Some(sender) => sender,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Wallet sender not initialized",
                ))
            }
        };*/
        match thread::Builder::new()
            .name("node_reciever_thread".to_string())
            .spawn(move || {
                for message in node_receiver.iter() {
                    match message {
                        NodeMessages::AccountBalance(account_balance) => {
                            node_reciever_logger
                                .debug(&format!("AccountBalance: {:?}", account_balance));
                            let _ = interfaz_sender_clone.send(InterfaceMessage::UpdateOverview(
                                Message::UpdateActiveAccountBalance(account_balance.to_string()),
                            ));
                        }
                        NodeMessages::HeadersDownloaded(amount) => {
                            let _ = interfaz_sender_clone.send(InterfaceMessage::UpdateOverview(
                                Message::HeadersDownloaded(amount),
                            ));
                        }
                        NodeMessages::BlocksDownloaded(amount) => {
                            let mut downloaded_blocks = downloaded_blocks_clone.lock().unwrap();
                            *downloaded_blocks += amount;
                            let _ = interfaz_sender_clone.send(InterfaceMessage::UpdateOverview(
                                Message::BlocksDownloaded(*downloaded_blocks),
                            ));
                        }
                        NodeMessages::MerkleTree(tree) => {
                            match wallet_sender_clone
                                .send(WalletMessages::GetProofOfInclusion(tree))
                            {
                                Ok(_) => {}
                                Err(_e) => {}
                            };
                        }
                        NodeMessages::TxNotFound() => {
                            match interfaz_sender_clone
                                .send(InterfaceMessage::Error(Message::TxNotFound()))
                            {
                                Ok(_) => {}
                                Err(_e) => {}
                            };
                        }
                        NodeMessages::NewTransactionArrived(tx) => {
                            let transaction_id = match tx.get_transaction_id() {
                                Ok(id) => id,
                                Err(e) => {
                                    node_reciever_logger.error(&format!("Error: {:?}", e));
                                    continue;
                                }
                            };
                            let time = chrono::offset::Utc::now();
                            let mut balance: f64 = 0.0;
                            for output in tx.outputs {
                                balance += (output.value as f64) / 100000000_f64;
                            }
                            let mut transaction_string: String = "".to_string();
                            let transacion_id_reversed = transaction_id.iter().rev();
                            for byte in transacion_id_reversed {
                                transaction_string.push_str(&format!("{:02x}", byte));
                            }
                            let _ = interfaz_sender_clone.send(
                                InterfaceMessage::UpdateTransactions(Message::NewTransaction(
                                    time.to_string()
                                        + ", Unconfirmed, "
                                        + &transaction_string
                                        + ", "
                                        + &balance.to_string(),
                                )),
                            );
                        }
                        NodeMessages::NewTransactionConfirmed(transaction) => {
                            let transaction_id = match transaction.get_transaction_id() {
                                Ok(id) => id,
                                Err(e) => {
                                    node_reciever_logger.error(&format!("Error: {:?}", e));
                                    continue;
                                }
                            };
                            let mut transaction_string: String = "".to_string();
                            let transacion_id_reversed = transaction_id.iter().rev();
                            for byte in transacion_id_reversed {
                                transaction_string.push_str(&format!("{:02x}", byte));
                            }
                            let time = chrono::offset::Utc::now();
                            let mut balance: f64 = 0.0;
                            for output in transaction.outputs {
                                balance += (output.value as f64) / 100000000_f64;
                            }
                            match interfaz_sender_clone.send(InterfaceMessage::UpdateTransactions(
                                Message::ConfirmTransaction(
                                    time.to_string()
                                        + ", Confirmed, "
                                        + &transaction_string
                                        + ", "
                                        + &balance.to_string(),
                                ),
                            )) {
                                Ok(_) => {}
                                Err(e) => node_reciever_logger.error(&format!("Error: {:?}", e)),
                            }
                        }
                        _ => {}
                    }
                }
            }) {
            Ok(handle) => Ok(handle),
            Err(e) => Err(*Box::new(e)),
        }
    }
}
