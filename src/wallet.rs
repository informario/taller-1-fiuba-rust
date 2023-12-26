use std::sync::{Arc, Mutex};

use crate::config::Config;
use crate::controller::WalletMessages;
use crate::file_utils::{read_file_utf8, write_file_utf8};
pub mod merkle;
use crate::logger::{Loggable, Logger};
use crate::node::p2pkh::create_p2pkh_transaction;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Account {
    pub private_key: String,
    pub address: String,
    pub name: String,
}

pub struct Wallet {
    config: Config,
    accounts: Vec<Account>,
    active_account: Option<Account>,
    logger: Arc<Mutex<Logger>>,
}

impl Wallet {
    /// Create a new Wallet
    ///
    /// # Arguments
    ///
    /// * `config` - Config
    ///
    /// ```
    pub fn new(config: Config, logger: Arc<Mutex<Logger>>) -> Result<Wallet, std::io::Error> {
        // Create the directory if it does not exist
        std::fs::create_dir_all(&config.ruta_claves_usuario)?;

        let accounts = Self::read_accounts(&config, &logger)?;

        Ok(Wallet {
            config,
            accounts,
            active_account: None,
            logger,
        })
    }

    /// Add a new account to the wallet
    ///
    /// # Arguments
    ///
    /// * `private_key` - Private key
    ///
    /// * `address` - Address
    ///
    /// * `account_name` - Account name
    ///
    /// ```
    pub fn add_account(
        &mut self,
        private_key: String,
        address: String,
        account_name: String,
    ) -> Result<(), std::io::Error> {
        let private_key_path = format!("{}/{}", self.config.ruta_claves_usuario, account_name);
        write_file_utf8(private_key_path, &private_key)?;
        let address_path = format!(
            "{}/{}.address",
            self.config.ruta_claves_usuario, account_name
        );
        write_file_utf8(address_path, &address)?;
        self.accounts.push(Account {
            private_key,
            address,
            name: account_name,
        });
        Ok(())
    }

    /// Read an account from the wallet
    ///
    /// # Arguments
    ///
    /// * `config` - Config
    ///
    /// * `account_name` - Account name
    ///
    /// ```
    fn read_account(config: &Config, account_name: String) -> Result<Account, std::io::Error> {
        let private_key_path = format!("{}/{}", config.ruta_claves_usuario, account_name);
        let private_key = read_file_utf8(private_key_path)?;
        let address_path = format!("{}/{}.address", config.ruta_claves_usuario, account_name);
        let address = read_file_utf8(address_path)?;
        Ok(Account {
            private_key,
            address,
            name: account_name,
        })
    }

    /// Read all accounts from the wallet
    ///
    /// # Arguments
    ///
    /// * `config` - Config
    ///
    /// ```
    fn read_accounts(
        config: &Config,
        logger: &Arc<Mutex<Logger>>,
    ) -> Result<Vec<Account>, std::io::Error> {
        let mut accounts = Vec::new();
        let paths = std::fs::read_dir(&config.ruta_claves_usuario)?;
        for path in paths {
            let path = path?.path();
            let path = match path.to_str() {
                Some(path) => path,
                None => {
                    logger.error(&format!("Error reading account: {}", "Invalid path"));
                    continue;
                }
            };
            let account_name = path.replace(&format!("{}/", &config.ruta_claves_usuario), "");
            if account_name.ends_with(".address") {
                continue;
            }

            match Self::read_account(config, account_name) {
                Ok(account) => accounts.push(account),
                Err(e) => {
                    logger.error(&format!("Error reading account: {}", e));
                    continue;
                }
            }
        }
        Ok(accounts)
    }

    /// Remove an account from the wallet
    ///
    /// # Arguments
    ///
    /// * `account_name` - Account name
    ///
    /// ```
    pub fn remove_account(&mut self, account_name: String) -> Result<(), std::io::Error> {
        let private_key_path = format!("{}/{}", self.config.ruta_claves_usuario, account_name);
        std::fs::remove_file(private_key_path)?;
        let address_path = format!(
            "{}/{}.address",
            self.config.ruta_claves_usuario, account_name
        );
        std::fs::remove_file(address_path)?;

        let mut index = 0;
        for account in &self.accounts {
            if account.name == account_name {
                break;
            }
            index += 1;
        }

        self.accounts.swap_remove(index);
        Ok(())
    }

    /// Get all accounts from the wallet
    ///
    /// ```
    pub fn get_accounts(&self) -> Result<Vec<Account>, std::io::Error> {
        Ok(self.accounts.clone())
    }

    /// Get an account from the wallet
    ///
    /// # Arguments
    ///
    /// * `account_name` - Account name
    ///
    /// ```
    pub fn get_account(&self, account_name: &str) -> Option<Account> {
        for account in &self.accounts {
            if account.name == account_name {
                return Some(account.clone());
            }
        }
        None
    }

    /// Get an account from the wallet by address
    ///
    /// # Arguments
    ///
    /// * `address` - Address
    ///
    /// ```
    pub fn get_account_by_address(&self, address: &str) -> Option<Account> {
        for account in &self.accounts {
            if account.address == address {
                return Some(account.clone());
            }
        }
        None
    }

    /// List all account names from the wallet
    ///
    /// ```
    pub fn list_account_names(&self) -> Result<Vec<String>, std::io::Error> {
        let mut accounts = Vec::new();
        for account in &self.accounts {
            accounts.push(account.name.clone());
        }
        Ok(accounts)
    }

    /// List all account addresses from the wallet
    ///
    /// ```
    fn list_account_addresses(&self) -> Vec<String> {
        let mut accounts = Vec::new();
        for account in &self.accounts {
            accounts.push(account.address.clone());
        }
        accounts
    }

    pub fn run(
        &mut self,
        wallet_sender: std::sync::mpsc::Sender<WalletMessages>,
        wallet_receiver: std::sync::mpsc::Receiver<WalletMessages>,
    ) -> Result<(), std::io::Error> {
        for message in wallet_receiver.iter() {
            match message {
                WalletMessages::AddAccount(text) => {
                    let split = text.split(',').collect::<Vec<&str>>();
                    let private_key = match split.first() {
                        Some(private_key) => private_key.to_string(),
                        None => {
                            self.logger.error("Error: private_key not found");
                            continue;
                        }
                    };
                    let address = match split.get(1) {
                        Some(address) => address.to_string(),
                        None => {
                            self.logger.error("Error: address not found");
                            continue;
                        }
                    };
                    let account_name = match split.get(2) {
                        Some(account_name) => account_name.to_string(),
                        None => {
                            self.logger.error("Error: account_name not found");
                            continue;
                        }
                    };
                    self.add_account(private_key, address, account_name)?;
                    let accounts_names = self.list_account_names()?;
                    match wallet_sender.send(WalletMessages::AccountNamesList(accounts_names)) {
                        Ok(_) => {}
                        Err(e) => {
                            self.logger
                                .error(&format!("Error sending AccountList: {}", e));
                            continue;
                        }
                    }

                    let accounts_addresses = self.list_account_addresses();
                    match wallet_sender.send(WalletMessages::AddressesList(accounts_addresses)) {
                        Ok(_) => {}
                        Err(e) => {
                            self.logger
                                .error(&format!("Error sending AccountList: {}", e));
                            continue;
                        }
                    }
                }
                WalletMessages::GetAccountList() => {
                    let accounts_names = self.list_account_names()?;
                    match wallet_sender.send(WalletMessages::AccountNamesList(accounts_names)) {
                        Ok(_) => {}
                        Err(e) => {
                            self.logger
                                .error(&format!("Error sending AccountList: {}", e));
                            continue;
                        }
                    }

                    let accounts_addresses = self.list_account_addresses();
                    match wallet_sender.send(WalletMessages::AddressesList(accounts_addresses)) {
                        Ok(_) => {}
                        Err(e) => {
                            self.logger
                                .error(&format!("Error sending AccountList: {}", e));
                            continue;
                        }
                    }
                }
                WalletMessages::ChangeActiveAccount(name) => {
                    for account in &self.accounts {
                        if account.name == name {
                            self.active_account = Some(account.clone());
                            match wallet_sender
                                .send(WalletMessages::ActiveAccount(account.address.clone()))
                            {
                                Ok(_) => {}
                                Err(e) => {
                                    self.logger
                                        .error(&format!("Error sending ActiveAccount: {}", e));
                                    continue;
                                }
                            }

                            break;
                        }
                    }
                }
                WalletMessages::CreateTransaction(tx_entry) => {
                    let input_tx_ids = tx_entry.input_tx_ids;
                    let input_tx_indexes = tx_entry.input_numbers;
                    let mut input_tx_private_keys = Vec::new();
                    for address in &tx_entry.input_addresses {
                        let account = self.get_account_by_address(address);
                        match account {
                            Some(account) => {
                                input_tx_private_keys.push(account.private_key.clone());
                            }
                            None => {
                                self.logger.error("Error: account not found");
                                continue;
                            }
                        }
                    }
                    let input_tx_addresses = tx_entry.input_addresses;
                    let output_addresses = tx_entry.output_addresses;
                    let output_values = tx_entry.output_amounts;
                    match create_p2pkh_transaction(
                        input_tx_ids,
                        input_tx_indexes,
                        input_tx_addresses,
                        input_tx_private_keys,
                        output_addresses,
                        output_values,
                    ) {
                        Ok(tx) => {
                            match wallet_sender.send(WalletMessages::TransactionCreated(tx)) {
                                Ok(_) => {}
                                Err(e) => {
                                    self.logger
                                        .error(&format!("Error sending TransactionCreated: {}", e));
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            self.logger
                                .error(&format!("Error creating transaction: {}", e));
                            continue;
                        }
                    }
                }
                WalletMessages::GetProofOfInclusion(tree) => {
                    let obtained_root = merkle::get_obtained_merkle_root(
                        &tree.hashes,
                        &tree.flags,
                        tree.tx_ammount,
                    );
                    let result = tree.expected_merkle_root == obtained_root;
                    match wallet_sender.send(WalletMessages::ProofOfInclusionResult(result)) {
                        Ok(_) => {}
                        Err(e) => {
                            self.logger
                                .error(&format!("Error sending ProofOfInclusionResult: {}", e));
                            continue;
                        }
                    };
                }

                _ => {}
            }
        }
        Ok(())
    }
}

pub fn decode_wif_compressed(wif: &str) -> Result<secp256k1::SecretKey, std::io::Error> {
    let wif_bytes = match bs58::decode(wif).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid WIF",
            ))
        }
    };
    if wif_bytes.len() != 38 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid WIF",
        ));
    }

    let raw_private_key = wif_bytes[1..33].to_vec();
    let secret_key = match secp256k1::SecretKey::from_slice(&raw_private_key) {
        Ok(secret_key) => secret_key,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid WIF",
            ))
        }
    };

    Ok(secret_key)
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use crate::{config, logger::Logger, wallet::Account};

    #[test]
    fn test_account_flow() {
        const ARCHIVO_CFG: &str = "Ruta claves usuario: data/.keys/temp";

        let config = config::Config::new(ARCHIVO_CFG.as_bytes()).unwrap();
        let logger = Arc::new(Mutex::new(Logger::new(
            "debug".to_owned(),
            Arc::new(Mutex::new(Box::new(io::stdout()))),
            true,
        )));

        let mut wallet = super::Wallet::new(config, logger).unwrap();

        wallet
            .add_account(
                "private_key_1".to_string(),
                "address_1".to_string(),
                "1".to_string(),
            )
            .unwrap();
        wallet
            .add_account(
                "private_key_2".to_string(),
                "address_2".to_string(),
                "2".to_string(),
            )
            .unwrap();

        wallet
            .add_account(
                "private_key_3".to_string(),
                "address_3".to_string(),
                "3".to_string(),
            )
            .unwrap();

        let account_names_list = wallet.list_account_names().unwrap();
        assert_eq!(account_names_list.len(), 3);
        // Check if accounts are in the list
        assert!(account_names_list.contains(&"1".to_string()));
        assert!(account_names_list.contains(&"2".to_string()));
        assert!(account_names_list.contains(&"3".to_string()));

        let accounts = wallet.get_accounts().unwrap();

        assert_eq!(accounts.len(), 3);
        assert!(accounts.contains(&Account {
            private_key: "private_key_1".to_string(),
            address: "address_1".to_string(),
            name: "1".to_string(),
        }));
        assert!(accounts.contains(&Account {
            private_key: "private_key_2".to_string(),
            address: "address_2".to_string(),
            name: "2".to_string(),
        }));
        assert!(accounts.contains(&Account {
            private_key: "private_key_3".to_string(),
            address: "address_3".to_string(),
            name: "3".to_string(),
        }));

        wallet.remove_account("2".to_string()).unwrap();

        assert_eq!(wallet.get_account("2"), None);
        assert_eq!(wallet.get_accounts().unwrap().len(), 2);

        // Remove directory at path
        std::fs::remove_dir_all("data/.keys/temp").unwrap();
    }
    #[test]
    fn test_decode_wif_compressed() {
        let secret_key = "cRv4CZyC6gpq9dZS2hiTXpzofhHKuFy8FtiyXVSvR3rj8eP9Te65";
        let secret_key = super::decode_wif_compressed(secret_key).unwrap();
        assert_eq!(
            "814E62910B9AF441CB9B4349B4E9B0BAA051829CCDBA4BAD3FF95D5E92A0CF11".to_ascii_lowercase(),
            secret_key.display_secret().to_string()
        );
    }
}
