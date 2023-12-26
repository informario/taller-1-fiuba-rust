pub mod config;
pub mod controller;
pub mod file_utils;
mod interfaz;
pub mod logger;
pub mod node;
pub mod peer_mock;
pub mod wallet;
use std::fs::File;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use config::Config;
use controller::{Controller, InterfaceMessage, Message, NodeMessages, WalletMessages};
use gtk::glib::{self, Receiver, Sender};
use logger::{Loggable, Logger};
use node::Node;
use peer_mock::PeerMock;
use wallet::Wallet;
fn parse_args() -> Result<String, std::io::Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <config_file>", args[0]);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid number of arguments",
        ));
    }

    Ok(args[1].clone())
}

fn main() {
    let path = match parse_args() {
        Ok(path) => path,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    let config = match Config::new_from_file_path(&path) {
        Ok(config) => config,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };
    config.log();

    let output: Box<dyn Write + Send> = match config.logger_file.as_str() {
        "" | "stdout" => Box::new(io::stdout()),
        _ => match File::create(&config.logger_file) {
            Ok(file) => Box::new(file),
            Err(e) => {
                println!("Error: {}", e);
                return;
            }
        },
    };

    let logger = Logger::new(
        config.logger_level.clone(),
        Arc::new(Mutex::new(output)),
        true,
    );

    logger.info(&config.log());

    // Creacion de channels para comunicacion entre threads
    let (controller_interfaz_tx, controller_interfaz_rx): (
        Sender<InterfaceMessage>,
        Receiver<InterfaceMessage>,
    ) = glib::MainContext::channel(glib::PRIORITY_DEFAULT);
    let (controller_node_tx, controller_node_rx): (
        std::sync::mpsc::Sender<NodeMessages>,
        std::sync::mpsc::Receiver<NodeMessages>,
    ) = std::sync::mpsc::channel();
    let (node_controller_tx, node_controller_rx): (
        std::sync::mpsc::Sender<NodeMessages>,
        std::sync::mpsc::Receiver<NodeMessages>,
    ) = std::sync::mpsc::channel();
    let (interfaz_controller_tx, interfaz_controller_rx): (
        std::sync::mpsc::Sender<Message>,
        std::sync::mpsc::Receiver<Message>,
    ) = std::sync::mpsc::channel();
    let (wallet_controller_tx, wallet_controller_rx): (
        std::sync::mpsc::Sender<WalletMessages>,
        std::sync::mpsc::Receiver<WalletMessages>,
    ) = std::sync::mpsc::channel();
    let (controller_wallet_tx, controller_wallet_rx): (
        std::sync::mpsc::Sender<WalletMessages>,
        std::sync::mpsc::Receiver<WalletMessages>,
    ) = std::sync::mpsc::channel();

    let mut handles: Vec<JoinHandle<()>> = vec![];

    let wrapped_logger = Arc::new(Mutex::new(logger));
    let main_thread_logger = Arc::clone(&wrapped_logger);

    // WALLET
    let wallet_logger_clone = Arc::clone(&wrapped_logger);
    let wallet_config_clone = config.clone();
    let wallet_thread_handle = match thread::Builder::new()
        .name("wallet_thread".to_string())
        .spawn(move || {
            let wallet_internal_logger = Arc::clone(&wallet_logger_clone);
            let mut wallet = match Wallet::new(wallet_config_clone, wallet_internal_logger) {
                Ok(wallet) => wallet,
                Err(e) => {
                    wallet_logger_clone.error(&format!("Error: {}", e));
                    return;
                }
            };
            match wallet.list_account_names() {
                Ok(accounts) => wallet_logger_clone.info(&format!("Accounts: {:?}", accounts)),
                Err(e) => {
                    wallet_logger_clone.error(&format!("{}", e));
                    return;
                }
            }
            match wallet.run(wallet_controller_tx, controller_wallet_rx) {
                Ok(_) => {}
                Err(e) => {
                    wallet_logger_clone.error(&format!("{}", e));
                }
            };
        }) {
        Ok(handle) => handle,
        Err(e) => {
            let err_msg = format!("Error: {}", e);
            main_thread_logger.error(&err_msg);
            return;
        }
    };
    handles.push(wallet_thread_handle);

    // NODO
    if config.nodo == "Si" {
        let node_logger_clone = Arc::clone(&wrapped_logger);
        let internal_node_logger = Arc::clone(&node_logger_clone);
        let config_clone = config.clone();
        let node_thread_handle = match thread::Builder::new()
            .name("node_thread".to_string())
            .spawn(move || {
                let mut node = match Node::new(
                    config_clone.clone(),
                    internal_node_logger,
                    node_controller_tx,
                ) {
                    Ok(node) => node,
                    Err(e) => {
                        node_logger_clone.error(&format!("Error: {}", e));
                        return;
                    }
                };
                match node.run(controller_node_rx) {
                    Ok(_) => {}
                    Err(e) => {
                        node_logger_clone.error(&format!("{}", e));
                    }
                };
            }) {
            Ok(handle) => handle,
            Err(e) => {
                let err_msg = format!("Error: {}", e);
                wrapped_logger.error(&err_msg);
                return;
            }
        };
        handles.push(node_thread_handle);
    }

    // INTERFAZ
    if config.interfaz == "Si" {
        let interfaz_logger_clone = Arc::clone(&wrapped_logger);
        let interfaz_thread_handle = match thread::Builder::new()
            .name("interfaz_thread".to_string())
            .spawn(move || {
                let interfaz =
                    interfaz::Interfaz::new(String::from("interfaz.hola"), interfaz_controller_tx);
                match interfaz.start(controller_interfaz_rx) {
                    Ok(_) => {}
                    Err(e) => {
                        interfaz_logger_clone.error(&format!("{}", e));
                    }
                };
            }) {
            Ok(handle) => handle,
            Err(e) => {
                let err_msg = format!("Error: {}", e);
                wrapped_logger.error(&err_msg);
                return;
            }
        };
        handles.push(interfaz_thread_handle);
    }

    // CONTROLLER
    let controller_logger_clone = Arc::clone(&wrapped_logger);
    let controller_thread_handle = match thread::Builder::new()
        .name("controller_thread".to_string())
        .spawn(move || {
            let mut controller = Controller::new(
                controller_logger_clone,
                controller_interfaz_tx,
                Some(interfaz_controller_rx),
                controller_node_tx,
                Some(node_controller_rx),
                controller_wallet_tx,
                Some(wallet_controller_rx),
            );
            match controller.start() {
                Ok(_) => {}
                Err(e) => {
                    let err_msg = format!("Error: {}", e);
                    println!("{}", err_msg);
                }
            };
        }) {
        Ok(handle) => handle,
        Err(e) => {
            let err_msg = format!("Error: {}", e);
            wrapped_logger.error(&err_msg);
            return;
        }
    };
    handles.push(controller_thread_handle);
    // PEER MOCK
    let run_peer_mock = false;
    if run_peer_mock {
        let peer_mock_logger_clone = Arc::clone(&wrapped_logger);
        let peer_mock_thread_handle = match thread::Builder::new()
            .name("peer_mock_thread".to_string())
            .spawn(move || {
                match PeerMock::run(peer_mock_logger_clone) {
                    Ok(_) => {}
                    Err(e) => {
                        let err_msg = format!("Error: {}", e);
                        println!("{}", err_msg);
                    }
                };
            }) {
            Ok(handle) => handle,
            Err(e) => {
                let err_msg = format!("Error: {}", e);
                wrapped_logger.error(&err_msg);
                return;
            }
        };
        handles.push(peer_mock_thread_handle);
    }

    for handle in handles {
        match handle.join() {
            Ok(_) => {}
            Err(e) => wrapped_logger.error(&format!("Error en hilo: {:?}", e)),
        }
    }

    main_thread_logger.debug("TERMINA HILO MAIN.RS");
}
