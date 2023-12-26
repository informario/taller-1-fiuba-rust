use crate::controller;
use bitcoin_hashes::hex::FromHex;
use controller::Message;
use gtk::{prelude::*, Builder};

#[derive(Clone, Debug)]
pub struct TransactionInterfaceEntry {
    pub output_addresses: Vec<String>,
    pub output_amounts: Vec<u64>,
    pub input_tx_ids: Vec<[u8; 32]>,
    pub input_numbers: Vec<u32>,
    pub input_addresses: Vec<String>,
}

impl TransactionInterfaceEntry {
    fn parse(
        output_addresses: Vec<String>,
        output_amounts: Vec<String>,
        input_tx_ids: Vec<String>,
        input_numbers: Vec<String>,
        input_addresses: Vec<String>,
    ) -> Result<Self, std::io::Error> {
        let mut output_amounts_parsed: Vec<u64> = Vec::new();
        for amount in output_amounts {
            let scaling_factor = 100_000_000.0; // 100 million

            // Parse the input string as a floating-point number
            let parsed_number = match amount.parse::<f64>() {
                Ok(n) => n,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Couldn't parse amount. Error: {}", e),
                    ));
                }
            };

            // Multiply the parsed number by the scaling factor
            let scaled_number = (parsed_number * scaling_factor).round() as u64;

            output_amounts_parsed.push(scaled_number);
        }

        let mut input_tx_ids_parsed: Vec<[u8; 32]> = Vec::new();
        for tx_id in input_tx_ids {
            let mut tx_id_parsed: [u8; 32] = [0; 32];
            let tx_id_bytes = match <[u8; 32]>::from_hex(&tx_id) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Couldn't parse tx_id. Error: {}", e),
                    ));
                }
            };
            tx_id_parsed.copy_from_slice(&tx_id_bytes);
            tx_id_parsed.reverse();
            input_tx_ids_parsed.push(tx_id_parsed);
        }

        let mut input_numbers_parsed: Vec<u32> = Vec::new();
        for number in input_numbers {
            let parsed_number = match number.parse::<u32>() {
                Ok(n) => n,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Couldn't parse number. Error: {}", e),
                    ));
                }
            };
            input_numbers_parsed.push(parsed_number);
        }

        Ok(Self {
            output_addresses,
            output_amounts: output_amounts_parsed,
            input_tx_ids: input_tx_ids_parsed,
            input_numbers: input_numbers_parsed,
            input_addresses,
        })
    }
}

pub fn build_stack(builder: &Builder, controller_sender: &std::sync::mpsc::Sender<Message>) {
    let output_addresses_entry: gtk::Entry = match builder.object("OutputAddressesEntryBox") {
        Some(entry) => entry,
        None => {
            return;
        }
    };
    output_addresses_entry
        .set_placeholder_text(Some("n2wx...kmHxhFc, mwqa8...fihVdN, mzfR6...bSaqc98Uo"));

    let output_amounts_entry: gtk::Entry = match builder.object("OutputAmountsEntryBox") {
        Some(entry) => entry,
        None => {
            return;
        }
    };
    output_amounts_entry.set_placeholder_text(Some("0.0015, 0.0005, 0.0005"));

    let input_tx_ids_entry: gtk::Entry = match builder.object("InputTransactionIdsEntryBox") {
        Some(entry) => entry,
        None => {
            return;
        }
    };
    input_tx_ids_entry.set_placeholder_text(Some("cf...0a, 1b...2c, 3d...4e"));

    let input_numbers_entry: gtk::Entry = match builder.object("InputNumbersEntryBox") {
        Some(entry) => entry,
        None => {
            return;
        }
    };
    input_numbers_entry.set_placeholder_text(Some("0, 1, 2"));

    let input_addresses_entry: gtk::Entry = match builder.object("InputAddressesEntryBox") {
        Some(entry) => entry,
        None => {
            return;
        }
    };
    input_addresses_entry
        .set_placeholder_text(Some("n2wx...kmHxhFc, mwqa8...fihVdN, mzfR6...bSaqc98Uo"));

    let send_button: gtk::Button = match builder.object("SendButton") {
        Some(button) => button,
        None => {
            return;
        }
    };
    let clear_button: gtk::Button = match builder.object("ClearButton") {
        Some(button) => button,
        None => {
            return;
        }
    };
    let output_addresses_entry_clone = output_addresses_entry.clone();
    let output_amounts_entry_clone = output_amounts_entry.clone();
    let input_tx_ids_entry_clone = input_tx_ids_entry.clone();
    let input_numbers_entry_clone = input_numbers_entry.clone();
    let input_addresses_entry_clone = input_addresses_entry.clone();
    clear_button.connect_clicked(move |_| {
        output_addresses_entry_clone.set_text("");
        output_amounts_entry_clone.set_text("");
        input_tx_ids_entry_clone.set_text("");
        input_numbers_entry_clone.set_text("");
        input_addresses_entry_clone.set_text("");
    });
    let controller_sender_clone = controller_sender.clone();
    send_button.connect_clicked(move |_| {
        if !output_addresses_entry.text().is_empty()
            && !output_amounts_entry.text().is_empty()
            && !input_tx_ids_entry.text().is_empty()
            && !input_numbers_entry.text().is_empty()
            && !input_addresses_entry.text().is_empty()
        {
            let output_addresses: Vec<String> = output_addresses_entry
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();

            let output_amounts: Vec<String> = output_amounts_entry
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();

            let input_tx_ids: Vec<String> = input_tx_ids_entry
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();

            let input_numbers: Vec<String> = input_numbers_entry
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();

            let input_addresses: Vec<String> = input_addresses_entry
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();

            if let Ok(tx_entry) = TransactionInterfaceEntry::parse(
                output_addresses,
                output_amounts,
                input_tx_ids,
                input_numbers,
                input_addresses,
            ) {
                match controller_sender_clone.send(Message::SendTransaction(tx_entry)) {
                    Ok(_) => {}
                    Err(_) => {
                        return;
                    }
                }
            };

            output_addresses_entry.set_text("");
            output_amounts_entry.set_text("");
            input_tx_ids_entry.set_text("");
            input_numbers_entry.set_text("");
            input_addresses_entry.set_text("");
        }
    });
}
