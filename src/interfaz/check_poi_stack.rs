use crate::controller;
use controller::Message;
use gtk::{prelude::*, Builder};

pub fn build_stack(builder: &Builder, controller_sender: &std::sync::mpsc::Sender<Message>) {
    let txid_entry: gtk::Entry = match builder.object("TxidBox") {
        Some(entry) => entry,
        None => {
            return;
        }
    };
    txid_entry.set_placeholder_text(Some(
        "Enter a Transaction Id (e.g. 5825e6137d5511fcc0ba77b0eca6f6f5474abf4610c8d18f03df2e39e46ceecd)",
    ));

    let block_entry: gtk::Entry = match builder.object("BlockIdBox") {
        Some(entry) => entry,
        None => {
            return;
        }
    };
    block_entry.set_placeholder_text(Some(
        "Enter a Block hash to check if the transaction is included there",
    ));

    let send_button: gtk::Button = match builder.object("ChckpoiSendButton") {
        Some(button) => button,
        None => {
            return;
        }
    };
    let clear_button: gtk::Button = match builder.object("ChkpoiClearButton") {
        Some(button) => button,
        None => {
            return;
        }
    };
    let status_label: gtk::Label = match builder.object("StatusLabel") {
        Some(label) => label,
        None => {
            return;
        }
    };
    let txid_entry_clone = txid_entry.clone();
    let block_entry_clone = block_entry.clone();

    clear_button.connect_clicked(move |_| {
        txid_entry_clone.set_text("");
        block_entry_clone.set_text("");
        status_label.set_text("Waiting for input");
    });

    let controller_sender_clone = controller_sender.clone();

    send_button.connect_clicked(move |_| {
        if !txid_entry.text().is_empty() && !block_entry.text().is_empty() {
            let mut transaction = txid_entry.text().as_str().to_string();
            //transaction.push_str(",");
            transaction.push_str(block_entry.text().as_str());
            match controller_sender_clone.send(Message::CheckPoi(transaction)) {
                Ok(_) => {}
                Err(_) => {
                    return;
                }
            }
            txid_entry.set_text("");
            block_entry.set_text("");
        }
    });
}

pub fn update(message: Message, builder: &mut Builder) {
    match message {
        Message::PoiResult(es_valido) => {
            let status_label: gtk::Label = match builder.object("StatusLabel") {
                Some(status_label) => status_label,
                None => {
                    return;
                }
            };
            let text = match es_valido {
                true => "Validated",
                false => "Not validated",
            };
            status_label.set_text(text);
        }
        Message::TxNotFound() => {
            let status_label: gtk::Label = match builder.object("StatusLabel") {
                Some(status_label) => status_label,
                None => {
                    return;
                }
            };
            status_label.set_text("TX not found in block");
        }
        _ => {}
    }
}
