use gtk::{prelude::*, Builder};

use crate::controller::Message;

pub fn build_dialog(builder: &Builder, controller_sender: &std::sync::mpsc::Sender<Message>) {
    let dialog: gtk::Dialog = match builder.object("AccountDialog") {
        Some(dialog) => dialog,
        None => {
            return;
        }
    };
    let private_key_entry: gtk::Entry = match builder.object("PrivateKeyDialogEntry") {
        Some(entry) => entry,
        None => {
            return;
            /* return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Couldn't build PrivateKeyDialogEntry",
            )); */
        }
    };
    let address_entry: gtk::Entry = match builder.object("AddressDialogEntry") {
        Some(entry) => entry,
        None => {
            return;
            /* return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Couldn't build AddressDialogEntry",
            )); */
        }
    };
    let account_name_entry: gtk::Entry = match builder.object("AccountNameDialogEntry") {
        Some(entry) => entry,
        None => {
            return;
            /* return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Couldn't build AccountNameDialogEntry",
            )); */
        }
    };
    let add_button: gtk::Button = match builder.object("AddDialogButton") {
        Some(button) => button,
        None => {
            return;
            /* return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Couldn't build AddDialogButton",
            )); */
        }
    };
    let cancel_button: gtk::Button = match builder.object("CancelDialogButton") {
        Some(button) => button,
        None => {
            return;
            /* return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Couldn't build CancelDialogButton",
            )); */
        }
    };
    let private_key_entry_clone = private_key_entry.clone();
    let address_entry_clone = address_entry.clone();
    let account_name_entry_clone = account_name_entry.clone();
    let dialog_cancel_clone = dialog.clone();
    cancel_button.connect_clicked(move |_| {
        //dialog_cancel_clone.response(gtk::ResponseType::Cancel);
        private_key_entry_clone.set_text("");
        address_entry_clone.set_text("");
        account_name_entry_clone.set_text("");
        dialog_cancel_clone.close();
    });

    let dialog_add_clone = dialog.clone();
    let controller_sender_clone = controller_sender.clone();
    add_button.connect_clicked(move |_| {
        if !private_key_entry.text().is_empty()
            && !address_entry.text().is_empty()
            && !account_name_entry.text().is_empty()
        {
            //dialog_add_clone.response(gtk::ResponseType::Ok);
            let mut account = private_key_entry.text().as_str().to_string();
            account.push(',');
            account.push_str(address_entry.text().as_str());
            account.push(',');
            account.push_str(account_name_entry.text().as_str());
            //account_dialog_clone.set_result(account);
            match controller_sender_clone.send(Message::AddAccount(account)) {
                Ok(_) => {}
                Err(_) => {
                    //println!("Account not added");
                    return;
                }
            }
            match controller_sender_clone.send(Message::GetBalance(
                address_entry.text().as_str().to_string(),
            )) {
                Ok(_) => {}
                Err(_) => {
                    //println!("Balance not obtained");
                    return;
                }
            }
            private_key_entry.set_text("");
            address_entry.set_text("");
            account_name_entry.set_text("");
            dialog_add_clone.close();
        }
    });
    dialog.show();
}
