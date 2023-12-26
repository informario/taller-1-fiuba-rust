use crate::{
    controller,
    interfaz::account_dialog::{self /* AccountDialog */},
};
use controller::Message;
use gtk::{prelude::*, Builder};

pub fn build_stack(builder: &Builder, controller_sender: &std::sync::mpsc::Sender<Message>) {
    // let available_balance_label: gtk::Label = match builder.object("AvailableBalanceLabel") {
    //     Some(label) => label,
    //     None => {
    //         return;
    //     }
    // };
    // let pending_balance_label: gtk::Label = match builder.object("PendingBalanceLabel") {
    //     Some(label) => label,
    //     None => {
    //         return;
    //     }
    // };
    // let immature_balance_label: gtk::Label = match builder.object("ImmatureBalanceLabel") {
    //     Some(label) => label,
    //     None => {
    //         return;
    //     }
    // };
    let total_balance_label: gtk::Label = match builder.object("TotalBalanceLabel") {
        Some(label) => label,
        None => {
            return;
        }
    };
    let download_status_label: gtk::Label = match builder.object("DownloadStatus") {
        Some(label) => label,
        None => {
            return;
        }
    };
    let download_blocks_status_label: gtk::Label = match builder.object("DownloadBlockStatus") {
        Some(label) => label,
        None => {
            return;
        }
    };

    // pending_balance_label.set_text("Select a wallet to see the balance");
    // immature_balance_label.set_text("Select a wallet to see the balance");
    total_balance_label.set_text("Select a wallet to see the balance");
    // available_balance_label.set_text("Select a wallet to see the balance");
    download_status_label.set_text("0 headers downloaded");
    download_blocks_status_label.set_text("0 blocks downloaded");

    let account_button: gtk::Button = match builder.object("DialogButton") {
        Some(button) => button,
        None => {
            return;
        }
    };
    let controller_sender_clone = controller_sender.clone();

    account_button.connect_clicked(move |_| {
        let builder_clone = Builder::new();
        let glade_src = include_str!("glade1.glade");
        builder_clone
            .add_from_string(glade_src)
            .expect("Couldn't add from string");
        account_dialog::build_dialog(&builder_clone, &controller_sender_clone);
    });
}

pub fn update(message: Message, builder: &mut Builder) {
    match message {
        Message::UpdateActiveAccountBalance(text) => {
            let available_balance_label: gtk::Label = match builder.object("TotalBalanceLabel") {
                Some(label) => label,
                None => {
                    return;
                }
            };
            available_balance_label.set_text(text.as_str());
        },
        Message::HeadersDownloaded(amount) => {
            let download_status_label: gtk::Label = match builder.object("DownloadStatus") {
                Some(label) => label,
                None => {
                    return;
                }
            };
            download_status_label.set_text(&(amount.to_string() + " headers downloaded"));
        },
        Message::BlocksDownloaded(amount) => {
            let download_block_status_label: gtk::Label = match builder.object("DownloadBlocksStatus") {
                Some(label) => label,
                None => {
                    return;
                }
            };
            download_block_status_label.set_text(&(amount.to_string() + " blocks downloaded"));
        },
        _ => {},
    }

    /*if let Message::UpdateActiveAccountBalance(text) = message {
        let available_balance_label: gtk::Label = match builder.object("TotalBalanceLabel") {
            Some(label) => label,
            None => {
                return;
            }
        };
        available_balance_label.set_text(text.as_str());
    }
    if let Message::UpdateDownloadStatus(text) = message {
        let download_status_label: gtk::Label = match builder.object("DownloadStatus") {
            Some(label) => label,
            None => {
                return;
            }
        };
        download_status_label.set_text(text.as_str());
    }*/
}
