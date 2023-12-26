use crate::controller::Message;
use gtk::{prelude::*, Builder};
pub fn build_stack(builder: &Builder, controller_sender: &std::sync::mpsc::Sender<Message>) {
    let combo_box: gtk::ComboBoxText = match builder.object("AccountSelector") {
        Some(combo_box) => combo_box,
        None => {
            return;
        }
    };
    let controller_sender_clone = controller_sender.clone();

    // When combo box changes value, send a message to the controller
    combo_box.connect_changed(move |combo_box| {
        on_combo_box_changed(combo_box, &controller_sender_clone);
    });
}
fn on_combo_box_changed(
    combo_box: &gtk::ComboBoxText,
    controller_sender: &std::sync::mpsc::Sender<Message>,
) {
    if let Some(text) = combo_box.active_text() {
        if controller_sender
            .send(Message::AccountSelected(text.to_string()))
            .is_ok()
        {}
    }
}

fn update_account_list(combo_box: &gtk::ComboBoxText, account_list: Vec<String>) {
    combo_box.remove_all();
    for account in account_list {
        combo_box.append_text(account.as_str());
    }
}
pub fn update(message: Message, builder: &mut Builder) {
    if let Message::UpdateAccountList(account_list) = message {
        let combo_box: gtk::ComboBoxText = match builder.object("AccountSelector") {
            Some(combo_box) => combo_box,
            None => {
                return;
            }
        };
        update_account_list(&combo_box, account_list);
    }
}
