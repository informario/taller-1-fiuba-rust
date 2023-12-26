use crate::controller;
use controller::Message;
use gtk::{prelude::*, Builder};
pub fn build_stack(builder: &Builder, _controller_sender: &std::sync::mpsc::Sender<Message>) {
    /* let pending_balance_label: gtk::Label = match builder.object("PendingBalanceLabel") {
        Some(label) => label,
        None => {
            return;
            /* return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Couldn't build PendingBalanceLabel",
            )); */
        }
    };
    pending_balance_label.set_text("Select a wallet to see the balance"); */
    let tree: gtk::TreeView = match builder.object("TreeView") {
        Some(tree) => tree,
        None => {
            return;
            /* return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Couldn't build PendingBalanceLabel",
            )); */
        }
    };
    //let store = gtk::TreeStore::new(&column_types);
    //tree.set_model(Some(&store));
    tree.set_model(Some(&create_model(builder)));
    add_columns(&tree);
}

fn create_model(builder: &Builder) -> gtk::ListStore {
    let store: gtk::ListStore = match builder.object("TestingListStore") {
        Some(store) => store,
        None => panic!("No object with name TestingListStore"),
    };

    store
}

#[repr(i32)]
enum Columns {
    Date,
    Type,
    Label,
    Amount,
}

//fn add_columns(treeview: &gtk::TreeView)
fn add_columns(treeview: &gtk::TreeView) {
    // Column for date
    {
        let renderer = gtk::CellRendererText::new();
        let column = gtk::TreeViewColumn::new();
        column.pack_start(&renderer, true);
        column.set_title("Date");
        column.add_attribute(&renderer, "text", Columns::Date as i32);
        column.set_sort_column_id(Columns::Date as i32);
        column.set_fixed_width(100);
        column.set_alignment(0.0);
        treeview.append_column(&column);
    }

    // Column for status
    {
        let renderer = gtk::CellRendererText::new();
        let column = gtk::TreeViewColumn::new();
        column.pack_start(&renderer, true);
        column.set_title("Status");
        column.add_attribute(&renderer, "text", Columns::Type as i32);
        column.set_sort_column_id(Columns::Type as i32);
        column.set_fixed_width(100);
        column.set_alignment(0.0);
        treeview.append_column(&column);
    }

    // Column for label
    {
        let renderer = gtk::CellRendererText::new();
        let column = gtk::TreeViewColumn::new();
        column.pack_start(&renderer, true);
        column.set_title("Label");
        column.add_attribute(&renderer, "text", Columns::Label as i32);
        column.set_sort_column_id(Columns::Label as i32);
        column.set_fixed_width(150);
        column.set_alignment(0.0);
        treeview.append_column(&column);
    }

    // Column for amount
    {
        let renderer = gtk::CellRendererText::new();
        let column = gtk::TreeViewColumn::new();
        column.pack_start(&renderer, true);
        column.set_title("Amount (BTC)");
        column.add_attribute(&renderer, "text", Columns::Amount as i32);
        column.set_sort_column_id(Columns::Amount as i32);
        column.set_fixed_width(150);
        column.set_alignment(0.5);
        treeview.append_column(&column);
    }
}

pub fn update(message: Message, builder: &mut Builder) {
    match message {
        Message::NewTransaction(text) => {
            let split = text.split(", ").collect::<Vec<&str>>();
            let store: gtk::ListStore = match builder.object("TestingListStore") {
                Some(store) => store,
                None => panic!("No object with name TestingListStore"),
            };
            store.set(
                &store.append(),
                &[
                    (0, &split.first().to_value()),
                    (1, &split.get(1).to_value()),
                    (2, &split.get(2).to_value()),
                    (3, &split.get(3).to_value()),
                ],
            );
        }
        Message::ConfirmTransaction(transaction_string) => {
            let store: gtk::ListStore = match builder.object("TestingListStore") {
                Some(store) => store,
                None => panic!("No object with name TestingListStore"),
            };
            let split = transaction_string.split(", ").collect::<Vec<&str>>();
            let transaction_id = match split.get(2) {
                Some(id) => id.to_string(),
                None => return,
            };
            let iter_option = store.iter_first();
            if iter_option.is_some() {
                let iter = match store.iter_first() {
                    Some(iter) => iter,
                    None => return,
                };
                let mut value: String = store.value(&iter, 2).get().unwrap();
                while value != transaction_id {
                    store.iter_next(&iter);
                    value = store.value(&iter, 2).get().unwrap();
                }
                store.set_value(&iter, 1, &"Confirmed".to_value());
            } else {
                store.set(
                    &store.append(),
                    &[
                        (0, &split.first().to_value()),
                        (1, &split.get(1).to_value()),
                        (2, &split.get(2).to_value()),
                        (3, &split.get(3).to_value()),
                    ],
                );
            }
        }
        _ => {}
    }
}
