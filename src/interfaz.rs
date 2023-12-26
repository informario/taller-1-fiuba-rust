//use std::{thread, time};

//use gtk::gdk::keys::constants::{N, S};
//use gtk::glib::PRIORITY_DEFAULT;
use gtk::{glib, Application};
use gtk::{prelude::*, Builder /* , glib */};
pub mod account_selector;
pub mod check_poi_stack;
pub mod overview_stack;
pub mod send_stack;
pub mod transactions_stack;
use crate::controller;
use controller::InterfaceMessage;
use controller::Message;
pub mod account_dialog;

/// public
///
/// Interfaz, encapsula la aplicacion
///
#[derive(Debug)]
pub struct Interfaz {
    app: Application,
    controller_sender: std::sync::mpsc::Sender<Message>,
}

impl Interfaz {
    /// public
    ///
    /// Construye la applicacion
    ///
    /// Input: nombre
    ///
    /// Output:
    ///
    pub fn new(nombre: String, controller_sender: std::sync::mpsc::Sender<Message>) -> Self {
        let app = gtk::Application::new(Some(&nombre), Default::default());

        Interfaz {
            app,
            controller_sender,
        }
    }

    /// public
    ///
    /// lanza la interfaz
    ///
    /// Input: self
    ///
    /// Output:
    pub fn start(
        &self,
        controller_interfaz_rx: gtk::glib::Receiver<InterfaceMessage>,
    ) -> Result<(), std::io::Error> {
        //Interfaz::cargar_contenido(&self.app);
        //self.app.connect_activate(move |_| {Interfaz::build_window(controller_interfaz_rx)});
        match gtk::init() {
            Ok(_) => {}
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Couldn't start GTK",
                ));
            }
        };
        //self.app.connect_activate(Interfaz::build_window);
        let mut builder = Builder::new();
        self.build_window(&self.app, &mut builder);
        controller_interfaz_rx.attach(None, move |msg| {
            match msg {
                InterfaceMessage::UpdateOverview(message) => {
                    overview_stack::update(message, &mut builder)
                }
                InterfaceMessage::UpdateTransactions(message) => {
                    transactions_stack::update(message, &mut builder)
                }
                InterfaceMessage::UpdateAccountSelector(message) => {
                    account_selector::update(message, &mut builder)
                }
                InterfaceMessage::UpdateCheckPoi(message) => {
                    check_poi_stack::update(message, &mut builder)
                }
                InterfaceMessage::Error(message) => check_poi_stack::update(message, &mut builder),
            }
            // Returning false here would close the receiver
            // and have senders fail
            glib::Continue(true)
        });
        gtk::main();
        self.app.run_with_args(&[""]);
        Ok(())
    }

    /// private
    ///
    /// Cargo contenido en la ventana del programa
    ///
    /// Input: ref a Applicacion
    ///
    /// Output:
    ///
    fn build_window(&self, _application: &gtk::Application, builder: &mut Builder)
    /* -> Result<(), std::io::Error> */
    {
        let glade_src = include_str!("interfaz/glade1.glade");
        //let builder = Builder::new();
        builder
            .add_from_string(glade_src)
            .expect("Couldn't add from string");

        let window: gtk::Window = match builder.object("Window") {
            Some(window) => window,
            None => {
                return;
                /* return Err(std::io::Error::new(
                  std::io::ErrorKind::Other,
                  "Couldn't build Window",
                )); */
            }
        };
        window.connect_destroy(Interfaz::quit);
        overview_stack::build_stack(builder, &self.controller_sender);
        send_stack::build_stack(builder, &self.controller_sender);
        transactions_stack::build_stack(builder, &self.controller_sender);
        account_selector::build_stack(builder, &self.controller_sender);
        check_poi_stack::build_stack(builder, &self.controller_sender);
        window.show_all();

        //Ok(())
    }
    fn quit(_window: &gtk::Window) {
        println!("CIERRO INTERFAZ");
        gtk::main_quit();
    }
}
