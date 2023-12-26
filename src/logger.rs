use std::io::{self, Write};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::{fmt, thread};

struct MutexGuardWrapper<'a, T: 'a>(&'a mut T);

impl<'a, T> Write for MutexGuardWrapper<'a, T>
where
    T: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }
}

#[derive(PartialEq, Clone)]
pub enum LogLevel {
    Info,
    Error,
    Debug,
}

impl LogLevel {
    pub fn new(log_level: String) -> LogLevel {
        match log_level.as_str() {
            "info" => LogLevel::Info,
            "error" => LogLevel::Error,
            "debug" => LogLevel::Debug,
            _ => LogLevel::Info,
        }
    }
}
impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Debug => write!(f, "DEBUG"),
        }
    }
}

/// Logger is a simple logging library that can be used to log messages to the console.
/// It is thread safe and can be used by multiple threads at the same time.
/// It is implemented using a channel and a separate thread that prints the messages.
/// The logger can be used by calling the info and error methods.
/// The info method is used to log info messages and the error method is used to log error messages.
/// Both methods return a Result object that can be used to check if the message was sent successfully.
/// If the message was sent successfully, the Result object will contain an empty Ok value.
/// If the message could not be sent, the Result object will contain an Err value with an error message.
/// The logger can be created by calling the new method.
/// The new method returns a Logger object that can be used to log messages.
/// The Logger object contains a Sender object that is used to send messages to the logger thread via the functions info and error.
#[derive(Clone)]
pub struct Logger {
    sender: Sender<String>,
    level: LogLevel,
    timestamp: bool,
}

impl Logger {
    /// Creates a new Logger object.
    ///
    /// ```
    pub fn new<T>(level: String, output: Arc<Mutex<T>>, timestamp: bool) -> Logger
    where
        T: Write + Send + 'static,
    {
        let (tx, rx) = channel();
        thread::spawn(move || loop {
            while let Ok(message) = rx.recv() {
                let mut output = match output.lock() {
                    Ok(guard) => guard,
                    Err(e) => {
                        println!("Error locking output: {}", e);
                        continue;
                    }
                };
                let writer = MutexGuardWrapper(&mut *output);
                match Self::write_to_output(writer, message) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("Error writing to output: {}", e);
                    }
                }
            }
        });
        Logger {
            sender: tx,
            level: LogLevel::new(level),
            timestamp,
        }
    }

    fn write_to_output<T>(mut output: T, text: String) -> io::Result<()>
    where
        T: Write,
    {
        output.write_all(text.as_bytes())?;
        Ok(())
    }

    /// Logs an info message.
    /// This function is used to log an info message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to log.
    ///
    /// ```
    pub fn info(&self, message: &str) {
        if self.level == LogLevel::Info || self.level == LogLevel::Debug {
            let formatted_message = Self::format_log(message, &LogLevel::Info, self.timestamp);
            match self.sender.send(formatted_message) {
                Ok(_) => {}
                Err(e) => println!("Error sending log message: {}", e),
            }
        }
    }

    /// Logs an error message.
    /// This function is used to log an error message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to log.
    ///
    /// ```
    pub fn error(&self, message: &str) {
        let formatted_message = Self::format_log(message, &LogLevel::Error, self.timestamp);
        match self.sender.send(formatted_message) {
            Ok(_) => {}
            Err(e) => println!("Error sending log message: {}", e),
        }
    }

    /// Logs a debug message.
    /// This function is used to log an debug message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to log.
    ///
    /// ```
    pub fn debug(&self, message: &str) {
        if self.level == LogLevel::Debug {
            let formatted_message = Self::format_log(message, &LogLevel::Debug, self.timestamp);
            match self.sender.send(formatted_message) {
                Ok(_) => {}
                Err(e) => println!("Error sending log message: {}", e),
            }
        }
    }

    /// Formats a log message.
    /// This function is used to format a log message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to format.
    /// * `level` - The log level.
    ///
    /// ```
    fn format_log(message: &str, level: &LogLevel, timestamp: bool) -> String {
        match timestamp {
            true => format!(
                "{}: {}: {}\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                level,
                message
            ),
            false => format!("{}: {}\n", level, message),
        }
    }
}

pub trait Loggable {
    fn info(&self, message: &str);
    fn error(&self, message: &str);
    fn debug(&self, message: &str);
}

impl Loggable for Arc<Mutex<Logger>> {
    fn info(&self, message: &str) {
        match self.lock() {
            Ok(guard) => guard.info(message),
            Err(e) => println!("Error locking logger: {}", e),
        }
    }

    fn error(&self, message: &str) {
        match self.lock() {
            Ok(guard) => guard.error(message),
            Err(e) => println!("Error locking logger: {}", e),
        }
    }

    fn debug(&self, message: &str) {
        match self.lock() {
            Ok(guard) => guard.debug(message),
            Err(e) => println!("Error locking logger: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;
    #[derive(Debug, PartialEq, Clone)]
    struct MockWriter {
        pub buffer: Vec<u8>,
    }

    impl MockWriter {
        fn new() -> Self {
            MockWriter { buffer: Vec::new() }
        }

        fn get_content(&self) -> &[u8] {
            &self.buffer
        }
    }

    impl Write for MockWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn write_fmt(&mut self, args: fmt::Arguments) -> io::Result<()> {
            let s = format!("{}", args);
            self.write_all(s.as_bytes())?;
            Ok(())
        }
    }
    fn setup(log_level: String, timestamp: bool) -> (Arc<Mutex<Logger>>, Arc<Mutex<MockWriter>>) {
        let output: Arc<Mutex<MockWriter>> = Arc::new(Mutex::new(MockWriter::new()));
        (
            Arc::new(Mutex::new(Logger::new(
                log_level,
                Arc::clone(&output),
                timestamp,
            ))),
            output,
        )
    }
    #[test]
    fn test_multiple_threads() {
        let mut handles: Vec<JoinHandle<()>> = vec![];
        let (logger, _) = setup("info".to_string(), false);
        {
            for index in 1..11 {
                let logger_clone = logger.clone();
                let handle = thread::spawn(move || {
                    thread::sleep(Duration::from_secs(20 - index));
                    logger_clone
                        .lock()
                        .unwrap()
                        .info(&format!("Thread {} is done", index))
                });

                handles.push(handle);
            }
        }
        for handle in handles {
            handle.join().unwrap();
        }

        logger.lock().unwrap().error("Main thread is done");
    }

    #[test]
    fn test_format_log() {
        let message = "This is a test message";
        let level = "INFO";
        let formatted_message = Logger::format_log(message, &LogLevel::Info, true);
        assert_eq!(
            formatted_message,
            format!(
                "{}: {}: {}\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                level,
                message
            )
        );

        let level = "DEBUG";
        let formatted_message = Logger::format_log(message, &LogLevel::Debug, false);
        assert_eq!(formatted_message, format!("{}: {}\n", level, message));
    }

    #[test]
    fn test_log_info() {
        let (logger, output) = setup("info".to_string(), true);
        logger.lock().unwrap().info("This is a test message");
        let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        // Sleep
        thread::sleep(Duration::from_secs(1));
        let output = output.lock().unwrap();
        assert_eq!(
            std::str::from_utf8(output.get_content()).unwrap(),
            format!("{}: INFO: This is a test message\n", time)
        );
    }

    #[test]
    fn test_log_error() {
        let (logger, output) = setup("error".to_string(), true);
        logger.lock().unwrap().error("This is a test message");
        let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        // Sleep
        thread::sleep(Duration::from_secs(1));
        let output = output.lock().unwrap();
        assert_eq!(
            std::str::from_utf8(output.get_content()).unwrap(),
            format!("{}: ERROR: This is a test message\n", time)
        );
    }

    #[test]
    fn test_log_debug() {
        let (logger, output) = setup("debug".to_string(), true);
        logger.lock().unwrap().debug("This is a test message");
        let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        // Sleep
        thread::sleep(Duration::from_secs(3));
        let output = output.lock().unwrap();
        assert_eq!(
            std::str::from_utf8(output.get_content()).unwrap(),
            format!("{}: DEBUG: This is a test message\n", time)
        );
    }
}

// Path: src\main.rs
