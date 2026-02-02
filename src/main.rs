// ============================================================
// TCP Chat Client - Educational Version
// ============================================================
// This client demonstrates:
// - Functional programming patterns in Rust (similar to F#)
// - Message-passing concurrency (Actor model)
// - Non-blocking I/O with threads
// - XOR encryption (weak, for learning only!)
// - Iterator-based control flow
// ============================================================

use std::io::{self, stdin, stdout, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::time::Duration;

// ============================================================
// Constants
// ============================================================

/// Encryption key - single byte XOR (VERY WEAK, educational only!)
/// In production, use TLS/SSL or proper encryption libraries
const KEY: u8 = 42;

/// Server port number
const PORT: u16 = 5555;

/// Maximum message size (1 MB) to prevent memory exhaustion attacks
const MAX_MESSAGE_SIZE: usize = 1_000_000;

// ============================================================
// Pure utility functions (no I/O, no side effects, no dependencies)
// ============================================================

/// XOR transformation for encryption/decryption
///
/// XOR is symmetric: encrypt(encrypt(data, key), key) == data
/// This is VERY weak encryption - trivial to break with frequency analysis
///
/// # Example
/// ```
/// let encrypted = xor_transform(b"hello", 42);
/// let decrypted = xor_transform(&encrypted, 42);
/// assert_eq!(decrypted, b"hello");
/// ```
fn xor_transform(data: &[u8], key: u8) -> Vec<u8> {
    data.iter()           // Iterator over bytes
        .map(|&b| b ^ key) // XOR each byte with key
        .collect()         // Collect into Vec<u8>
}

/// Check if a message is a quit command
///
/// Uses pattern matching with `matches!` macro - similar to F#'s pattern matching
/// Returns true if msg is "/quit" or "/exit"
fn is_quit_command(msg: &str) -> bool {
    matches!(msg, "/quit" | "/exit")
}

/// Get server IP with default fallback
///
/// Returns default IP if input is empty, otherwise returns trimmed input
fn get_default_ip(input: &str) -> &str {
    match input.trim().is_empty() {
        true => "192.168.1.10",  // Default IP
        false => input.trim(),    // User-provided IP
    }
}

// ============================================================
// I/O functions (depend only on utilities)
// ============================================================

/// Read message length from stream (first 4 bytes)
///
/// Protocol: Each message is prefixed with its length as 4-byte big-endian u32
/// This allows the receiver to know exactly how many bytes to read
///
/// # Errors
/// Returns error if stream is closed or read fails
fn read_message_length<R: Read>(reader: &mut R) -> io::Result<usize> {
    let mut len_buf = [0u8; 4];        // Buffer for 4-byte length
    reader.read_exact(&mut len_buf)?;  // Read exactly 4 bytes (or error)
    Ok(u32::from_be_bytes(len_buf) as usize) // Convert big-endian bytes to usize
}

/// Read encrypted message bytes from stream
///
/// Reads exactly `len` bytes into a buffer
/// Used after reading the message length
///
/// # Arguments
/// * `reader` - The stream to read from
/// * `len` - Number of bytes to read
fn read_encrypted_bytes<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];  // Allocate buffer of exact size
    reader.read_exact(&mut buf)?;   // Read exactly len bytes (or error)
    Ok(buf)
}

/// Receive and decrypt a complete message from stream
///
/// This is a higher-level function that combines:
/// 1. Reading message length
/// 2. Validating size
/// 3. Reading encrypted bytes
/// 4. Decrypting
/// 5. Converting to UTF-8 string
///
fn receive_message<R: Read>(reader: &mut R) -> io::Result<String> {
    let len = read_message_length(reader)?;

    // Pattern matching for validation (F# style)
    // Notice: no early returns, entire logic is expression-based
    match len <= MAX_MESSAGE_SIZE {
        false => Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large")),
        true => {
            let encrypted = read_encrypted_bytes(reader, len)?;
            let decrypted = xor_transform(&encrypted, KEY);

            // Convert bytes to UTF-8 string, map error to io::Error
            String::from_utf8(decrypted)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))
        }
    }
}

/// Encrypt and send a message to stream
///
/// Protocol:
/// 1. Encrypt message with XOR
/// 2. Send length as 4-byte big-endian u32
/// 3. Send encrypted bytes
/// 4. Flush to ensure immediate sending
///
/// Uses functional chaining with `and_then` instead of sequential statements
fn send_message<W: Write>(writer: &mut W, msg: &str) -> io::Result<()> {
    let encrypted = xor_transform(msg.as_bytes(), KEY);
    let len = encrypted.len() as u32;

    // Functional chaining: each operation must succeed for next to run
    writer.write_all(&len.to_be_bytes())      // Write length
        .and_then(|_| writer.write_all(&encrypted))  // Then write data
        .and_then(|_| writer.flush())          // Then flush
}

// ============================================================
// Console actor (message-passing concurrency)
// ============================================================
// This implements the Actor model (like F# MailboxProcessor):
// - Single thread owns stdout
// - Other threads send messages to it via channel
// - Prevents interleaved/corrupted output
// - Sequential processing guarantees order
// ============================================================

/// Messages that can be sent to the console actor
///
/// This is similar to discriminated unions in F#
/// Each variant represents a different type of console action
enum ConsoleEvent {
    /// Display an incoming chat message
    Message(String),

    /// Display a system/status message
    Info(String),

    /// Display the input prompt
    Prompt,

    /// Signal the console thread to exit
    Exit,
}

/// Handle a single console event
///
/// Extracted as separate function for clarity and testability
/// Takes ownership of event and mutable reference to output stream
fn handle_console_event(event: ConsoleEvent, out: &mut impl Write) {
    match event {
        ConsoleEvent::Message(msg) => {
            println!();          // Blank line before message
            println!("{}", msg); // The message itself
            print!("> ");        // Prompt for next input
        }
        ConsoleEvent::Info(msg) => {
            println!("\r{}", msg); // \r moves cursor to start of line
            print!("> ");
        }
        ConsoleEvent::Prompt => {
            print!("> ");
        }
        ConsoleEvent::Exit => {}  // No action, just stops iteration
    }
    out.flush().ok();  // Ensure output is displayed immediately
}

/// Spawn the console actor thread
///
/// Returns a Sender that other threads can use to send console events
/// The actor runs in its own thread and processes events sequentially
///
/// This prevents multiple threads from writing to stdout simultaneously,
/// which would cause garbled output
fn spawn_console() -> Sender<ConsoleEvent> {
    let (tx, rx) = mpsc::channel::<ConsoleEvent>();

    thread::spawn(move || {
        let mut out = stdout();

        // Functional iterator approach instead of loop
        rx.into_iter()  // Convert receiver into iterator
            .take_while(|event| !matches!(event, ConsoleEvent::Exit))  // Stop on Exit
            .for_each(|event| handle_console_event(event, &mut out)); // Process each
    });

    tx  // Return sender for other threads to use
}

// ============================================================
// Reader thread (depends on receive_message)
// ============================================================
// This thread handles incoming messages from the server.
// It runs concurrently with the main thread that handles user input.
// ============================================================

/// Spawn a thread to read messages from server
///
/// This thread:
/// 1. Continuously reads messages from server
/// 2. Sends them to console actor for display
/// 3. Notifies main thread on disconnect via shutdown channel
///
/// # Arguments
/// * `reader` - TCP stream clone for reading
/// * `console` - Channel to send display events
/// * `shutdown` - Channel to signal main thread on disconnect
fn spawn_reader_thread(
    mut reader: TcpStream,
    console: Sender<ConsoleEvent>,
    shutdown: Sender<()>,
) {
    thread::spawn(move || {
        // Create iterator that yields messages until connection closes
        std::iter::from_fn(|| receive_message(&mut reader).ok())
            .for_each(|msg| {
                // Send each message to console actor
                console.send(ConsoleEvent::Message(msg)).ok();
            });

        // When iterator ends, connection is closed
        console.send(ConsoleEvent::Info("[Disconnected from server]".to_string())).ok();
        shutdown.send(()).ok();  // Notify main thread to stop
    });
}

// ============================================================
// User input handling
// ============================================================
// Functions for reading and validating user input
// ============================================================

/// Read a line of input from user with prompt
///
/// # Arguments
/// * `prompt` - Text to display before reading input
///
/// # Returns
/// Trimmed user input as String
fn read_user_input(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    stdout().flush()?;  // Ensure prompt is displayed

    let mut input = String::new();
    stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())  // Remove whitespace
}

/// Validate username is non-empty
///
/// Uses Option type (like F#) instead of bool for more expressive API
/// Returns Some(username) if valid, None if empty
///
/// Pattern matching forces caller to handle both cases explicitly
fn validate_username(username: &str) -> Option<String> {
    match username.is_empty() {
        true => None,
        false => Some(username.to_string()),
    }
}

// ============================================================
// Connection setup
// ============================================================
// Functions for establishing connection and initial handshake
// ============================================================

/// Connect to chat server at given IP
///
/// Constructs full address with PORT constant and attempts connection
/// Logs error message if connection fails
fn connect_to_server(ip: &str) -> io::Result<TcpStream> {
    let address = format!("{}:{}", ip, PORT);

    TcpStream::connect(&address).map_err(|e| {
        eprintln!("Failed to connect to {}: {}", address, e);
        e  // Return original error
    })
}

/// Setup username with server
///
/// 1. Prompts user for username via console actor
/// 2. Reads input
/// 3. Validates it's non-empty
/// 4. Sends to server
///
/// Uses functional composition: validate_username returns Option,
/// which we pattern match to return Result
fn setup_username(stream: &mut TcpStream, console: &Sender<ConsoleEvent>) -> io::Result<String> {
    console.send(ConsoleEvent::Info(
        "Please enter your username and press Enter:".to_string()
    )).ok();

    let username = read_user_input("")?;

    // Pattern matching on Option, converting to Result
    match validate_username(&username) {
        None => {
            console.send(ConsoleEvent::Info("Username cannot be empty.".to_string())).ok();
            Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty username"))
        }
        Some(name) => {
            send_message(stream, &name)?;
            Ok(name)
        }
    }
}

// ============================================================
// Message loop processing
// ============================================================
// Functions for the main message send loop
// ============================================================

/// Process a single user message
///
/// Either:
/// 1. Execute quit command and signal to stop (Err)
/// 2. Send message to server and continue (Ok)
///
/// Returns Result<(), ()> where:
/// - Ok(()) means continue processing
/// - Err(()) means stop processing (quit command or send error)
fn process_user_message(
    line: String,
    stream: &mut TcpStream,
    console: &Sender<ConsoleEvent>,
) -> Result<(), ()> {
    match is_quit_command(&line) {
        true => {
            console.send(ConsoleEvent::Info("Goodbye!".to_string())).ok();
            Err(())  // Signal to stop iteration
        }
        false => {
            send_message(stream, &line)
                .map_err(|e| {
                    console.send(ConsoleEvent::Info(
                        format!("Failed to send message: {}", e)
                    )).ok();
                    // map_err converts io::Error to (), signaling iteration stop
                })
                .and_then(|_| {
                    console.send(ConsoleEvent::Prompt).ok();
                    Ok(())  // Continue iteration
                })
        }
    }
}

/// Main message loop - reads user input and sends to server
///
/// Uses iterator combinators to build a processing pipeline:
///
/// 1. map_while: Stop if shutdown signal received
/// 2. filter_map: Extract Ok values, skip errors
/// 3. map: Trim whitespace
/// 4. filter: Skip empty lines
/// 5. try_for_each: Process each line, stop on error
///
/// This is very similar to F# pipeline operators (|>)
fn run_message_loop(
    mut stream: TcpStream,
    console: Sender<ConsoleEvent>,
    shutdown_rx: Receiver<()>,
) {
    stdin()
        .lines()  // Iterator over lines from stdin
        // Continue while shutdown signal NOT received
        .map_while(|line| shutdown_rx.try_recv().is_err().then(|| line))
        // Convert Result<String> to Option<String>, keeping only Ok values
        .filter_map(|line| line.ok())
        // Trim each line
        .map(|line| line.trim().to_string())
        // Skip empty lines
        .filter(|line| !line.is_empty())
        // Process each line until error (quit or send failure)
        .try_for_each(|line| process_user_message(line, &mut stream, &console))
        .ok();  // Ignore final result (we don't care if it stopped normally or on error)
}

// ============================================================
// Main entry point
// ============================================================

fn main() -> io::Result<()> {
    // ========== Connection Setup ==========

    // Get server IP from user (or use default)
    let server_ip = read_user_input("Enter server IP (e.g. 192.168.1.10): ")?;
    let server_ip = get_default_ip(&server_ip);

    // Connect to server
    let mut stream = connect_to_server(server_ip)?;

    // ========== Console Actor Setup ==========

    // Start console actor (owns stdout)
    let console = spawn_console();
    console.send(ConsoleEvent::Info(
        format!("Connected to chat server at {}:{}", server_ip, PORT)
    )).ok();

    // ========== Username Setup ==========

    // Get and send username to server
    // If this fails, exit gracefully
    if setup_username(&mut stream, &console).is_err() {
        console.send(ConsoleEvent::Exit).ok();
        return Ok(());
    }

    // ========== Thread Setup ==========

    // Create shutdown channel for reader thread to notify main thread
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    // Spawn reader thread for incoming messages
    // Clones stream for concurrent reading
    let reader = stream.try_clone()?;
    spawn_reader_thread(reader, console.clone(), shutdown_tx);

    // ========== Main Message Loop ==========

    // Show initial prompt
    console.send(ConsoleEvent::Prompt).ok();

    // Run main loop (blocks until quit or disconnect)
    run_message_loop(stream, console.clone(), shutdown_rx);

    // ========== Graceful Shutdown ==========

    // Tell console actor to exit
    console.send(ConsoleEvent::Exit).ok();

    // Give console thread time to finish displaying final messages
    thread::sleep(Duration::from_millis(300));

    Ok(())
}