use std::io::{self, stdin, stdout, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::time::Duration;

const KEY: u8 = 42;
const PORT: u16 = 5555;
const MAX_MESSAGE_SIZE: usize = 1_000_000;

// ============================================================
// Pure utility functions (no I/O, no dependencies)
// ============================================================

fn xor_transform(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

fn is_quit_command(msg: &str) -> bool {
    matches!(msg, "/quit" | "/exit")
}

fn get_default_ip(input: &str) -> &str {
    match input.trim().is_empty() {
        true => "192.168.1.10",
        false => input.trim(),
    }
}

// ============================================================
// I/O functions (depend only on utilities)
// ============================================================

fn read_message_length<R: Read>(reader: &mut R) -> io::Result<usize> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    Ok(u32::from_be_bytes(len_buf) as usize)
}

fn read_encrypted_bytes<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn receive_message<R: Read>(reader: &mut R) -> io::Result<String> {
    let len = read_message_length(reader)?;

    match len <= MAX_MESSAGE_SIZE {
        false => Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large")),
        true => {
            let encrypted = read_encrypted_bytes(reader, len)?;
            let decrypted = xor_transform(&encrypted, KEY);
            String::from_utf8(decrypted)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))
        }
    }
}

fn send_message<W: Write>(writer: &mut W, msg: &str) -> io::Result<()> {
    let encrypted = xor_transform(msg.as_bytes(), KEY);
    let len = encrypted.len() as u32;

    writer.write_all(&len.to_be_bytes())
        .and_then(|_| writer.write_all(&encrypted))
        .and_then(|_| writer.flush())
}

// ============================================================
// Console actor (message-passing concurrency)
// ============================================================

enum ConsoleEvent {
    Message(String),
    Info(String),
    Prompt,
    Exit,
}

fn handle_console_event(event: ConsoleEvent, out: &mut impl Write) {
    match event {
        ConsoleEvent::Message(msg) => {
            println!();
            println!("{}", msg);
            print!("> ");
        }
        ConsoleEvent::Info(msg) => {
            println!("\r{}", msg);
            print!("> ");
        }
        ConsoleEvent::Prompt => {
            print!("> ");
        }
        ConsoleEvent::Exit => {}
    }
    out.flush().ok();
}

fn spawn_console() -> Sender<ConsoleEvent> {
    let (tx, rx) = mpsc::channel::<ConsoleEvent>();

    thread::spawn(move || {
        let mut out = stdout();

        rx.into_iter()
            .take_while(|event| !matches!(event, ConsoleEvent::Exit))
            .for_each(|event| handle_console_event(event, &mut out));
    });

    tx
}

// ============================================================
// Reader thread (depends on receive_message)
// ============================================================

fn spawn_reader_thread(
    mut reader: TcpStream,
    console: Sender<ConsoleEvent>,
    shutdown: Sender<()>,
) {
    thread::spawn(move || {
        std::iter::from_fn(|| receive_message(&mut reader).ok())
            .for_each(|msg| {
                console.send(ConsoleEvent::Message(msg)).ok();
            });

        // Connection closed
        console.send(ConsoleEvent::Info("[Disconnected from server]".to_string())).ok();
        shutdown.send(()).ok();
    });
}

// ============================================================
// User input handling
// ============================================================

fn read_user_input(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    stdout().flush()?;

    let mut input = String::new();
    stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn validate_username(username: &str) -> Option<String> {
    match username.is_empty() {
        true => None,
        false => Some(username.to_string()),
    }
}

// ============================================================
// Connection setup
// ============================================================

fn connect_to_server(ip: &str) -> io::Result<TcpStream> {
    let address = format!("{}:{}", ip, PORT);

    TcpStream::connect(&address).map_err(|e| {
        eprintln!("Failed to connect to {}: {}", address, e);
        e
    })
}

fn setup_username(stream: &mut TcpStream, console: &Sender<ConsoleEvent>) -> io::Result<String> {
    console.send(ConsoleEvent::Info(
        "Please enter your username and press Enter:".to_string()
    )).ok();

    let username = read_user_input("")?;

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

fn process_user_message(
    line: String,
    stream: &mut TcpStream,
    console: &Sender<ConsoleEvent>,
) -> Result<(), ()> {
    match is_quit_command(&line) {
        true => {
            console.send(ConsoleEvent::Info("Goodbye!".to_string())).ok();
            Err(())
        }
        false => {
            send_message(stream, &line)
                .map_err(|e| {
                    console.send(ConsoleEvent::Info(
                        format!("Failed to send message: {}", e)
                    )).ok();
                })
                .and_then(|_| {
                    console.send(ConsoleEvent::Prompt).ok();
                    Ok(())
                })
        }
    }
}

fn run_message_loop(
    mut stream: TcpStream,
    console: Sender<ConsoleEvent>,
    shutdown_rx: Receiver<()>,
) {
    stdin()
        .lines()
        .map_while(|line| shutdown_rx.try_recv().is_err().then(|| line))
        .filter_map(|line| line.ok())
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .try_for_each(|line| process_user_message(line, &mut stream, &console))
        .ok();
}

// ============================================================
// Main entry point
// ============================================================

fn main() -> io::Result<()> {
    // Get server IP
    let server_ip = read_user_input("Enter server IP (e.g. 192.168.1.10): ")?;
    let server_ip = get_default_ip(&server_ip);

    // Connect to server
    let mut stream = connect_to_server(server_ip)?;

    // Start console actor
    let console = spawn_console();
    console.send(ConsoleEvent::Info(
        format!("Connected to chat server at {}:{}", server_ip, PORT)
    )).ok();

    // Setup username
    if setup_username(&mut stream, &console).is_err() {
        console.send(ConsoleEvent::Exit).ok();
        return Ok(());
    }

    // Setup shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    // Spawn reader thread
    let reader = stream.try_clone()?;
    spawn_reader_thread(reader, console.clone(), shutdown_tx);

    // Show initial prompt
    console.send(ConsoleEvent::Prompt).ok();

    // Run main message loop
    run_message_loop(stream, console.clone(), shutdown_rx);

    // Graceful shutdown
    console.send(ConsoleEvent::Exit).ok();
    thread::sleep(Duration::from_millis(300));

    Ok(())
}