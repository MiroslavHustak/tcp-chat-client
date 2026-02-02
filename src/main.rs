use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;

/// ===============================
/// XOR Encryption (matches server)
/// ===============================

fn send_message(stream: &mut TcpStream, msg: String, key: u8) {
    let bytes: Vec<u8> = msg.into_bytes().into_iter().map(|b| b ^ key).collect();
    let len = bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).unwrap();
    stream.write_all(&bytes).unwrap();
}

fn receive_message(stream: &mut TcpStream, key: u8) -> String {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).unwrap();

    let decrypted: Vec<u8> = payload.into_iter().map(|b| b ^ key).collect();
    String::from_utf8(decrypted).unwrap()
}

/// ===============================
/// Main client
/// ===============================

fn main() {
    let key = 42;
    let mut stream = TcpStream::connect("192.168.1.10:5555").expect("Cannot connect");

    // Send username
    send_message(&mut stream, "alice".to_string(), key);

    // Reader thread
    let mut reader = stream.try_clone().unwrap();
    thread::spawn(move || loop {
        let msg = receive_message(&mut reader, key);
        println!("{}", msg);
    });

    // Writer loop
    loop {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        send_message(&mut stream, input.trim().to_string(), key);
    }
}