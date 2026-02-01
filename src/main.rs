use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;

/// Same encryption logic as server (must match!)

pub struct PlainBytes {
    bytes: Vec<u8>,
    pos: usize,
}

pub struct EncryptedBytes {
    bytes: Vec<u8>,
    pos: usize,
    key: u8,
}

impl PlainBytes {
    pub fn encrypt(self, key: u8) -> EncryptedBytes {
        EncryptedBytes {
            bytes: self.bytes,
            pos: 0,
            key,
        }
    }
}

impl EncryptedBytes {
    pub fn read_all(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for b in self.bytes.drain(..) {
            out.push(b ^ self.key);
        }
        out
    }
}

fn encrypt_string(s: String, key: u8) -> Vec<u8> {
    PlainBytes {
        bytes: s.into_bytes(),
        pos: 0,
    }
        .encrypt(key)
        .read_all()
}

fn decrypt_bytes(bytes: Vec<u8>, key: u8) -> String {
    let decrypted: Vec<u8> = bytes.into_iter().map(|b| b ^ key).collect();
    String::from_utf8(decrypted).unwrap()
}

fn main() {
    let key = 42;
    let mut stream = TcpStream::connect("127.0.0.1:7878")
        .expect("Cannot connect");

    // Send username
    let username = encrypt_string("alice".to_string(), key);
    stream.write_all(&username).unwrap();

    // Reader thread
    let mut reader = stream.try_clone().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            if let Ok(size) = reader.read(&mut buf) {
                if size > 0 {
                    let msg = decrypt_bytes(buf[..size].to_vec(), key);
                    println!("{}", msg);
                }
            }
        }
    });

    // Send messages
    loop {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let encrypted = encrypt_string(input.trim().to_string(), key);
        stream.write_all(&encrypted).unwrap();
    }
}