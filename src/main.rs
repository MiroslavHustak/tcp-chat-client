// ============================================================
// Secure Chat Client
// ============================================================
// Characteristics:
// - Encrypts FULL plaintext message ("username: message")
// - Decrypts exactly ONE ciphertext per frame
// - Iterator-based receive loop
// - Pattern matching (no if-let shortcuts)
// ============================================================

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::sha256;

// ============================================================
// Utility functions
// ============================================================

fn derive_key_from_passphrase(passphrase: &str) -> secretbox::Key {
    let hash = sha256::hash(passphrase.as_bytes());
    secretbox::Key::from_slice(&hash.0)
        .expect("SHA-256 always produces 32 bytes")
}

fn read_message_length<R: Read>(reader: &mut R) -> io::Result<usize> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf) as usize)
}

fn receive_encrypted_message<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = read_message_length(reader)?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn send_encrypted_message<W: Write>(
    writer: &mut W,
    plaintext: &str,
    key: &secretbox::Key,
) -> io::Result<()> {
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(plaintext.as_bytes(), &nonce, key);

    let mut payload = nonce.0.to_vec();
    payload.extend_from_slice(&ciphertext);

    writer.write_all(&(payload.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(&payload))
        .and_then(|_| writer.flush())
}

fn decrypt_message(encrypted: &[u8], key: &secretbox::Key) -> Option<String> {
    match encrypted.len() < secretbox::NONCEBYTES {
        true => None,
        false => {
            let nonce = secretbox::Nonce::from_slice(&encrypted[..secretbox::NONCEBYTES])?;
            let ciphertext = &encrypted[secretbox::NONCEBYTES..];

            secretbox::open(ciphertext, &nonce, key)
                .ok()
                .and_then(|p| String::from_utf8(p).ok())
        }
    }
}

// ============================================================
// Main
// ============================================================

fn main() -> io::Result<()> {
    sodiumoxide::init().expect("libsodium init failed");

    println!("=== Secure Chat Client ===");

    print!("Enter encryption passphrase: ");
    io::stdout().flush()?;

    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase)?;
    let key = derive_key_from_passphrase(passphrase.trim());

    print!("Enter server IP: ");
    io::stdout().flush()?;

    let mut addr = String::new();
    io::stdin().read_line(&mut addr)?;
    let addr = format!("{}:5555", addr.trim());

    let mut stream = TcpStream::connect(addr)?;
    let mut reader = stream.try_clone().expect("clone failed");

    print!("Enter username: ");
    io::stdout().flush()?;

    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    // ===== Send encrypted username (single encrypted frame) =====
    send_encrypted_message(&mut stream, &username, &key)?;

    // ===== Reader thread =====
    let reader_key = key.clone();
    thread::spawn(move || {
        std::iter::from_fn(|| receive_encrypted_message(&mut reader).ok())
            .filter_map(|encrypted| decrypt_message(&encrypted, &reader_key))
            .for_each(|msg| println!("\n{}", msg));
    });

    // ===== Input loop =====
    let stdin = io::stdin();
    loop {
        let mut line = String::new();
        stdin.read_line(&mut line)?;

        let full = format!("{}: {}", username, line.trim());
        send_encrypted_message(&mut stream, &full, &key)?;
    }
}