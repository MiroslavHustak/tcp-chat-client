// ============================================================
// Secure Chat Client
// ============================================================
// Characteristics:
// - Encrypts FULL plaintext message ("username: message")
// - Decrypts exactly ONE ciphertext per frame
// - Iterator-based receive loop
// - Pattern matching (no if-let shortcuts)
// - Argon2 key derivation with salt received from server
// ============================================================

// cargo build --release

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::thread;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::pwhash;

// ============================================================
// Utility functions
// ============================================================

/// Derives a secretbox key from a passphrase and a salt using Argon2id.
///
/// The salt is received from the server in plaintext at the very start
/// of the connection, before any encrypted traffic begins.
/// Salt does not need to be secret — its purpose is to ensure that
/// even identical passphrases produce different keys per deployment.
fn derive_key_from_passphrase(passphrase: &str, salt: &pwhash::Salt) -> secretbox::Key {
    let mut key_bytes = [0u8; secretbox::KEYBYTES];

    pwhash::derive_key(
        &mut key_bytes,
        passphrase.as_bytes(),
        salt,
        pwhash::OPSLIMIT_INTERACTIVE, // ~0.5 seconds on modern hardware
        pwhash::MEMLIMIT_INTERACTIVE, // ~64 MB RAM — too costly to brute-force
    )
        .expect("Argon2 key derivation failed");

    secretbox::Key(key_bytes)
}

/// Receives the raw salt bytes sent by the server in plaintext.
/// This must be the very first thing read from the connection.
fn receive_salt<R: Read>(reader: &mut R) -> io::Result<pwhash::Salt> {
    let mut buf = [0u8; pwhash::SALTBYTES];
    reader.read_exact(&mut buf)?;
    Ok(pwhash::Salt(buf))
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

    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
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
    let passphrase = passphrase.trim().to_string();

    print!("Enter server address (host:port): ");
    io::stdout().flush()?;
    let mut addr = String::new();
    io::stdin().read_line(&mut addr)?;
    let addr = addr.trim().to_string();

    let mut stream = TcpStream::connect(&addr)?;

    // ===== Receive salt from server before doing anything else =====
    // The server sends its random salt in plaintext so both sides
    // can derive the same Argon2 key from the shared passphrase.
    println!("Receiving salt from server...");
    let salt = receive_salt(&mut stream)?;

    println!("Deriving key (Argon2id)...");
    let key = derive_key_from_passphrase(&passphrase, &salt);
    println!("Key ready.");

    let mut reader = stream.try_clone().expect("clone failed");

    print!("Enter username: ");
    io::stdout().flush()?;

    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    // ===== Send encrypted username =====
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