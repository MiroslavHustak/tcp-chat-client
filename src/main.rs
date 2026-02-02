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
// These functions are "pure" - they only transform data without
// performing I/O or modifying global state. This makes them:
// - Easy to test
// - Easy to reason about
// - Composable with other functions
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
/// Pattern matching approach (F# style) instead of if-else
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
// These functions handle input/output operations.
// They're organized in order of dependency: simpler functions first,
// more complex functions that use them later (F# style).
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
fn read_encrypted_bytes<R: Read>(reader: &mut R, len: usize)