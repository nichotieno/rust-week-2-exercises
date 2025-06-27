// use hex::{decode, encode};

/// Decodes a hexadecimal string into a vector of bytes.
pub fn decode_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters".to_string());
    }

    let mut bytes = Vec::with_capacity(hex_str.len() / 2);

    for i in (0..hex_str.len()).step_by(2) {
        let byte_str = &hex_str[i..i + 2];
        match u8::from_str_radix(byte_str, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => return Err(format!("Invalid hex character sequence: '{}'", byte_str)),
        }
    }

    Ok(bytes)
}

/// Reverses the byte order of input slice and returns as Vec<u8>.
pub fn to_big_endian(bytes: &[u8]) -> Vec<u8> {
    let mut reversed_bytes = bytes.to_vec();
    reversed_bytes.reverse();
    reversed_bytes
}

/// Converts a slice of bytes into its hexadecimal string representation.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Decodes a hexadecimal string into a vector of bytes using the hex crate.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

/// Swaps the endianness of a u32 and returns its byte representation.
pub fn swap_endian_u32(num: u32) -> [u8; 4] {
    num.swap_bytes().to_be_bytes()
}

/// Parses a string representing a Bitcoin amount into satoshis (u64).
pub fn parse_satoshis(input: &str) -> Result<u64, String> {
    if input.is_empty() {
        return Err("Input string cannot be empty.".to_string());
    }

    let trimmed_input = input.trim();
    let parts: Vec<&str> = trimmed_input.split('.').collect();

    let (integer_part_str, fractional_part_str) = match parts.len() {
        1 => (parts[0], ""),
        2 => (parts[0], parts[1]),
        _ => return Err("Too many decimal points.".to_string()),
    };

    for c in integer_part_str.chars() {
        if !c.is_ascii_digit() {
            return Err("Invalid satoshi amount".to_string());
        }
    }
    for c in fractional_part_str.chars() {
        if !c.is_ascii_digit() {
            return Err("Invalid satoshi amount".to_string());
        }
    }

    if fractional_part_str.len() > 8 {
        return Err("Too many decimal places (max 8 supported).".to_string());
    }

    let mut total_satoshis: u64 = 0;

    if !integer_part_str.is_empty() {
        let integer_val = integer_part_str
            .parse::<u64>()
            .map_err(|_| "Invalid satoshi amount".to_string())?;

        total_satoshis = integer_val;
    }

    if !fractional_part_str.is_empty() {
        let mut fractional_val = fractional_part_str
            .parse::<u64>()
            .map_err(|_| "Invalid satoshi amount".to_string())?;

        let num_zeros_to_pad = 8 - fractional_part_str.len();
        for _ in 0..num_zeros_to_pad {
            fractional_val *= 10;
        }

        if u64::MAX - total_satoshis < fractional_val {
            return Err("Value too large.".to_string());
        }
        total_satoshis += fractional_val;
    }

    Ok(total_satoshis)
}

/// Represents the type of a Bitcoin script.
#[derive(Debug, PartialEq, Eq)]
pub enum ScriptType {
    P2PKH,
    P2WPKH,
    Unknown,
}

/// Classifies a Bitcoin script byte slice into a known ScriptType.
pub fn classify_script(script: &[u8]) -> ScriptType {
    if script.len() >= 3 && script[0] == 0x76 && script[1] == 0xA9 && script[2] == 0x14 {
        return ScriptType::P2PKH;
    }

    if script.len() >= 2 && script[0] == 0x00 && script[1] == 0x14 {
        return ScriptType::P2WPKH;
    }

    ScriptType::Unknown
}

/// Represents a Bitcoin transaction outpoint (txid and vout).
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Outpoint(pub String, pub u32);

/// Returns the pushdata portion of the script slice (assumes pushdata starts at index 2).
pub fn read_pushdata(script: &[u8]) -> &[u8] {
    if script.len() < 3 {
        return &[];
    }

    let pushdata_len_byte = script[1];
    let pushdata_length = pushdata_len_byte as usize;
    let start_index = 2;

    if start_index + pushdata_length > script.len() {
        return &[];
    }

    &script[start_index..start_index + pushdata_length]
}

/// Defines a trait for wallet balance.
pub trait Wallet {
    fn balance(&self) -> u64;
}

/// A test wallet implementation.
pub struct TestWallet {
    pub confirmed: u64,
}

impl Wallet for TestWallet {
    fn balance(&self) -> u64 {
        self.confirmed
    }
}

/// Subtracts a fee from a mutable balance.
pub fn apply_fee(balance: &mut u64, fee: u64) {
    if *balance >= fee {
        *balance -= fee;
    } else {
        eprintln!(
            "Warning: Attempted to subtract fee ({}) greater than balance ({})",
            fee, *balance
        );
        *balance = 0;
    }
}

/// Formats a transaction ID for display or logging.
pub fn move_txid(txid: String) -> String {
    format!("txid: {}", txid)
}

/// Represents Bitcoin script opcodes.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Opcode {
    OpChecksig,
    OpDup,
    OpInvalid,
}

impl Opcode {
    /// Converts a byte into an Opcode variant.
    pub fn from_byte(byte: u8) -> Result<Self, String> {
        match byte {
            0xAC => Ok(Opcode::OpChecksig),
            0x76 => Ok(Opcode::OpDup),
            _ => Err(format!("Invalid opcode: 0x{:02x}", byte)),
        }
    }
}

/// Represents an unspent transaction output (UTXO).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UTXO {
    pub txid: Vec<u8>,
    pub vout: u32,
    pub value: u64,
}

/// Simulates UTXO consumption logic (returns the UTXO as a placeholder).
pub fn consume_utxo(utxo: UTXO) -> UTXO {
    utxo
}
