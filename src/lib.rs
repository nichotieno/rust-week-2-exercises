use hex::{decode, encode};

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

// Reverse the byte order of input slice and return as Vec<u8>
pub fn to_big_endian(bytes: &[u8]) -> Vec<u8> {
    let mut reversed_bytes = bytes.to_vec();
    reversed_bytes.reverse();
    reversed_bytes
}


//Implement conversion of bytes slice to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
         .map(|byte| format!("{:02x}", byte))
         .collect()
}

//Implement conversion of hex string to bytes vector
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

//Implement little-endian byte swap for u32
pub fn swap_endian_u32(num: u32) -> [u8; 4] {
    num.swap_bytes().to_be_bytes()
}

//Parse input string to u64, return error string if invalid
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

    // Validate characters
    for c in integer_part_str.chars() {
        if !c.is_ascii_digit() {
            return Err(format!("Invalid character found in amount: '{}'", c));
        }
    }
    for c in fractional_part_str.chars() {
        if !c.is_ascii_digit() {
            return Err(format!("Invalid character found in amount: '{}'", c));
        }
    }

    if fractional_part_str.len() > 8 {
        return Err("Too many decimal places (max 8 supported).".to_string());
    }

    let mut total_satoshis: u64 = 0;

    // Parse integer part
    if !integer_part_str.is_empty() {
        let integer_btc = integer_part_str
            .parse::<u64>()
            .map_err(|_| "Invalid number format.".to_string())?;

        // Check for overflow before multiplication
        if integer_btc > u64::MAX / 100_000_000 {
            return Err("Value too large.".to_string());
        }
        total_satoshis = integer_btc * 100_000_000;
    }

    // Parse fractional part
    if !fractional_part_str.is_empty() {
        let mut fractional_btc = fractional_part_str
            .parse::<u64>()
            .map_err(|_| "Invalid number format.".to_string())?;

        let num_zeros_to_pad = 8 - fractional_part_str.len();
        for _ in 0..num_zeros_to_pad {
            fractional_btc *= 10;
        }

        // Check for overflow before addition
        if u64::MAX - total_satoshis < fractional_btc {
            return Err("Value too large.".to_string());
        }
        total_satoshis += fractional_btc;
    }

    Ok(total_satoshis)
}

pub enum ScriptType {
    P2PKH,
    P2WPKH,
    Unknown,
}

// Match script pattern and return corresponding ScriptType
pub fn classify_script(script: &[u8]) -> ScriptType {
    if script.len() == 25
        && script[0] == 0x76 // OP_DUP
        && script[1] == 0xA9 // OP_HASH160
        && script[2] == 0x14 // PUSHDATA1 20 bytes
        && script[23] == 0x88 // OP_EQUALVERIFY
        && script[24] == 0xAC // OP_CHECKSIG
    {
        return ScriptType::P2PKH;
    }

    // P2WPKH script pattern: OP_0 <20-byte-pubkey-hash>
    // Hex: 00 14 {20-byte-hash}
    if script.len() == 22
        && script[0] == 0x00 // OP_0 (witness version 0)
        && script[1] == 0x14 // PUSHDATA1 20 bytes
    {
        return ScriptType::P2WPKH;
    }

    ScriptType::Unknown
}

// TODO: complete Outpoint tuple struct
pub struct Outpoint();

pub fn read_pushdata(script: &[u8]) -> &[u8] {
    // TODO: Return the pushdata portion of the script slice (assumes pushdata starts at index 2)
}

pub trait Wallet {
    fn balance(&self) -> u64;
}

pub struct TestWallet {
    pub confirmed: u64,
}

impl Wallet for TestWallet {
    fn balance(&self) -> u64 {
        // TODO: Return the wallet's confirmed balance
    }
}

pub fn apply_fee(balance: &mut u64, fee: u64) {
    // TODO: Subtract fee from mutable balance reference
}

pub fn move_txid(txid: String) -> String {
    // TODO: Return formatted string including the txid for display or logging
}

//Add necessary derive traits
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Opcode {
    OpChecksig,
    OpDup,
    OpInvalid,
}

//Implement mapping from byte to Opcode variant
impl Opcode {
    pub fn from_byte(byte: u8) -> Result<Self, String> {
        match byte {
            0xAC => Ok(Opcode::OpChecksig),
            0x76 => Ok(Opcode::OpDup),
            _ => Err(format!("Unknown opcode byte: 0x{:02x}", byte)),
        }
    }
}

// Add necessary derive traits
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UTXO {
    pub txid: Vec<u8>,
    pub vout: u32,
    pub value: u64,
}

// Implement UTXO consumption logic (if any)
pub fn consume_utxo(utxo: UTXO) -> UTXO {
    utxo
}
