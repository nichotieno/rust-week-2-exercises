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

pub fn swap_endian_u32(num: u32) -> [u8; 4] {
    // TODO: Implement little-endian byte swap for u32
}

pub fn parse_satoshis(input: &str) -> Result<u64, String> {
    // TODO: Parse input string to u64, return error string if invalid
}

pub enum ScriptType {
    P2PKH,
    P2WPKH,
    Unknown,
}

pub fn classify_script(script: &[u8]) -> ScriptType {
    // TODO: Match script pattern and return corresponding ScriptType
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

// TODO: Add necessary derive traits
pub enum Opcode {
    OpChecksig,
    OpDup,
    OpInvalid,
}

impl Opcode {
    pub fn from_byte(byte: u8) -> Result<Self, String> {
        // TODO: Implement mapping from byte to Opcode variant
    }
}

// TODO: Add necessary derive traits
pub struct UTXO {
    pub txid: Vec<u8>,
    pub vout: u32,
    pub value: u64,
}

pub fn consume_utxo(utxo: UTXO) -> UTXO {
    // TODO: Implement UTXO consumption logic (if any)
}
