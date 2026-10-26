use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::path::Path;

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn key_to_hex(key: &[u8; 32]) -> String {
    hex::encode(key)
}

pub fn hex_to_key(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Ошибка hex: {}", e))?;
    if bytes.len() != 32 { return Err("Неверная длина ключа".to_string()); }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn encrypt_file(input_path: &Path, output_path: &Path, key: &[u8; 32]) -> Result<(), String> {
    let plaintext = fs::read(input_path).map_err(|e| format!("Ошибка чтения: {}", e))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|e| format!("Ошибка шифрования: {}", e))?;
    
    let mut output_data = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    output_data.extend_from_slice(&nonce_bytes);
    output_data.extend_from_slice(&ciphertext);
    fs::write(output_path, output_data).map_err(|e| format!("Ошибка записи: {}", e))?;
    Ok(())
}

pub fn decrypt_file(input_path: &Path, output_path: &Path, key: &[u8; 32]) -> Result<(), String> {
    let data = fs::read(input_path).map_err(|e| format!("Ошибка чтения: {}", e))?;
    if data.len() < 12 { return Err("Файл поврежден".to_string()); }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Ошибка расшифровки: {}", e))?;
    fs::write(output_path, plaintext).map_err(|e| format!("Ошибка записи: {}", e))?;
    Ok(())
}