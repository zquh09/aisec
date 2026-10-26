use std::fs;
use std::path::{Path, PathBuf};
use crate::quarantine_crypto;

pub const QUARANTINE_DIR: &str = "AISEC_Quarantine";

pub fn init_quarantine() {
    let _ = fs::create_dir_all(QUARANTINE_DIR);
}

pub fn move_to_quarantine(file_path: &Path, key_hex: &str) -> Result<PathBuf, String> {
    init_quarantine();
    let key = quarantine_crypto::hex_to_key(key_hex)?;
    
    let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
    let dest_path = Path::new(QUARANTINE_DIR).join(format!("{}.quarantine", file_name));
    
    quarantine_crypto::encrypt_file(file_path, &dest_path, &key)?;
    let _ = fs::remove_file(file_path); // Удаляем оригинал только после шифрования
    Ok(dest_path)
}

pub fn restore_from_quarantine(quarantine_path: &Path, original_dir: &Path, key_hex: &str) -> Result<PathBuf, String> {
    let key = quarantine_crypto::hex_to_key(key_hex)?;
    let file_name = quarantine_path.file_stem().and_then(|n| n.to_str()).unwrap_or("restored_file");
    let dest_path = original_dir.join(file_name);
    
    quarantine_crypto::decrypt_file(quarantine_path, &dest_path, &key)?;
    let _ = fs::remove_file(quarantine_path);
    Ok(dest_path)
}