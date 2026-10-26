use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime};
use sha2::{Digest, Sha256};

const DB_URL: &str = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
const DB_FILE_NAME: &str = "virus_hashes.txt";
const CACHE_DURATION_HOURS: u64 = 24;

pub fn update_virus_db() -> Result<(), String> {
    let db_path = Path::new(DB_FILE_NAME);

    if let Ok(metadata) = fs::metadata(db_path) {
        if let Ok(modified) = metadata.modified() {
            let now = SystemTime::now();
            if let Ok(elapsed) = now.duration_since(modified) {
                if elapsed < Duration::from_secs(CACHE_DURATION_HOURS * 3600) {
                    return Ok(());
                }
            }
        }
    }

    let response = reqwest::blocking::get(DB_URL)
        .map_err(|e| format!("Ошибка подключения: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP ошибка: {}", response.status()));
    }

    let body = response.text().map_err(|e| format!("Ошибка чтения: {}", e))?;
    fs::write(db_path, &body).map_err(|e| format!("Ошибка записи: {}", e))?;
    Ok(())
}

pub fn load_db() -> HashSet<String> {
    let mut hashes = HashSet::new();
    let db_path = Path::new(DB_FILE_NAME);

    if !db_path.exists() { return hashes; }

    if let Ok(file_content) = fs::read_to_string(db_path) {
        for line in file_content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                hashes.insert(trimmed.to_lowercase());
            }
        }
    }
    hashes
}

pub fn check_file_hash(path: &Path, db: &HashSet<String>) -> Result<Option<String>, String> {
    if !path.exists() { return Err("Файл не найден".to_string()); }

    let mut file = fs::File::open(path).map_err(|e| format!("Не удалось открыть: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).map_err(|e| format!("Ошибка чтения: {}", e))?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash_hex = format!("{:x}", hasher.finalize());
    if db.contains(&hash_hex) {
        Ok(Some(format!("Найден в базе MalwareBazaar (SHA256: {})", hash_hex)))
    } else {
        Ok(None)
    }
}