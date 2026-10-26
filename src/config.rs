use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use crate::quarantine_crypto;

const CONFIG_FILE_NAME: &str = "config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub scan_path: String,
    pub watcher_path: String,
    pub theme: String,
    #[serde(default)]
    pub vt_api_key: String,
    #[serde(default)]
    pub quarantine_key: String,
    #[serde(default)]
    pub whitelist: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let key_bytes = quarantine_crypto::generate_key();
        let key_hex = quarantine_crypto::key_to_hex(&key_bytes);
        Self {
            scan_path: String::from("."),
            watcher_path: String::new(),
            theme: String::from("dark"),
            vt_api_key: String::new(),
            quarantine_key: key_hex,
            whitelist: Vec::new(),
        }
    }
}

pub fn load_config() -> AppConfig {
    let config_path = Path::new(CONFIG_FILE_NAME);
    if !config_path.exists() {
        let def = AppConfig::default();
        save_config(&def);
        return def;
    }
    match fs::read_to_string(config_path) {
        Ok(contents) => {
            let mut cfg: AppConfig = serde_json::from_str(&contents).unwrap_or_default();
            if cfg.quarantine_key.is_empty() {
                let key_bytes = quarantine_crypto::generate_key();
                cfg.quarantine_key = quarantine_crypto::key_to_hex(&key_bytes);
                save_config(&cfg);
            }
            cfg
        },
        Err(_) => AppConfig::default(),
    }
}

pub fn save_config(config: &AppConfig) {
    if let Ok(json_string) = serde_json::to_string_pretty(config) {
        let _ = fs::write(CONFIG_FILE_NAME, json_string);
    }
}

pub fn is_whitelisted(path: &Path, whitelist: &[String]) -> bool {
    if whitelist.is_empty() { return false; }
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    for entry in whitelist {
        let entry = entry.trim();
        if entry.is_empty() { continue; }
        let wl_path = Path::new(entry);
        let wl_canonical = wl_path.canonicalize().unwrap_or_else(|_| wl_path.to_path_buf());
        if canonical.starts_with(&wl_canonical) { return true; }
    }
    false
}