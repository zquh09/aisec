use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const CONFIG_FILE_NAME: &str = "config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub scan_path: String,
    pub watcher_path: String,
    pub theme: String,
    #[serde(default)]
    pub vt_api_key: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            scan_path: String::from("."),
            watcher_path: String::new(),
            theme: String::from("dark"),
            vt_api_key: String::new(),
        }
    }
}

pub fn load_config() -> AppConfig {
    let config_path = Path::new(CONFIG_FILE_NAME);
    if !config_path.exists() {
        return AppConfig::default();
    }
    match fs::read_to_string(config_path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => AppConfig::default(),
    }
}

pub fn save_config(config: &AppConfig) {
    if let Ok(json_string) = serde_json::to_string_pretty(config) {
        let _ = fs::write(CONFIG_FILE_NAME, json_string);
    }
}