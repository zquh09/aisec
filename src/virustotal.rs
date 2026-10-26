use reqwest::blocking::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct VtReport {
    pub positives: u32,
    pub total: u32,
    pub permalink: String,
}

#[derive(Debug, Deserialize)]
struct ApiResponse { data: FileData }
#[derive(Debug, Deserialize)]
struct FileData { attributes: FileAttributes }
#[derive(Debug, Deserialize)]
struct FileAttributes { last_analysis_stats: AnalysisStats }

#[derive(Debug, Default, Deserialize)]
struct AnalysisStats {
    #[serde(default)] malicious: u32,
    #[serde(default)] suspicious: u32,
    #[serde(default)] harmless: u32,
    #[serde(default)] undetected: u32,
    #[serde(default, rename = "timeout")] timeout: u32,
    #[serde(default, rename = "confirmed-timeout")] confirmed_timeout: u32,
    #[serde(default)] failure: u32,
    #[serde(default, rename = "type-unsupported")] type_unsupported: u32,
}

impl AnalysisStats {
    fn positives(&self) -> u32 { self.malicious + self.suspicious }
    fn total(&self) -> u32 {
        self.malicious + self.suspicious + self.harmless + self.undetected + self.timeout + self.confirmed_timeout + self.failure + self.type_unsupported
    }
}

pub fn check_virustotal(file_path: &Path, api_key: &str) -> Result<VtReport, String> {
    if api_key.trim().is_empty() {
        return Err("VirusTotal API-ключ не задан".to_string());
    }

    // Считаем хеш
    let mut file = File::open(file_path).map_err(|e| format!("Ошибка чтения файла: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer).map_err(|e| format!("Ошибка чтения: {e}"))?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    let hash = format!("{:x}", hasher.finalize());

    let url = format!("https://www.virustotal.com/api/v3/files/{hash}");
    let client = Client::builder().build().map_err(|e| format!("Ошибка HTTP клиента: {e}"))?;
    let response = client.get(&url).header("x-apikey", api_key.trim()).send().map_err(|e| format!("Ошибка запроса: {e}"))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err("Файл не найден в базе VirusTotal.".to_string());
    }
    if !response.status().is_success() {
        return Err(format!("VirusTotal вернул HTTP {}", response.status()));
    }

    let report: ApiResponse = response.json().map_err(|e| format!("Ошибка JSON: {e}"))?;
    let stats = report.data.attributes.last_analysis_stats;

    Ok(VtReport {
        positives: stats.positives(),
        total: stats.total(),
        permalink: format!("https://www.virustotal.com/gui/file/{hash}"),
    })
}