use std::fs;
use std::io::{Cursor, Read};
use std::path::{Component, Path};
use std::time::Duration;

use zip::ZipArchive;

const RULES_URL: &str = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip";
const RULES_DIR: &str = "rules";
const MAX_ARCHIVE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_RULE_FILE_BYTES: u64 = 10 * 1024 * 1024;

pub fn update_yara_rules() -> Result<usize, String> {
    let archive_bytes = download_archive()?;
    extract_rules(archive_bytes, Path::new(RULES_DIR))
}

fn download_archive() -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("aisec/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|e| format!("Не удалось создать HTTP-клиент: {e}"))?;

    let response = client.get(RULES_URL).send().map_err(|e| {
        if e.is_timeout() {
            "Превышено время ожидания ответа от GitHub.".to_string()
        } else if e.is_connect() {
            "Не удалось подключиться к GitHub.".to_string()
        } else {
            format!("Ошибка сети: {e}")
        }
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("GitHub вернул ошибку: HTTP {status}"));
    }

    let mut buf = Vec::new();
    response.take(MAX_ARCHIVE_BYTES + 1).read_to_end(&mut buf).map_err(|e| format!("Ошибка скачивания: {e}"))?;

    if buf.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(format!("Архив больше {} МБ, отменено.", MAX_ARCHIVE_BYTES / 1024 / 1024));
    }
    Ok(buf)
}

fn extract_rules(archive_bytes: Vec<u8>, out_dir: &Path) -> Result<usize, String> {
    let mut archive = ZipArchive::new(Cursor::new(archive_bytes)).map_err(|e| format!("Неверный ZIP: {e}"))?;
    fs::create_dir_all(out_dir).map_err(|e| format!("Не удалось создать папку: {e}"))?;
    let mut saved = 0usize;

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) { Ok(e) => e, Err(_) => continue };
        if !entry.is_file() { continue; }

        let Some(rel_path) = entry.enclosed_name() else { continue };
        let Some(file_name) = flat_file_name(&rel_path) else { continue };

        let mut content = Vec::new();
        if entry.by_ref().take(MAX_RULE_FILE_BYTES + 1).read_to_end(&mut content).is_err() { continue; }
        if content.len() as u64 > MAX_RULE_FILE_BYTES { continue; }

        if fs::write(out_dir.join(&file_name), &content).is_ok() { saved += 1; }
    }

    if saved == 0 { Err("В архиве не найдено .yar/.yara файлов.".to_string()) } else { Ok(saved) }
}

fn flat_file_name(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    if ext != "yar" && ext != "yara" { return None; }

    let parts: Vec<&str> = path.components().filter_map(|c| match c {
        Component::Normal(s) => s.to_str(), _ => None
    }).collect();

    if parts.len() < 3 { return None; }

    let dirs = parts[1..parts.len() - 1].join("_");
    let file = parts[parts.len() - 1];
    Some(sanitize(&format!("{dirs}_{file}")))
}

fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' }).collect()
}