use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file_path: String,
    pub line_number: usize,
    pub secret_type: String,
    pub masked_value: String,
    pub entropy: f64,
}

impl Finding {
    pub fn format_text(&self) -> String {
        format!(
            "[!] Файл: {} | Строка: {} | Тип: {} | Значение: {} | Энтропия: {:.2}",
            self.file_path, self.line_number, self.secret_type, self.masked_value, self.entropy
        )
    }
}

struct PatternRule {
    name: &'static str,
    regex: Regex,
    min_entropy: f64,
}

fn get_rules() -> &'static Vec<PatternRule> {
    static RULES: OnceLock<Vec<PatternRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            PatternRule { name: "AWS Access Key ID", regex: Regex::new(r"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(), min_entropy: 3.5 },
                       PatternRule { name: "AWS Secret Key", regex: Regex::new(r#"(?i)aws_secret_access_key\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?"#).unwrap(), min_entropy: 4.0 },
            PatternRule { name: "GitHub Token", regex: Regex::new(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}").unwrap(), min_entropy: 3.5 },
            PatternRule { name: "OpenAI API Key", regex: Regex::new(r"sk-[A-Za-z0-9]{48}").unwrap(), min_entropy: 4.0 },
            PatternRule { name: "Generic Password", regex: Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"]([^'"\s]{8,})['"]"#).unwrap(), min_entropy: 3.0 },
            PatternRule { name: "Email Address", regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(), min_entropy: 0.0 },
            PatternRule { name: "Credit Card", regex: Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap(), min_entropy: 2.5 },
        ]
    })
}

pub fn calculate_shannon_entropy(data: &str) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut char_counts = [0u32; 256];
    let len = data.len() as f64;
    for byte in data.bytes() { char_counts[byte as usize] += 1; }
    let mut entropy = 0.0;
    for &count in &char_counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn mask_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let len = chars.len();
    if len <= 6 { return "*".repeat(len); }
    let prefix = 3; let suffix = 3;
    let mut masked = String::new();
    masked.extend(&chars[..prefix]);
    masked.push_str(&"*".repeat(len - prefix - suffix));
    masked.extend(&chars[len - suffix..]);
    masked
}

fn is_system_path(path: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase().replace('\\', "/");
    p.starts_with("c:/windows") || p.starts_with("/system") || p.starts_with("/proc") || p.starts_with("/sys") || p.starts_with("/dev")
}

fn is_excluded(path: &Path, excludes: &[PathBuf]) -> bool {
    excludes.iter().any(|ex| path.starts_with(ex))
}

fn is_binary_extension(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        matches!(ext.to_lowercase().as_str(), "exe" | "dll" | "so" | "dylib" | "bin" | "png" | "jpg" | "jpeg" | "gif" | "zip" | "tar" | "gz" | "rar" | "7z" | "pdf" | "mp3" | "mp4" | "avi" | "mov" | "db" | "sqlite")
    } else { false }
}

fn scan_line(line: &str, file_path: &str, line_number: usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in get_rules() {
        for mat in rule.regex.find_iter(line) {
            let mut actual_secret = mat.as_str();
            if rule.name == "Generic Password" {
                if let Some(caps) = rule.regex.captures(mat.as_str()) {
                    actual_secret = caps.get(2).map_or(actual_secret, |m| m.as_str());
                }
            }
            if rule.name == "Credit Card" {
                let digits: String = actual_secret.chars().filter(|c| c.is_ascii_digit()).collect();
                if !luhn_check(&digits) { continue; }
            }
            let entropy = calculate_shannon_entropy(actual_secret);
            if rule.min_entropy > 0.0 && entropy < rule.min_entropy { continue; }
            findings.push(Finding {
                file_path: file_path.to_string(),
                line_number,
                secret_type: rule.name.to_string(),
                masked_value: mask_secret(actual_secret),
                entropy,
            });
        }
    }
    findings
}

fn luhn_check(number: &str) -> bool {
    if number.len() < 13 { return false; }
    let mut sum = 0; let mut alternate = false;
    for c in number.chars().rev() {
        if let Some(mut digit) = c.to_digit(10) {
            if alternate { digit *= 2; if digit > 9 { digit -= 9; } }
            sum += digit; alternate = !alternate;
        } else { return false; }
    }
    sum % 10 == 0
}

fn scan_file(path: &Path) -> io::Result<Vec<Finding>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut findings = Vec::new();
    let path_str = path.display().to_string();
    for (index, line_result) in reader.lines().enumerate() {
        if let Ok(line) = line_result {
            findings.extend(scan_line(&line, &path_str, index + 1));
        }
    }
    Ok(findings)
}

pub fn start_scan(target_path: PathBuf, excludes: Vec<PathBuf>, output_json: bool) -> Result<(), String> {
    if !target_path.exists() { return Err(format!("Путь не существует: {:?}", target_path)); }
    let mut files_to_scan: Vec<PathBuf> = Vec::new();

    for entry in WalkDir::new(target_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if is_system_path(path) || is_excluded(path, &excludes) { continue; }
        if path.is_file() && !is_binary_extension(path) {
            files_to_scan.push(path.to_path_buf());
        }
    }

    let all_findings: Vec<Finding> = files_to_scan.par_iter().filter_map(|p| scan_file(p).ok()).flatten().collect();

    if output_json {
        println!("{}", serde_json::to_string_pretty(&all_findings).unwrap_or_default());
    } else if all_findings.is_empty() {
        println!("Секреты не найдены.");
    } else {
        println!("Найдено {} подозрительных элементов:\n", all_findings.len());
        for f in &all_findings { println!("{}", f.format_text()); }
    }
    Ok(())
}