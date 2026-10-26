use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;

pub fn check_hosts_file() -> Vec<String> {
    let mut warnings = Vec::new();
    let path = Path::new(r"C:\Windows\System32\drivers\etc\hosts");

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return warnings,
    };

    let reader = BufReader::new(file);
    let suspicious_domains = ["google.com", "microsoft.com", "kaspersky.com", "virustotal.com"];
    let target_ips = ["127.0.0.1", "0.0.0.0"];

    for line_res in reader.lines() {
        if let Ok(line) = line_res {
            let line_content = match line.split_once('#') {
                Some((content, _)) => content,
                None => &line,
            };
            let trimmed = line_content.trim();
            if trimmed.is_empty() { continue; }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 { continue; }

            let ip = parts[0];
            if target_ips.contains(&ip) {
                for domain in &parts[1..] {
                    let domain_lower = domain.to_lowercase();
                    let is_match = suspicious_domains.iter().any(|&d| {
                        domain_lower == d || domain_lower.ends_with(&format!(".{}", d))
                    });
                    if is_match {
                        warnings.push(format!("⚠ Подозрительная запись в HOSTS: [{}]", trimmed));
                        break;
                    }
                }
            }
        }
    }
    warnings
}

pub fn check_windows_defender() -> String {
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", "(Get-MpComputerStatus).AntivirusEnabled"])
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                let result_str = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
                if result_str == "true" { "🟢 Defender активен".to_string() }
                else if result_str == "false" { "🔴 Defender ОТКЛЮЧЕН!".to_string() }
                else { format!("⚠ Не удалось определить статус: {}", result_str) }
            } else {
                "🔴 Defender ОТКЛЮЧЕН! (Ошибка PowerShell)".to_string()
            }
        }
        Err(_) => "⚠ Ошибка при запуске PowerShell".to_string(),
    }
}