use std::process::Command;

pub fn scan_wmi_and_tasks() -> Vec<String> {
    let mut suspicious = Vec::new();
    scan_wmi_command("wmic", &["/namespace:\\root\\subscription", "PATH", "__EventFilter", "get", "*"], "WMI EventFilter", &mut suspicious);
    scan_wmi_command("wmic", &["/namespace:\\root\\subscription", "PATH", "CommandLineEventConsumer", "get", "*"], "WMI EventConsumer", &mut suspicious);
    scan_scheduled_tasks(&mut suspicious);
    suspicious
}

fn scan_wmi_command(program: &str, args: &[&str], source_name: &str, suspicious: &mut Vec<String>) {
    let output = match Command::new(program).args(args).output() { Ok(out) => out, Err(_) => return };
    if !output.status.success() { return; }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && is_suspicious_payload(trimmed) {
            suspicious.push(format!("Источник: {} | Найдено: {}", source_name, trimmed));
        }
    }
}

fn scan_scheduled_tasks(suspicious: &mut Vec<String>) {
    let output = match Command::new("schtasks").args(&["/query", "/fo", "CSV", "/v"]).output() { Ok(out) => out, Err(_) => return };
    if !output.status.success() { return; }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for (i, line) in stdout.lines().enumerate() {
        if i == 0 { continue; }
        if is_suspicious_payload(line) {
            let clean = line.replace('"', "");
            suspicious.push(format!("Источник: Schtasks | Задача: {}", clean));
        }
    }
}

fn is_suspicious_payload(text: &str) -> bool {
    let lower = text.to_lowercase();
    let bad_path = lower.contains("appdata") || lower.contains("temp") || lower.contains("programdata") || lower.contains("users\\public");
    let bad_tool = lower.contains("powershell") || lower.contains("mshta") || lower.contains("regsvr32") || lower.contains("wscript") || lower.contains("cscript") || lower.contains("certutil");
    bad_path || (bad_tool && (lower.contains("-enc") || lower.contains("-encodedcommand") || lower.contains("hidden") || lower.contains("downloadstring") || lower.contains("iex")))
}