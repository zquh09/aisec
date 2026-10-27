use winreg::enums::*;
use winreg::{RegKey, HKEY};

pub fn scan_registry() -> Vec<String> {
    let mut suspicious = Vec::new();

    let run_paths = vec![
        (HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU"),
        (HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU"),
        (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM"),
        (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM"),
    ];

    for (hkey, path, hive_name) in run_paths {
        scan_run_key(hkey, path, hive_name, &mut suspicious);
    }
    scan_winlogon(&mut suspicious);
    scan_services(&mut suspicious);
    suspicious
}

fn scan_run_key(hkey: HKEY, path: &str, hive_name: &str, suspicious: &mut Vec<String>) {
    let root = RegKey::predef(hkey);
    let key = match root.open_subkey_with_flags(path, KEY_READ) { Ok(k) => k, Err(_) => return };
    for value_res in key.enum_values() {
        if let Ok((name, _)) = value_res {
            if let Ok(val_str) = key.get_value::<String, _>(&name) {
                if is_suspicious_path(&val_str) {
                    let full_path = format!("{}\\{}\\{}", hive_name, path, name);
                    suspicious.push(format!("Ключ: {} | Значение: {}", full_path, val_str));
                }
            }
        }
    }
}

fn scan_winlogon(suspicious: &mut Vec<String>) {
    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    let key = match root.open_subkey_with_flags(path, KEY_READ) { Ok(k) => k, Err(_) => return };
    for param in &["Userinit", "Shell"] {
        if let Ok(val_str) = key.get_value::<String, _>(param) {
            if is_suspicious_path(&val_str) || is_abnormal_winlogon(param, &val_str) {
                suspicious.push(format!("Ключ: HKLM\\{}\\{} | Значение: {}", path, param, val_str));
            }
        }
    }
}

fn scan_services(suspicious: &mut Vec<String>) {
    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    let services_path = "SYSTEM\\CurrentControlSet\\Services";
    let services_key = match root.open_subkey_with_flags(services_path, KEY_READ) { Ok(k) => k, Err(_) => return };
    for subkey_name in services_key.enum_keys().filter_map(Result::ok) {
        let service_path = format!("{}\\{}", services_path, subkey_name);
        if let Ok(service_key) = root.open_subkey_with_flags(&service_path, KEY_READ) {
            if let Ok(image_path) = service_key.get_value::<String, _>("ImagePath") {
                if is_suspicious_path(&image_path) {
                    suspicious.push(format!("Ключ: HKLM\\{} (ImagePath) | Значение: {}", service_path, image_path));
                }
            }
        }
    }
}

fn is_suspicious_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    let clean = lower.trim_matches('"').trim();
    clean.contains("appdata") || clean.contains("temp") || clean.contains("programdata") || clean.contains("users\\public")
}

fn is_abnormal_winlogon(param: &str, val: &str) -> bool {
    let lower = val.to_lowercase();
    if param.eq_ignore_ascii_case("shell") { !lower.contains("explorer.exe") }
    else if param.eq_ignore_ascii_case("userinit") { !lower.contains("userinit.exe") }
    else { false }
}