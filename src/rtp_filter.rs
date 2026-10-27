use std::path::{Path, PathBuf};

const MIN_FILE_SIZE: u64 = 1024;
const SYSTEM_DIRECTORIES: &[&str] = &[
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\WinSxS",
];
const QUARANTINE_DIRECTORY: &str = "AISEC_Quarantine";

pub fn should_scan(path: &Path) -> bool {
    if is_in_quarantine(path) { return false; }
    if is_in_system_directory(path) { return false; }
    
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.is_file() && metadata.len() < MIN_FILE_SIZE {
            return false;
        }
    }
    if is_microsoft_signed(path) { return false; }
    true
}

pub fn is_critical_zone(path: &Path) -> bool {
    if is_in_system_directory(path) { return true; }
    is_in_startup_directory(path)
}

fn is_in_system_directory(path: &Path) -> bool {
    let normalized_path = normalize_windows_path(path);
    SYSTEM_DIRECTORIES.iter().any(|directory| {
        let normalized_directory = normalize_windows_path(Path::new(directory));
        is_same_or_child_path(&normalized_path, &normalized_directory)
    })
}

fn is_in_quarantine(path: &Path) -> bool {
    path.components().any(|component| {
        component.as_os_str().to_string_lossy().eq_ignore_ascii_case(QUARANTINE_DIRECTORY)
    })
}

fn is_in_startup_directory(path: &Path) -> bool {
    let startup_suffix = Path::new(r"Microsoft\Windows\Start Menu\Programs\Startup");
    if let Some(app_data) = std::env::var_os("APPDATA") {
        let startup_path = PathBuf::from(app_data).join(startup_suffix);
        if is_same_or_child_path(&normalize_windows_path(path), &normalize_windows_path(&startup_path)) { return true; }
    }
    if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
        let startup_path = PathBuf::from(program_data).join(startup_suffix);
        if is_same_or_child_path(&normalize_windows_path(path), &normalize_windows_path(&startup_path)) { return true; }
    }
    false
}

fn normalize_windows_path(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase()
}

fn is_same_or_child_path(path: &str, directory: &str) -> bool {
    path == directory || path.strip_prefix(directory).is_some_and(|suffix| suffix.starts_with('\\'))
}

fn is_microsoft_signed(path: &Path) -> bool {
    if let crate::signature_check::SignatureStatus::Valid(signer) = crate::signature_check::check_signature(path) {
        signer.to_lowercase().contains("microsoft")
    } else {
        false
    }
}