use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;

#[cfg(windows)]
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
#[cfg(windows)]
use winreg::{RegKey, HKEY};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupSource { Registry, Folder }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupEntry {
    pub name: String,
    pub path: String,
    pub source: StartupSource,
}

#[derive(Debug, Default)]
pub struct StartupReport {
    pub entries: Vec<StartupEntry>,
    pub errors: Vec<String>,
}

impl StartupReport {
    pub fn format(&self) -> String {
        let mut output = String::new();
        writeln!(&mut output, "=== Windows Startup Check ===").unwrap();
        writeln!(&mut output, "Found: {}", self.entries.len()).unwrap();

        for entry in &self.entries {
            let source = match entry.source {
                StartupSource::Registry => "Registry",
                StartupSource::Folder => "Folder",
            };
            writeln!(&mut output, "\nName: {}", entry.name).unwrap();
            writeln!(&mut output, "Path: {}", entry.path).unwrap();
            writeln!(&mut output, "Source: {}", source).unwrap();
        }

        if !self.errors.is_empty() {
            writeln!(&mut output, "\n=== Errors ===").unwrap();
            for error in &self.errors {
                writeln!(&mut output, "- {}", error).unwrap();
            }
        }
        output
    }
}

pub fn scan_startup() -> StartupReport {
    let mut report = StartupReport::default();

    #[cfg(windows)]
    {
        scan_registry(&mut report, "HKCU", HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run");
        scan_registry(&mut report, "HKLM", HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run");
        scan_registry(&mut report, "HKCU", HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce");
        scan_registry(&mut report, "HKLM", HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce");
    }

    scan_startup_folder(&mut report, "APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup");
    scan_startup_folder(&mut report, "PROGRAMDATA", r"Microsoft\Windows\Start Menu\Programs\Startup");
    report
}

#[cfg(windows)]
fn scan_registry(report: &mut StartupReport, hive_name: &str, hive: HKEY, subkey: &str) {
    let full_source = format!(r"{}\{}", hive_name, subkey);
    let root = RegKey::predef(hive);

    let key = match root.open_subkey(subkey) {
        Ok(k) => k,
        Err(e) => {
            report.errors.push(format!("Cannot open registry key {}: {}", full_source, e));
            return;
        }
    };

    let values = match key.enum_values().collect::<Result<Vec<_>, _>>() {
        Ok(v) => v,
        Err(e) => {
            report.errors.push(format!("Cannot enumerate registry key {}: {}", full_source, e));
            return;
        }
    };

    for (name, _value) in values {
        match key.get_value::<String, _>(&name) {
            Ok(path) => report.entries.push(StartupEntry { name, path, source: StartupSource::Registry }),
            Err(e) => report.errors.push(format!("Cannot read value {}\\{}: {}", full_source, name, e)),
        }
    }
}

fn scan_startup_folder(report: &mut StartupReport, env_name: &str, relative_path: &str) {
    let base = match env::var_os(env_name) {
        Some(v) => v,
        None => {
            report.errors.push(format!("Environment variable {} is not set", env_name));
            return;
        }
    };

    let folder = Path::new(&base).join(relative_path);
    let entries = match fs::read_dir(&folder) {
        Ok(e) => e,
        Err(e) => {
            report.errors.push(format!("Cannot read startup folder {}: {}", folder.display(), e));
            return;
        }
    };

    for item in entries {
        if let Ok(item) = item {
            let path = item.path();
            let name = item.file_name().to_string_lossy().into_owned();
            report.entries.push(StartupEntry { name, path: path.to_string_lossy().into_owned(), source: StartupSource::Folder });
        }
    }
}