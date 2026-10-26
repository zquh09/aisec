//! src/file_integrity.rs
//!
//! Монитор целостности файлов (FIM) для критических папок Windows.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DB_FILE_NAME: &str = "fim_db.json";
const INCLUDE_SYSTEM32: bool = false;
const SYSTEM32_EXTENSIONS: &[&str] = &["exe", "dll", "sys"];
const MAX_DEPTH: usize = 6;
const DB_VERSION: u32 = 1;

#[derive(Debug, Default, Serialize, Deserialize)]
struct FimDb {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    created_at: u64,
    #[serde(default)]
    files: BTreeMap<String, String>,
}

enum DbState {
    Empty,
    Loaded(FimDb),
    Unusable(String),
}

struct WatchTarget {
    dir: PathBuf,
    label: &'static str,
    recursive: bool,
    extensions: Option<&'static [&'static str]>,
}

#[derive(Default)]
struct Snapshot {
    files: BTreeMap<String, String>,
    errors: Vec<String>,
}

pub fn check_integrity() -> Vec<String> {
    let targets = watch_targets();
    if targets.is_empty() {
        return vec!["ℹ Не найдены папки для мониторинга (нужна Windows)".to_string()];
    }

    let db_path = db_path();
    let current = take_snapshot(&targets);
    let mut report: Vec<String> = Vec::new();

    match load_db(&db_path) {
        DbState::Empty => {
            let db = FimDb {
                version: DB_VERSION,
                created_at: now_unix(),
                files: current.files.clone(),
            };
            match save_db(&db_path, &db) {
                Ok(()) => report.push(format!(
                    "ℹ База целостности создана: {} файл(ов), {}",
                    db.files.len(),
                    db_path.display()
                )),
                Err(e) => report.push(format!(
                    "⚠ Не удалось сохранить базу целостности {}: {e}",
                    db_path.display()
                )),
            }
            report.extend(current.errors);
        }
        DbState::Loaded(db) => {
            report = compare(&db, &current, &targets);
        }
        DbState::Unusable(reason) => {
            report.push(format!(
                "⚠ База целостности недоступна или повреждена ({}): {reason}. \
                 Возможна подмена — проверьте файл вручную.",
                db_path.display()
            ));
        }
    }

    report
}

pub fn rebuild_baseline() -> Result<usize, String> {
    let targets = watch_targets();
    if targets.is_empty() {
        return Err("Не найдены папки для мониторинга".to_string());
    }

    let current = take_snapshot(&targets);
    let db = FimDb {
        version: DB_VERSION,
        created_at: now_unix(),
        files: current.files,
    };
    let path = db_path();
    save_db(&path, &db).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(db.files.len())
}

fn compare(db: &FimDb, current: &Snapshot, targets: &[WatchTarget]) -> Vec<String> {
    let mut warnings = Vec::new();

    for (path, old_hash) in &db.files {
        if !targets.iter().any(|t| Path::new(path).starts_with(&t.dir)) {
            continue;
        }

        match current.files.get(path) {
            Some(new_hash) if new_hash != old_hash => {
                warnings.push(format!("⚠ Файл изменен: {path}"));
            }
            Some(_) => {}
            None => {
                if !Path::new(path).exists() {
                    warnings.push(format!("⚠ Файл изменен: {path} (удалён)"));
                }
            }
        }
    }

    for path in current.files.keys() {
        if !db.files.contains_key(path) {
            warnings.push(format!(
                "⚠ Новый файл в {}: {path}",
                label_for(path, targets)
            ));
        }
    }

    warnings.extend(current.errors.iter().cloned());
    warnings
}

fn label_for(path: &str, targets: &[WatchTarget]) -> &'static str {
    targets
        .iter()
        .find(|t| Path::new(path).starts_with(&t.dir))
        .map(|t| t.label)
        .unwrap_or("контролируемой папке")
}

fn watch_targets() -> Vec<WatchTarget> {
    let mut targets = Vec::new();

    if let Some(appdata) = env::var_os("APPDATA") {
        targets.push(WatchTarget {
            dir: join_all(PathBuf::from(appdata), &["Microsoft", "Windows", "Start Menu", "Programs", "Startup"]),
            label: "автозагрузке",
            recursive: true,
            extensions: None,
        });
    }

    if let Some(program_data) = env::var_os("PROGRAMDATA") {
        targets.push(WatchTarget {
            dir: join_all(PathBuf::from(program_data), &["Microsoft", "Windows", "Start Menu", "Programs", "StartUp"]),
            label: "автозагрузке",
            recursive: true,
            extensions: None,
        });
    }

    if INCLUDE_SYSTEM32 {
        if let Some(root) = env::var_os("SystemRoot") {
            targets.push(WatchTarget {
                dir: PathBuf::from(root).join("System32"),
                label: "System32",
                recursive: false,
                extensions: Some(SYSTEM32_EXTENSIONS),
            });
        }
    }

    targets
}

fn join_all(mut base: PathBuf, parts: &[&str]) -> PathBuf {
    for p in parts { base.push(p); }
    base
}

fn take_snapshot(targets: &[WatchTarget]) -> Snapshot {
    let mut snap = Snapshot::default();
    for target in targets { walk_dir(&target.dir, target, 0, &mut snap); }
    snap
}

fn walk_dir(dir: &Path, target: &WatchTarget, depth: usize, snap: &mut Snapshot) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            if !(depth == 0 && e.kind() == io::ErrorKind::NotFound) {
                snap.errors.push(format!("⚠ Не удалось прочитать папку {}: {e}", dir.display()));
            }
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) => {
                snap.errors.push(format!("⚠ Не удалось получить тип {}: {e}", path.display()));
                continue;
            }
        };

        if file_type.is_dir() {
            if target.recursive && depth < MAX_DEPTH {
                walk_dir(&path, target, depth + 1, snap);
            }
        } else if file_type.is_file() && extension_allowed(&path, target.extensions) {
            match sha256_file(&path) {
                Ok(hash) => { snap.files.insert(path.to_string_lossy().into_owned(), hash); }
                Err(e) => snap.errors.push(format!("⚠ Не удалось прочитать файл: {} ({e})", path.display())),
            }
        }
    }
}

fn extension_allowed(path: &Path, allowed: Option<&[&str]>) -> bool {
    let Some(list) = allowed else { return true; };
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| list.iter().any(|a| a.eq_ignore_ascii_case(e)))
        .unwrap_or(false)
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn db_path() -> PathBuf {
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join(DB_FILE_NAME);
        }
    }
    PathBuf::from(DB_FILE_NAME)
}

fn load_db(path: &Path) -> DbState {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return DbState::Empty,
        Err(e) => return DbState::Unusable(e.to_string()),
    };

    if text.trim().is_empty() { return DbState::Empty; }

    match serde_json::from_str::<FimDb>(&text) {
        Ok(db) => DbState::Loaded(db),
        Err(e) => DbState::Unusable(e.to_string()),
    }
}

fn save_db(path: &Path, db: &FimDb) -> Result<(), String> {
    let json = serde_json::to_string_pretty(db).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e.to_string()
    })
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}