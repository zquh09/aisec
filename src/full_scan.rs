use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use walkdir::{DirEntry, WalkDir};

const MAX_FILE_SIZE: u64 = 20 * 1024 * 1024;

#[cfg(windows)]
const EXCLUDED_DIRS: &[&str] = &[
    r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)",
    r"C:\$Recycle.Bin", r"C:\System Volume Information", r"C:\ProgramData",
    r"C:\Users\Andrey\AppData", r"node_modules", r".git",
];

#[cfg(windows)]
fn is_excluded(path: &Path) -> bool {
    let path_lower = path.to_string_lossy().to_lowercase();
    EXCLUDED_DIRS.iter().any(|excluded| {
        let excluded_lower = excluded.to_lowercase();
        path_lower == excluded_lower || path_lower.starts_with(&format!("{}\\", excluded_lower))
    })
}

#[cfg(not(windows))]
fn is_excluded(_path: &Path) -> bool { false }

fn should_visit(entry: &DirEntry) -> bool { !is_excluded(entry.path()) }

fn calculate_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn scan_system_path(
    root: impl AsRef<Path>,
    db: &HashSet<String>,
    tx: Sender<String>,
) {
    let root = root.as_ref();
    if !root.exists() || !root.is_dir() {
        let _ = tx.send(format!("Ошибка: путь недоступен {}", root.display()));
        return;
    }

    let _ = tx.send("▶ Сбор списка файлов...".to_string());
    let mut files: Vec<PathBuf> = Vec::new();
    
    for entry in WalkDir::new(root).follow_links(false).into_iter().filter_entry(should_visit).filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Ok(meta) = entry.metadata() {
                if meta.len() <= MAX_FILE_SIZE && meta.len() > 0 {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
    }

    let total = files.len();
    let _ = tx.send(format!("▶ Найдено {} файлов. Начинаем параллельную проверку...", total));

    let counter = std::sync::atomic::AtomicUsize::new(0);

    files.par_iter().for_each(|path| {
        let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        if let Ok(hash) = calculate_sha256(path) {
            if db.contains(&hash) {
                let _ = tx.send(format!("⚠ НАЙДЕН ВИРУС: {}", path.display()));
            }
        }
        
        if idx % 500 == 0 {
            let _ = tx.send(format!("▶ Проверено файлов: {} / {}", idx, total));
        }
    });

    let _ = tx.send("✔ Сканирование завершено.".to_string());
}