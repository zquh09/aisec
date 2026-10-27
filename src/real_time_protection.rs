use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use yara_x::Rules;
use crate::{crack_detector, hash_scanner, quarantine, yara_scanner, rtp_filter, notifications};

const MONITORED_EXTENSIONS: &[&str] = &["exe", "dll", "bat", "ps1", "vbs"];
const FILE_SETTLE_DELAY: Duration = Duration::from_secs(2);

pub fn start_rtp(key: String, db: HashSet<String>, rules: Option<Arc<Rules>>, whitelist: Vec<String>, tx: Sender<String>) -> Result<RecommendedWatcher, String> {
    let whitelist = Arc::new(whitelist);
    let key = Arc::new(key);
    let db = Arc::new(db);
    let in_flight: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
    let (event_tx, event_rx) = std::sync::mpsc::channel::<Event>();

    let mut watcher = RecommendedWatcher::new(
        move |res| { if let Ok(event) = res { let _ = event_tx.send(event); } },
        Config::default(),
    ).map_err(|e| format!("Ошибка watcher: {}", e))?;

    for dir in monitored_dirs() { let _ = watcher.watch(&dir, RecursiveMode::Recursive); }

    thread::Builder::new().name("aisec-rtp".into()).spawn(move || {
        for event in event_rx.iter() {
            handle_event(event, &key, &db, &rules, &whitelist, &in_flight, &tx);
        }
    }).map_err(|e| format!("Ошибка потока RTP: {}", e))?;
    Ok(watcher)
}

fn handle_event(event: Event, key: &Arc<String>, db: &Arc<HashSet<String>>, rules: &Option<Arc<Rules>>, whitelist: &Arc<Vec<String>>, in_flight: &Arc<Mutex<HashSet<PathBuf>>>, tx: &Sender<String>) {
    if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) { return; }
    for path in event.paths {
        if !is_monitored_file(&path) { continue; }
        if !rtp_filter::should_scan(&path) { continue; }
        {
            let mut guard = match in_flight.lock() { Ok(g) => g, Err(_) => continue };
            if !guard.insert(path.clone()) { continue; }
        }
        let path_clone = path.clone();
        let key = Arc::clone(key);
        let db = Arc::clone(db);
        let rules = rules.clone();
        let whitelist = Arc::clone(whitelist);
        let in_flight = Arc::clone(in_flight);
        let tx = tx.clone();

        thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { 
                process_file(&path_clone, &key, &db, &rules, &whitelist, &tx); 
            }));
            if let Ok(mut g) = in_flight.lock() { g.remove(&path_clone); }
        });
    }
}

fn process_file(path: &Path, key: &str, db: &HashSet<String>, rules: &Option<Arc<Rules>>, whitelist: &[String], tx: &Sender<String>) {
    thread::sleep(FILE_SETTLE_DELAY);
    if !path.exists() { return; }
    let file_name = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "<unknown>".into());

    let path_str = path.to_string_lossy().to_lowercase();
    if whitelist.iter().any(|e| path_str.contains(&e.to_lowercase())) { return; }

    if let Ok(Some(reason)) = hash_scanner::check_file_hash(path, db) {
        block_file(path, &file_name, &format!("Хеш в базе: {}", reason), key, tx);
        return;
    }
    if let Some(r) = rules {
        if let Ok(hits) = yara_scanner::scan_with_yara(path, r) {
            if !hits.is_empty() {
                block_file(path, &file_name, &format!("YARA: {}", hits.join(", ")), key, tx);
                return;
            }
        }
    }
    if let Ok(report) = crack_detector::analyze_file(path) {
        if report.verdict == crack_detector::Verdict::Suspicious {
            block_file(path, &file_name, "Подозрительное поведение", key, tx);
            return;
        }
    }
}

fn block_file(path: &Path, file_name: &str, reason: &str, key: &str, tx: &Sender<String>) {
    // Логируем угрозу в историю (SQLite)
    crate::threat_history::log_threat(
        &path.to_string_lossy(),
        reason,
        "quarantined",
        "",
    );

    if let Ok(_) = quarantine::move_to_quarantine(path, key) {
        notifications::notify_threat(file_name, reason);
        let msg = format!("🛡 ЗАБЛОКИРОВАН: {} | Причина: {}", file_name, reason);
        let _ = tx.send(msg);
    }
}

fn monitored_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join("Downloads"));
        dirs.push(home.join("Desktop"));
        dirs.push(home.join("AppData").join("Local").join("Temp"));
        dirs.push(home.join("AppData").join("Roaming").join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Startup"));
    }
    dirs.into_iter().filter(|p| p.is_dir()).collect()
}

fn is_monitored_file(path: &Path) -> bool {
    if !path.is_file() { return false; }
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => MONITORED_EXTENSIONS.iter().any(|m| *m == ext.to_ascii_lowercase()),
        None => false,
    }
}