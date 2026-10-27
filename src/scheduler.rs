use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::mpsc;
use crate::config::{self, AppConfig};
use crate::hash_scanner;
use crate::full_scan;

pub fn should_run_scheduled_scan(config: &AppConfig) -> bool {
    if config.scan_schedule_days == 0 { return false; }
    
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let elapsed = current_time.saturating_sub(config.last_scan_timestamp);
    let schedule_secs = config.scan_schedule_days * 24 * 60 * 60;
    
    elapsed >= schedule_secs
}

pub fn start_scheduler(config: Arc<Mutex<AppConfig>>) {
    let config_clone = Arc::clone(&config);
    thread::spawn(move || {
        loop {
            thread::sleep(std::time::Duration::from_secs(300)); // 5 минут
            
            let should_scan = {
                let cfg = config_clone.lock().unwrap();
                should_run_scheduled_scan(&cfg)
            };
            
            if should_scan {
                let db = hash_scanner::load_db();
                let (tx, _rx) = mpsc::channel();
                
                // Запускаем сканирование диска C
                let _ = full_scan::scan_system_path("C:\\", &db, tx);
                
                // Обновляем время
                let mut cfg = config_clone.lock().unwrap();
                cfg.last_scan_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                config::save_config(&cfg);
            }
        }
    });
}