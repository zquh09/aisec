use crate::cloud_db::{CloudPaths, HashDb};
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

static DB: OnceLock<HashDb> = OnceLock::new();

fn get_db() -> &'static HashDb {
    DB.get_or_init(|| {
        let root = std::env::current_dir().unwrap_or_default();
        let paths = CloudPaths::new(&root);
        HashDb::load(paths).unwrap_or_else(|_| HashDb::empty(CloudPaths::new(&root)))
    })
}

/// Обновляет облачную базу MalwareBazaar (кнопка «Обновить базу»)
pub fn update_virus_db() -> Result<(), String> {
    get_db().update_now().map(|_| ())
}

/// Заглушка для совместимости со старым кодом (возвращает пустой HashSet)
pub fn load_db() -> HashSet<String> {
    HashSet::new()
}

pub fn check_file_hash(path: &Path, _db: &HashSet<String>) -> Result<Option<String>, String> {
    let hash_hex = crate::hash_cache::get_or_compute_hash(path)?;
    if get_db().contains(&hash_hex) {
        Ok(Some("Найден в базе MalwareBazaar".to_string()))
    } else {
        Ok(None)
    }
}