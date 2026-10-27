use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const DB_PATH: &str = "data/threat_history.db";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatRecord {
    pub id: i64,
    pub file_path: String,
    pub threat_type: String,
    pub action: String,
    pub sha256: String,
    pub timestamp: i64,
}

fn get_connection() -> Result<Connection> {
    if let Some(parent) = Path::new(DB_PATH).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }

    let conn = Connection::open(DB_PATH)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            action TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(conn)
}

pub fn log_threat(path: &str, threat_type: &str, action: &str, sha256: &str) {
    let conn = match get_connection() {
        Ok(c) => c,
        Err(e) => { eprintln!("[ThreatHistory] DB error: {}", e); return; }
    };

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;

    let _ = conn.execute(
        "INSERT INTO threats (file_path, threat_type, action, sha256, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![path, threat_type, action, sha256, timestamp],
    );
}

pub fn get_history(limit: usize) -> Vec<ThreatRecord> {
    let conn = match get_connection() {
        Ok(c) => c,
        Err(e) => { eprintln!("[ThreatHistory] DB error: {}", e); return Vec::new(); }
    };

    let mut stmt = match conn.prepare(
        "SELECT id, file_path, threat_type, action, sha256, timestamp FROM threats ORDER BY timestamp DESC LIMIT ?1"
    ) {
        Ok(s) => s,
        Err(e) => { eprintln!("[ThreatHistory] Prepare error: {}", e); return Vec::new(); }
    };

    let record_iter = match stmt.query_map(params![limit as i64], |row| {
        Ok(ThreatRecord {
            id: row.get(0)?,
            file_path: row.get(1)?,
            threat_type: row.get(2)?,
            action: row.get(3)?,
            sha256: row.get(4)?,
            timestamp: row.get(5)?,
        })
    }) {
        Ok(iter) => iter,
        Err(e) => { eprintln!("[ThreatHistory] Query error: {}", e); return Vec::new(); }
    };

    let mut records = Vec::new();
    for record in record_iter.flatten() {
        records.push(record);
    }
    records
}

pub fn clear_old_history(days: u64) {
    let conn = match get_connection() {
        Ok(c) => c,
        Err(e) => { eprintln!("[ThreatHistory] DB error: {}", e); return; }
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let cutoff = now - (days as i64 * 24 * 60 * 60);

    let _ = conn.execute("DELETE FROM threats WHERE timestamp < ?1", params![cutoff]);
}