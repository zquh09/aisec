use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::UNIX_EPOCH;

const CACHE_FILE: &str = "data/hash_cache.json";

#[derive(Serialize, Deserialize, Clone)]
struct CacheEntry { mtime: u64, size: u64, sha256: String }

struct CacheStore { entries: HashMap<PathBuf, CacheEntry> }

static CACHE: OnceLock<Mutex<CacheStore>> = OnceLock::new();

fn get_cache() -> &'static Mutex<CacheStore> {
    CACHE.get_or_init(|| {
        let entries = load_cache_from_disk().unwrap_or_default();
        Mutex::new(CacheStore { entries })
    })
}

fn load_cache_from_disk() -> io::Result<HashMap<PathBuf, CacheEntry>> {
    let path = Path::new(CACHE_FILE);
    if !path.exists() { return Ok(HashMap::new()); }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let entries: HashMap<PathBuf, CacheEntry> = serde_json::from_reader(reader).unwrap_or_default();
    Ok(entries)
}

pub fn save_cache() -> Result<(), String> {
    let cache = get_cache().lock().map_err(|e| e.to_string())?;
    if let Some(parent) = Path::new(CACHE_FILE).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let file = File::create(CACHE_FILE).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(file, &cache.entries).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn get_or_compute_hash(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    let size = metadata.len();
    let mtime = metadata.modified().map_err(|e| e.to_string())?
        .duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    {
        let cache = get_cache().lock().map_err(|e| e.to_string())?;
        if let Some(entry) = cache.entries.get(&canonical_path) {
            if entry.mtime == mtime && entry.size == size {
                return Ok(entry.sha256.clone());
            }
        }
    }

    let sha256 = compute_sha256(path)?;

    {
        let mut cache = get_cache().lock().map_err(|e| e.to_string())?;
        cache.entries.insert(canonical_path, CacheEntry { mtime, size, sha256: sha256.clone() });
    }
    Ok(sha256)
}

fn compute_sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}