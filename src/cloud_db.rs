//! Облачные базы: MalwareBazaar (abuse.ch).
//!
//! * Локальная база — текстовый файл `data/malware_hashes.txt` (один SHA-256 на строку)
//!   плюс копия в памяти (`HashSet`) для быстрых проверок.
//! * Раз в 24 часа свежие хеши докачиваются и ДОБАВЛЯЮТСЯ к локальной базе.
//! * abuse.ch требует бесплатный Auth-Key (https://auth.abuse.ch). Ключ берётся из
//!   переменной окружения `ABUSECH_AUTH_KEY` или из файла `config/abusech_auth_key.txt`.
//!
//! Все функции здесь блокирующие — вызывайте их из фоновых потоков
//! (`spawn_daily_updater` / `spawn_manual_update` делают это сами).

use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Шаблон адреса выгрузки. Старый `bazaar.abuse.ch/export/txt/sha256/recent/` отдаёт HTTP 410.
const EXPORT_URL_TEMPLATE: &str = "https://mb-api.abuse.ch/v2/files/exports/{KEY}/recent.csv";
const EXPORT_HOST: &str = "mb-api.abuse.ch";
const AUTH_KEY_ENV: &str = "ABUSECH_AUTH_KEY";

const UPDATE_INTERVAL_SECS: u64 = 24 * 60 * 60;
/// abuse.ch пересобирает «recent» каждые 5 минут и просит не качать чаще.
const MIN_FETCH_GAP_SECS: u64 = 5 * 60;
/// Как часто фоновый поток проверяет, не пора ли обновляться.
const CHECK_PERIOD: Duration = Duration::from_secs(60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;

const MISSING_KEY_MSG: &str = "Не задан Auth-Key abuse.ch. Получите бесплатный ключ на \
https://auth.abuse.ch и вставьте его в настройках (или задайте переменную ABUSECH_AUTH_KEY).";

// ───────────────────────────── пути ─────────────────────────────

#[derive(Debug, Clone)]
pub struct CloudPaths {
    /// Локальная база хешей.
    pub hashes: PathBuf,
    /// Время последнего успешного обновления.
    pub state: PathBuf,
    /// Файл с Auth-Key.
    pub key: PathBuf,
}

impl CloudPaths {
    pub fn new(root: &Path) -> Self {
        Self {
            hashes: root.join("data").join("malware_hashes.txt"),
            state: root.join("data").join("bazaar_state.json"),
            key: root.join("config").join("abusech_auth_key.txt"),
        }
    }
}

// ───────────────────────────── события и отчёт ─────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct UpdateReport {
    pub downloaded: usize,
    pub added: usize,
    pub total: usize,
}

impl fmt::Display for UpdateReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MalwareBazaar: получено {}, новых {}, всего в базе {}",
            self.downloaded, self.added, self.total
        )
    }
}

/// Сообщение из фонового потока в GUI.
#[derive(Debug, Clone)]
pub enum CloudEvent {
    Updated(UpdateReport),
    Failed(String),
}

impl CloudEvent {
    pub fn describe(&self) -> String {
        match self {
            CloudEvent::Updated(r) => format!("✔ {r}"),
            CloudEvent::Failed(e) => format!("✖ {e}"),
        }
    }
}

// ───────────────────────────── база хешей ─────────────────────────────

/// Потокобезопасный дескриптор локальной базы. `Clone` дешёвый (Arc).
#[derive(Clone)]
pub struct HashDb {
    inner: Arc<RwLock<HashSet<String>>>,
    update_lock: Arc<Mutex<()>>,
    paths: CloudPaths,
}

impl HashDb {
    pub fn empty(paths: CloudPaths) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashSet::new())),
            update_lock: Arc::new(Mutex::new(())),
            paths,
        }
    }

    /// Загружает базу с диска. Нет файла — пустая база (не ошибка).
    pub fn load(paths: CloudPaths) -> Result<Self, String> {
        let set = match fs::read_to_string(&paths.hashes) {
            Ok(text) => text
                .lines()
                .filter_map(|l| normalize_hash(l.trim()))
                .collect::<HashSet<_>>(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => HashSet::new(),
            Err(e) => {
                return Err(format!(
                    "Не удалось прочитать {}: {e}",
                    paths.hashes.display()
                ))
            }
        };
        let db = Self::empty(paths);
        *db.write() = set;
        Ok(db)
    }

    pub fn paths(&self) -> &CloudPaths {
        &self.paths
    }

    /// Есть ли SHA-256 в базе (регистр не важен).
    pub fn contains(&self, sha256: &str) -> bool {
        self.read().contains(&sha256.trim().to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Идёт ли сейчас обновление (в любом потоке).
    pub fn is_updating(&self) -> bool {
        matches!(self.update_lock.try_lock(), Err(TryLockError::WouldBlock))
    }

    fn read(&self) -> RwLockReadGuard<'_, HashSet<String>> {
        self.inner.read().unwrap_or_else(|p| p.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashSet<String>> {
        self.inner.write().unwrap_or_else(|p| p.into_inner())
    }

    /// Пора ли обновляться по расписанию (прошло ≥ 24 ч или обновлений ещё не было).
    pub fn is_due(&self) -> bool {
        match read_last_update(&self.paths.state) {
            Some(ts) => {
                let now = now_unix();
                ts > now || now - ts >= UPDATE_INTERVAL_SECS // ts > now: часы переводили назад
            }
            None => true,
        }
    }

    /// Обновляет базу, только если прошли сутки. `Ok(None)` — рано.
    pub fn update_if_due(&self) -> Result<Option<UpdateReport>, String> {
        if !self.is_due() {
            return Ok(None);
        }
        self.update_now().map(Some)
    }

    /// Принудительное обновление (кнопка в GUI).
    pub fn update_now(&self) -> Result<UpdateReport, String> {
        let _guard = match self.update_lock.try_lock() {
            Ok(g) => g,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err("Обновление уже выполняется".to_string());
            }
        };

        if let Some(ts) = read_last_update(&self.paths.state) {
            let age = now_unix().saturating_sub(ts);
            if ts <= now_unix() && age < MIN_FETCH_GAP_SECS {
                return Err(format!(
                    "База обновлена {} сек. назад; abuse.ch просит не чаще раза в 5 минут",
                    age
                ));
            }
        }

        let key = load_auth_key(&self.paths).ok_or_else(|| MISSING_KEY_MSG.to_string())?;
        let body = download_recent(&key)?;
        let fresh = parse_hashes(&body);

        // Защита от «пустого» ответа (HTML-заглушка и т.п.): базу не трогаем.
        if fresh.is_empty() {
            return Err("Ответ abuse.ch не содержит ни одного SHA-256 — база не изменена".into());
        }

        let report = self.merge_and_save(fresh)?;

        write_last_update(&self.paths.state, now_unix())
            .map_err(|e| format!("Не удалось сохранить время обновления: {e}"))?;

        Ok(report)
    }

    /// Добавляет новые хеши: сначала атомарно пишет файл, потом обновляет память.
    fn merge_and_save(&self, fresh: Vec<String>) -> Result<UpdateReport, String> {
        let downloaded = fresh.len();

        let (added, mut all): (Vec<String>, Vec<String>) = {
            let set = self.read();
            let added: Vec<String> = fresh
                .into_iter()
                .collect::<HashSet<_>>()
                .into_iter()
                .filter(|h| !set.contains(h))
                .collect();
            let all: Vec<String> = set.iter().cloned().chain(added.iter().cloned()).collect();
            (added, all)
        };
        all.sort_unstable();

        write_lines_atomic(&self.paths.hashes, &all).map_err(|e| {
            format!(
                "Не удалось записать базу {}: {e}",
                self.paths.hashes.display()
            )
        })?;

        let added_count = added.len();
        let mut set = self.write();
        set.extend(added);

        Ok(UpdateReport {
            downloaded,
            added: added_count,
            total: set.len(),
        })
    }
}

// ───────────────────────────── Auth-Key ─────────────────────────────

/// Ключ попадает в путь URL, поэтому допускаем только безопасные символы.
fn validate_key(key: &str) -> Result<&str, String> {
    let key = key.trim();
    let ok_len = (8..=128).contains(&key.len());
    let ok_chars = key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok_len && ok_chars {
        Ok(key)
    } else {
        Err("Auth-Key выглядит некорректно (ожидаются латинские буквы, цифры, '-' и '_')".into())
    }
}

/// Env-переменная имеет приоритет над файлом.
pub fn load_auth_key(paths: &CloudPaths) -> Option<String> {
    if let Ok(v) = std::env::var(AUTH_KEY_ENV) {
        if let Ok(k) = validate_key(&v) {
            return Some(k.to_string());
        }
    }
    let text = fs::read_to_string(&paths.key).ok()?;
    validate_key(&text).ok().map(str::to_string)
}

pub fn save_auth_key(paths: &CloudPaths, key: &str) -> Result<(), String> {
    let key = validate_key(key)?;
    if let Some(dir) = paths.key.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("Не удалось создать {}: {e}", dir.display()))?;
    }
    fs::write(&paths.key, key).map_err(|e| format!("Не удалось сохранить ключ: {e}"))
}

// ───────────────────────────── сеть и разбор ─────────────────────────────

fn download_recent(key: &str) -> Result<String, String> {
    let client = Client::builder()
        .user_agent(concat!("aisec/", env!("CARGO_PKG_VERSION")))
        .timeout(REQUEST_TIMEOUT)
        // Ключ лежит в URL — не ходим за редиректами на чужие хосты.
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() < 3
                && attempt.url().scheme() == "https"
                && attempt.url().host_str() == Some(EXPORT_HOST)
            {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|e| format!("Не удалось создать HTTP-клиент: {e}"))?;

    let url = EXPORT_URL_TEMPLATE.replace("{KEY}", key);

    let response = client.get(url).send().map_err(|e| {
        // without_url(): иначе ключ попадёт в текст ошибки (он часть URL).
        let e = e.without_url();
        if e.is_timeout() {
            "Превышено время ожидания ответа abuse.ch".to_string()
        } else if e.is_connect() {
            format!("Нет соединения с abuse.ch: {e}")
        } else {
            format!("Ошибка сети при обращении к abuse.ch: {e}")
        }
    })?;

    match response.status() {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            return Err("abuse.ch отклонил Auth-Key (HTTP 401/403). Проверьте ключ.".into())
        }
        StatusCode::GONE => {
            return Err("Адрес выгрузки выведен из эксплуатации (HTTP 410). Нужно обновить URL.".into())
        }
        StatusCode::TOO_MANY_REQUESTS => {
            return Err("abuse.ch: слишком много запросов (HTTP 429). Попробуйте позже.".into())
        }
        s if s.is_redirection() => {
            return Err(format!("Неожиданный редирект (HTTP {s}) — запрос остановлен"))
        }
        s if !s.is_success() => return Err(format!("abuse.ch вернул HTTP {s}")),
        _ => {}
    }

    if let Some(len) = response.content_length() {
        if len > MAX_BODY_BYTES {
            return Err(format!("Ответ слишком большой ({len} байт) — отменено"));
        }
    }

    response
        .text()
        .map_err(|e| format!("Не удалось прочитать ответ abuse.ch: {}", e.without_url()))
}

fn normalize_hash(token: &str) -> Option<String> {
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(token.to_ascii_lowercase())
    } else {
        None
    }
}

/// Достаёт SHA-256 из CSV или plain-text. Из каждой строки берётся первое
/// 64-символьное hex-поле; комментарии (`#`) и заголовки пропускаются.
pub fn parse_hashes(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let found = line
            .split([',', ';', '\t', ' '])
            .map(|t| t.trim().trim_matches('"'))
            .find_map(|t| normalize_hash(t));
        if let Some(h) = found {
            out.push(h);
        }
    }
    out
}

// ───────────────────────────── файлы ─────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_last_update(path: &Path) -> Option<u64> {
    let text = fs::read_to_string(path).ok()?;
    let json: Value = serde_json::from_str(&text).ok()?;
    json.get("last_update_unix")?.as_u64()
}

fn write_last_update(path: &Path, ts: u64) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, json!({ "last_update_unix": ts }).to_string())
}

/// Пишет во временный файл и переименовывает — при сбое старая база остаётся целой.
fn write_lines_atomic(path: &Path, lines: &[String]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("txt.tmp");
    {
        let mut w = BufWriter::new(File::create(&tmp)?);
        for line in lines {
            w.write_all(line.as_bytes())?;
            w.write_all(b"\n")?;
        }
        w.flush()?;
        w.get_ref().sync_all()?;
    }
    fs::rename(&tmp, path)
}

// ───────────────────────────── фоновые потоки ─────────────────────────────

/// Фоновый поток: при старте и затем раз в час проверяет, не прошли ли сутки,
/// и при необходимости обновляет базу. Результаты шлёт в `tx`, затем зовёт `wake`
/// (например, `ctx.request_repaint()`). Поток завершается, когда `tx` закрыт.
pub fn spawn_daily_updater<F>(
    db: HashDb,
    tx: Sender<CloudEvent>,
    wake: F,
) -> io::Result<JoinHandle<()>>
where
    F: Fn() + Send + 'static,
{
    thread::Builder::new()
        .name("bazaar-daily".into())
        .spawn(move || loop {
            let event = match db.update_if_due() {
                Ok(Some(report)) => Some(CloudEvent::Updated(report)),
                Ok(None) => None,
                Err(e) => Some(CloudEvent::Failed(e)),
            };
            if let Some(ev) = event {
                if tx.send(ev).is_err() {
                    break; // GUI закрыт
                }
                wake();
            }
            thread::sleep(CHECK_PERIOD);
        })
}

/// Разовое обновление по кнопке — тоже в отдельном потоке.
pub fn spawn_manual_update<F>(
    db: HashDb,
    tx: Sender<CloudEvent>,
    wake: F,
) -> io::Result<JoinHandle<()>>
where
    F: Fn() + Send + 'static,
{
    thread::Builder::new()
        .name("bazaar-manual".into())
        .spawn(move || {
            let event = match db.update_now() {
                Ok(report) => CloudEvent::Updated(report),
                Err(e) => CloudEvent::Failed(e),
            };
            let _ = tx.send(event);
            wake();
        })
}