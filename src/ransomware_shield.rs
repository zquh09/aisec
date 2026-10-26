use notify::{
    Config,
    Event,
    EventKind,
    RecommendedWatcher,
    RecursiveMode,
    Watcher,
};

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::time::{Duration, Instant};

const WINDOW_DURATION: Duration = Duration::from_secs(5);
const FILE_THRESHOLD: usize = 30;
const ALERT_COOLDOWN: Duration = Duration::from_secs(5);

const MONITORED_EXTENSIONS: &[&str] = &[
    "docx", "jpg", "pdf", "txt", "zip",
];

const ALERT_MESSAGE: &str =
    "🚨 ВНИМАНИЕ! Обнаружена подозрительная активность \
     (возможен шифровальщик). Рекомендуется срочно отключить \
     интернет и проверить процессы.";

struct FileActivity {
    timestamp: Instant,
    path: PathBuf,
}

fn is_monitored_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            MONITORED_EXTENSIONS
                .iter()
                .any(|allowed| ext.eq_ignore_ascii_case(allowed))
        })
        .unwrap_or(false)
}

fn monitored_directories() -> Vec<PathBuf> {
    let mut directories = Vec::new();

    let Some(profile) = std::env::var_os("USERPROFILE") else {
        eprintln!("Ransomware Shield: переменная USERPROFILE не найдена");
        return directories;
    };

    let profile = PathBuf::from(profile);

    for name in ["Documents", "Pictures", "Desktop"] {
        let directory = profile.join(name);
        if directory.is_dir() {
            directories.push(directory);
        }
    }
    directories
}

fn record_activity(
    history: &mut VecDeque<FileActivity>,
    path: PathBuf,
    now: Instant,
) -> usize {
    while let Some(activity) = history.front() {
        if now.duration_since(activity.timestamp) >= WINDOW_DURATION {
            history.pop_front();
        } else {
            break;
        }
    }

    history.push_back(FileActivity {
        timestamp: now,
        path,
    });

    let unique_files: HashSet<&PathBuf> =
        history.iter().map(|activity| &activity.path).collect();

    unique_files.len()
}

fn extract_monitored_paths(event: &Event) -> Vec<PathBuf> {
    event
        .paths
        .iter()
        .filter(|path| is_monitored_file(path))
        .cloned()
        .collect()
}

pub fn start_ransomware_shield(
    alert_tx: Sender<String>,
) -> notify::Result<()> {
    let directories = monitored_directories();

    if directories.is_empty() {
        eprintln!(
            "Ransomware Shield: не найдены доступные каталоги \
             Documents, Pictures или Desktop"
        );
        return Ok(());
    }

    let (event_tx, event_rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(
        move |result: notify::Result<Event>| {
            let _ = event_tx.send(result);
        },
        Config::default(),
    )?;

    for directory in &directories {
        watcher.watch(directory, RecursiveMode::Recursive)?;
        println!(
            "Ransomware Shield: мониторинг {}",
            directory.display()
        );
    }

    let mut history: VecDeque<FileActivity> = VecDeque::new();
    let mut last_alert: Option<Instant> = None;

    while let Ok(event_result) = event_rx.recv() {
        let event = match event_result {
            Ok(event) => event,
            Err(error) => {
                eprintln!(
                    "Ransomware Shield: ошибка файлового наблюдателя: {}",
                    error
                );
                continue;
            }
        };

        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {}
            _ => continue,
        }

        let paths = extract_monitored_paths(&event);

        if paths.is_empty() {
            continue;
        }

        let now = Instant::now();

        for path in paths {
            record_activity(&mut history, path, now);
        }

        let unique_files: HashSet<&PathBuf> =
            history.iter().map(|activity| &activity.path).collect();

        let file_count = unique_files.len();

        if file_count <= FILE_THRESHOLD {
            continue;
        }

        let should_alert = last_alert
            .map(|last| now.duration_since(last) >= ALERT_COOLDOWN)
            .unwrap_or(true);

        if !should_alert {
            continue;
        }

        last_alert = Some(now);

        eprintln!(
            "Ransomware Shield: обнаружено {} уникальных файлов \
             за последние 5 секунд.",
            file_count
        );

        let message = format!(
            "{}\nОбнаружено файлов: {} за 5 секунд.\n\
             PID процесса-источника: не определён средствами notify.",
            ALERT_MESSAGE,
            file_count,
        );

        if alert_tx.send(message).is_err() {
            eprintln!(
                "Ransomware Shield: канал предупреждений закрыт; \
                 мониторинг остановлен."
            );
            break;
        }
    }

    Ok(())
}