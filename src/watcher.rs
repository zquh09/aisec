use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind};
use std::path::Path;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

pub fn start_watching(path: &str, tx: Sender<String>) {
    let target_path = path.to_string();

    thread::spawn(move || {
        let (notify_tx, notify_rx) = channel();
        let mut watcher: RecommendedWatcher = match RecommendedWatcher::new(notify_tx, notify::Config::default()) {
            Ok(w) => w,
            Err(e) => {
                let _ = tx.send(format!("Ошибка создания наблюдателя: {}", e));
                return;
            }
        };

        if let Err(e) = watcher.watch(Path::new(&target_path), RecursiveMode::NonRecursive) {
            let _ = tx.send(format!("Ошибка: папка '{}' недоступна: {}", target_path, e));
            return;
        }

        for res in notify_rx {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Create(_)) {
                    for file_path in event.paths {
                        if let Some(ext) = file_path.extension() {
                            if ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll") {
                                let file_path_clone = file_path.clone();
                                let tx_clone = tx.clone();

                                // ВЫНОСИМ ПРОВЕРКУ В ОТДЕЛЬНЫЙ ПОТОК (фикс Gemini)
                                thread::spawn(move || {
                                    let file_name = file_path_clone.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();
                                    
                                    // Ждём 2 секунды, пока файл скачается
                                    thread::sleep(Duration::from_secs(2));

                                    if !file_path_clone.exists() {
                                        let _ = tx_clone.send(format!("⚠ Файл {} исчез до проверки.", file_name));
                                        return;
                                    }

                                    let message = match crate::crack_detector::analyze_file(&file_path_clone) {
                                        Ok(report) => format!("⚠ Новый файл: {} | Вердикт: {:?} | Очки: {}", file_name, report.verdict, report.pirate_score),
                                        Err(e) => format!("⚠ Новый файл: {} | Ошибка: {:?}", file_name, e),
                                    };
                                    let _ = tx_clone.send(message);
                                });
                            }
                        }
                    }
                }
            }
        }
    });
}