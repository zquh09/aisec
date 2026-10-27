mod scan;
mod prompt_guard;
mod proxy;
mod canary;
mod crack_detector;
mod startup_check;
mod process_scanner;
mod watcher;
mod config;
mod gui;
mod signature_check;
mod virustotal;
mod report_export;
mod privacy_audit;
mod hash_scanner;
mod quarantine_crypto;
mod quarantine;
mod full_scan;
mod network_monitor;
mod yara_scanner;
mod file_integrity;
mod yara_manager;
mod system_check;
mod real_time_protection;
mod rtp_filter;
mod notifications;
mod ransomware_shield;
mod scheduler_audit;
mod process_killer;
mod self_defense;
mod tray;
mod updater;
mod cloud_db;
mod scheduler;
mod usb_guard;
mod hash_cache;
mod registry_scanner;
mod wmi_scanner;
mod threat_history;
mod ntfs_scanner;
mod pdf_export;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;

#[derive(Parser, Debug)]
#[command(name = "AI Security Toolkit")]
#[command(about = "Защита данных и анализ угроз", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Scan { #[arg(short, long, default_value = ".")] path: PathBuf, #[arg(long)] exclude: Vec<PathBuf>, #[arg(long)] json: bool },
    Guard { #[arg(short, long)] input: String, #[arg(long)] explain: bool, #[arg(long)] json: bool },
    Canary { #[arg(long, default_value_t = 1)] count: usize, #[arg(long)] r#type: Vec<String> },
    Crack { #[arg(short, long)] path: PathBuf },
    Startup,
    Proxy,
    Processes,
    Watch { #[arg(short, long, default_value = ".")] path: PathBuf },
    Privacy,
}

fn main() {
    // Защита exe от удаления
    let _ = self_defense::lock_executable();

    let cli = Cli::parse();

    if cli.command.is_none() {
        // === РЕЖИМ GUI ===
        
        // 1. Загружаем конфиг и запускаем планировщик
        let config_arc = Arc::new(Mutex::new(config::load_config()));
        scheduler::start_scheduler(Arc::clone(&config_arc));

        // 2. Запускаем USB Guard в фоне (чтобы не блокировать GUI)
        std::thread::spawn(|| {
            if let Err(e) = usb_guard::start_usb_listener() {
                eprintln!("[USB Guard] Ошибка: {}", e);
            }
        });

        // 3. Запускаем GUI
        if let Err(e) = gui::run_gui() {
            eprintln!("Ошибка запуска GUI: {}", e);
            process::exit(1);
        }
        return;
    }

    // === РЕЖИМ CLI ===
    match cli.command.unwrap() {
        Commands::Scan { path, exclude, json } => {
            if let Err(e) = scan::start_scan(path, exclude, json) {
                eprintln!("Ошибка сканирования: {}", e);
                process::exit(1);
            }
        }
        Commands::Guard { input, explain, json } => {
            let report = prompt_guard::analyze_prompt(&input);
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!("{}", report.format_text(explain));
            }
            if report.risk_level == prompt_guard::RiskLevel::High {
                process::exit(2);
            }
        }
        Commands::Canary { count, r#type } => {
            canary::generate_canaries(count, r#type);
        }
        Commands::Crack { path } => {
            match crack_detector::analyze_file(&path) {
                Ok(report) => {
                    println!("Вердикт: {:?}", report.verdict);
                    for r in report.reasons { println!("- {}", r); }
                }
                Err(e) => eprintln!("Ошибка: {}", e),
            }
        }
        Commands::Startup => {
            print!("{}", startup_check::scan_startup().format());
        }
        Commands::Proxy => {
            proxy::start_proxy();
        }
        Commands::Processes => {
            println!("{}", process_scanner::scan_processes());
        }
        Commands::Watch { path } => {
            println!("Слежка за папкой {:?}. Нажмите Ctrl+C для выхода.", path);
            let (tx, rx) = channel();
            watcher::start_watching(&path.to_string_lossy(), tx);
            for msg in rx { println!("{}", msg); }
        }
        Commands::Privacy => {
            let report = privacy_audit::run_privacy_audit();
            println!("=== АУДИТ ПРИВАТНОСТИ ===");
            println!("DNS-утечка: {}", if report.dns_leak { "ОБНАРУЖЕНА" } else { "НЕТ" });
            println!("IPv6 активен: {}", if report.ipv6_active { "ДА" } else { "НЕТ" });
            println!("Локальный IP раскрыт: {}", if report.webrtc_leak { "ДА" } else { "НЕТ" });
            if !report.warnings.is_empty() {
                println!("\nПредупреждения:");
                for w in report.warnings { println!(" - {}", w); }
            }
        }
    }
}