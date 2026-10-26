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

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;
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
    let cli = Cli::parse();

    if cli.command.is_none() {
        if let Err(e) = gui::run_gui() {
            eprintln!("Ошибка запуска GUI: {}", e);
            process::exit(1);
        }
        return;
    }

    match cli.command.unwrap() {
        Commands::Scan { path, exclude, json } => {
            if let Err(e) = scan::start_scan(path, exclude, json) { eprintln!("Ошибка сканирования: {}", e); process::exit(1); }
        }
        Commands::Guard { input, explain, json } => {
            let report = prompt_guard::analyze_prompt(&input);
            if json { println!("{}", serde_json::to_string_pretty(&report).unwrap()); }
            else { println!("{}", report.format_text(explain)); }
            if report.risk_level == prompt_guard::RiskLevel::High { process::exit(2); }
        }
        Commands::Canary { count, r#type } => { canary::generate_canaries(count, r#type); }
        Commands::Crack { path } => {
            match crack_detector::analyze_file(&path) {
                Ok(report) => { println!("Вердикт: {:?}", report.verdict); for r in report.reasons { println!("- {}", r); } }
                Err(e) => eprintln!("Ошибка: {}", e),
            }
        }
        Commands::Startup => { print!("{}", startup_check::scan_startup().format()); }
        Commands::Proxy => { proxy::start_proxy(); }
        Commands::Processes => { println!("{}", process_scanner::scan_processes()); }
        Commands::Watch { path } => {
            println!("Слежка за папкой {:?}. Нажмите Ctrl+C для выхода.", path);
            let (tx, rx) = channel();
            watcher::start_watching(&path.to_string_lossy(), tx);
            for msg in rx { println!("{}", msg); }
        }
        Commands::Privacy => {
            let report = privacy_audit::run_privacy_audit();
            println!("=== АУДИТ ПРИВАТНОСТИ ===");
            println!("DNS-утечка: {}", if report.dns_leak { "❌ ОБНАРУЖЕНА" } else { "✅ НЕТ" });
            println!("IPv6 активен: {}", if report.ipv6_active { "⚠️ ДА" } else { "✅ НЕТ" });
            println!("Локальный IP раскрыт: {}", if report.webrtc_leak { "⚠️ ДА" } else { "✅ НЕТ" });
            if !report.warnings.is_empty() {
                println!("\nПредупреждения:");
                for w in report.warnings { println!(" - {}", w); }
            }
        }
    }
}