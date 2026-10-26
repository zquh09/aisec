use sysinfo::System; // Убрали устаревшие ProcessExt и SystemExt
use std::thread;
use std::time::Duration;

pub fn scan_processes() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();
    thread::sleep(Duration::from_millis(200));
    sys.refresh_all();

    let mut process_data: Vec<ProcessInfo> = Vec::new();

    for (pid, process) in sys.processes() {
        let name = process.name().to_string(); // В новой версии name() возвращает &str
        let pid_val = pid.as_u32();
        let exe_path = process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "N/A".to_string());
        let cpu_usage = process.cpu_usage();
        let memory_mb = process.memory() as f64 / 1024.0 / 1024.0;
        let is_suspicious = check_suspicious_path(&exe_path);

        process_data.push(ProcessInfo { pid: pid_val, name, exe_path, cpu_usage, memory_mb, is_suspicious });
    }

    process_data.sort_by(|a, b| b.cpu_usage.partial_cmp(&a.cpu_usage).unwrap_or(std::cmp::Ordering::Equal));
    format_table(&process_data)
}

struct ProcessInfo {
    pid: u32,
    name: String,
    exe_path: String,
    cpu_usage: f32,
    memory_mb: f64,
    is_suspicious: bool,
}

fn check_suspicious_path(path: &str) -> bool {
    if path == "N/A" { return false; }
    let lower_path = path.to_lowercase();
    let suspicious_patterns = [r"\appdata\local\temp\", r"\windows\temp\", r"\downloads\"];
    suspicious_patterns.iter().any(|pattern| lower_path.contains(pattern))
}

fn format_table(processes: &[ProcessInfo]) -> String {
    let mut output = String::new();
    output.push_str(&format!("{:<8} | {:<25} | {:<10} | {:<8} | {:<12} | {}\n", "PID", "Name", "CPU %", "RAM MB", "Status", "Path"));
    output.push_str(&"-".repeat(110));
    output.push('\n');

    for proc_info in processes {
        let suspicious_tag = if proc_info.is_suspicious { "[SUSPICIOUS]" } else { "" };
        let display_path = if proc_info.exe_path.len() > 40 { format!("...{}", &proc_info.exe_path[proc_info.exe_path.len() - 37..]) } else { proc_info.exe_path.clone() };
        output.push_str(&format!("{:<8} | {:<25} | {:<10.2} | {:<8.2} | {:<12} | {}\n", proc_info.pid, truncate(&proc_info.name, 25), proc_info.cpu_usage, proc_info.memory_mb, suspicious_tag, display_path));
    }
    output
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() > max_chars {
        let truncated: String = s.chars().take(max_chars - 3).collect();
        format!("{}...", truncated)
    } else {
        s.to_string()
    }
}