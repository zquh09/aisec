use sysinfo::{Pid, System};

const CRITICAL_PROCESSES: &[&str] = &["csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "system", "smss.exe"];

pub fn is_process_significant(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_all();
    let process_pid = Pid::from(pid as usize);
    let Some(process) = system.process(process_pid) else { return false; };
    let process_name = process.name().to_string();
    CRITICAL_PROCESSES.iter().any(|name| process_name.eq_ignore_ascii_case(name))
}

pub fn kill_process_by_pid(pid: u32) -> Result<(), String> {
    if is_process_significant(pid) {
        return Err("Отказано в доступе. Это критический системный процесс.".to_string());
    }
    let mut system = System::new_all();
    system.refresh_all();
    let process_pid = Pid::from(pid as usize);
    let Some(process) = system.process(process_pid) else {
        return Err(format!("Процесс с PID {} не найден", pid));
    };
    if process.kill() { Ok(()) } else { Err("Не удалось завершить процесс. Отказано в доступе.".to_string()) }
}