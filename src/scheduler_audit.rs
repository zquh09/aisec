use std::process::Command;

pub fn get_suspicious_scheduled_tasks() -> Vec<String> {
    let mut suspicious = Vec::new();

    let output = match Command::new("schtasks")
        .args(["/query", "/fo", "CSV", "/v"])
        .output() {
            Ok(out) => out,
            Err(_) => return suspicious,
        };

    if !output.status.success() {
        return suspicious;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();

    let header_line = match lines.next() {
        Some(h) => h,
        None => return suspicious,
    };

    let headers = parse_csv_line(header_line);

    let task_name_idx = headers.iter().position(|h| h.to_lowercase().contains("taskname") || h.to_lowercase().contains("имя задачи")).unwrap_or(1);
    let run_as_idx = headers.iter().position(|h| h.to_lowercase().contains("run as user") || h.to_lowercase().contains("пользователь")).unwrap_or(13);
    let task_to_run_idx = headers.iter().position(|h| h.to_lowercase().contains("task to run") || h.to_lowercase().contains("задача")).unwrap_or(8);

    for line in lines {
        let fields = parse_csv_line(line);
        if fields.len() > std::cmp::max(std::cmp::max(task_name_idx, run_as_idx), task_to_run_idx) {
            let task_name = &fields[task_name_idx];
            let run_as = &fields[run_as_idx];
            let task_path = &fields[task_to_run_idx];

            let is_privileged = run_as.to_uppercase().contains("SYSTEM")
                || run_as.to_uppercase().contains("ADMINISTRATOR")
                || run_as.to_uppercase().contains("АДМИНИСТРАТОР");

            let path_lower = task_path.to_lowercase();
            let is_suspicious_path = path_lower.contains("appdata") 
                || path_lower.contains("\\temp\\") 
                || path_lower.contains("/temp/");

            if is_privileged && is_suspicious_path {
                suspicious.push(format!(
                    "Task: '{}' | RunAs: '{}' | Path: '{}'",
                    task_name, run_as, task_path
                ));
            }
        }
    }

    suspicious
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;

    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            if in_quotes && i + 1 < chars.len() && chars[i + 1] == '"' {
                current_field.push('"');
                i += 1;
            } else {
                in_quotes = !in_quotes;
            }
        } else if c == ',' && !in_quotes {
            result.push(current_field.trim().to_string());
            current_field = String::new();
        } else {
            current_field.push(c);
        }
        i += 1;
    }
    result.push(current_field.trim().to_string());
    result
}