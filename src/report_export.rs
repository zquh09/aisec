use std::fs;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn export_html(path: &str, title: &str, content: &str) -> Result<(), String> {
    let current_date = get_current_utc_date_str();
    let escaped_content = escape_html(content);
    let escaped_title = escape_html(title);

    let html_content = format!(
        r#"<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-color: #121212;
            --card-bg: #1e1e1e;
            --text-color: #E6E6E6;
            --accent-color: #FFCC00;
            --border-color: #333333;
            --muted-color: #888888;
        }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .wrapper {{ max-width: 1280px; margin: 0 auto; }}
        header {{ border-bottom: 2px solid var(--accent-color); padding-bottom: 15px; margin-bottom: 25px; }}
        h1 {{ color: var(--accent-color); font-size: 24px; margin: 0 0 8px 0; letter-spacing: 0.5px; }}
        .meta-info {{ color: var(--muted-color); font-size: 14px; }}
        .report-card {{ background-color: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5); }}
        pre {{ margin: 0; white-space: pre-wrap; word-wrap: break-word; }}
        code {{ font-family: "JetBrains Mono", "Fira Code", "Courier New", Courier, monospace; color: var(--text-color); font-size: 13.5px; line-height: 1.6; }}
        footer {{ margin-top: 25px; text-align: center; color: var(--muted-color); font-size: 12px; }}
    </style>
</head>
<body>
    <div class="wrapper">
        <header>
            <h1>🔒 AI Security Toolkit (aisec) — {escaped_title}</h1>
            <div class="meta-info">Дата генерации отчета: {current_date}</div>
        </header>
        <main class="report-card">
            <pre><code>{escaped_content}</code></pre>
        </main>
        <footer>
            Сгенерировано автоматически с помощью aisec report engine
        </footer>
    </div>
</body>
</html>"#,
        title = escaped_title,
        current_date = current_date,
        escaped_title = escaped_title,
        escaped_content = escaped_content
    );

    fs::write(path, html_content).map_err(|err| {
        match err.kind() {
            io::ErrorKind::PermissionDenied => format!("Ошибка записи: Недостаточно прав для '{}'.", path),
            io::ErrorKind::NotFound => format!("Ошибка записи: Путь не существует '{}'.", path),
            _ => format!("Не удалось записать HTML отчет '{}': {}", path, err),
        }
    })?;
    Ok(())
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

fn get_current_utc_date_str() -> String {
    let since_epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return "Неизвестная дата".to_string(),
    };
    let days = since_epoch / 86400;
    let seconds_in_day = since_epoch % 86400;
    let hours = seconds_in_day / 3600;
    let minutes = (seconds_in_day % 3600) / 60;
    let seconds = seconds_in_day % 60;
    let (year, month, day) = days_to_civil_date(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", year, month, day, hours, minutes, seconds)
}

fn days_to_civil_date(mut days: u64) -> (u64, u64, u64) {
    days += 719468;
    let era = days / 146097;
    let doe = days % 146097;
    let yoe = (doe - doe / 1465 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}