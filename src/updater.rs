use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

const LATEST_RELEASE_URL: &str = "https://api.github.com/repos/zquh09/aisec/releases/latest";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub fn check_for_updates() -> Result<Option<String>, String> {
    let client = Client::builder()
        .user_agent(concat!("aisec/", env!("CARGO_PKG_VERSION")))
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("Не удалось создать HTTP-клиент: {e}"))?;

    let response = client
        .get(LATEST_RELEASE_URL)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .map_err(|e| {
            if e.is_timeout() {
                "Превышено время ожидания ответа от GitHub".to_string()
            } else if e.is_connect() {
                format!("Нет соединения с GitHub: {e}")
            } else {
                format!("Ошибка сети при запросе к GitHub: {e}")
            }
        })?;

    let status = response.status();
    match status {
        StatusCode::NOT_FOUND => return Ok(None),
        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => {
            return Err(format!(
                "GitHub API отклонил запрос (HTTP {status}): возможно, превышен лимит запросов"
            ));
        }
        s if !s.is_success() => {
            return Err(format!("GitHub API вернул HTTP {s}"));
        }
        _ => {}
    }

    let body = response
        .text()
        .map_err(|e| format!("Не удалось прочитать ответ GitHub: {e}"))?;

    let json: Value = serde_json::from_str(&body)
        .map_err(|e| format!("Ответ GitHub не является корректным JSON: {e}"))?;

    let tag_name = json
        .get("tag_name")
        .and_then(Value::as_str)
        .ok_or_else(|| "В ответе GitHub нет поля tag_name".to_string())?;

    let html_url = json
        .get("html_url")
        .and_then(Value::as_str)
        .ok_or_else(|| "В ответе GitHub нет поля html_url".to_string())?;

    if !html_url.starts_with("https://github.com/") {
        return Err(format!("Неожиданный адрес релиза: {html_url}"));
    }

    let latest = parse_version(tag_name)
        .ok_or_else(|| format!("Не удалось разобрать версию релиза: '{tag_name}'"))?;
    let current = parse_version(CURRENT_VERSION)
        .ok_or_else(|| format!("Не удалось разобрать текущую версию: '{CURRENT_VERSION}'"))?;

    if latest > current {
        Ok(Some(html_url.to_string()))
    } else {
        Ok(None)
    }
}

fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    let core = trimmed.split(['-', '+']).next()?;

    let mut parts = core.split('.');

    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = match parts.next() {
        Some(p) => p.parse().ok()?,
        None => 0,
    };
    let patch: u64 = match parts.next() {
        Some(p) => p.parse().ok()?,
        None => 0,
    };

    if parts.next().is_some() {
        return None;
    }

    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::parse_version;

    #[test]
    fn parses_common_formats() {
        assert_eq!(parse_version("v2.1.0"), Some((2, 1, 0)));
        assert_eq!(parse_version("2.1.0"), Some((2, 1, 0)));
        assert_eq!(parse_version("V3.0"), Some((3, 0, 0)));
        assert_eq!(parse_version("v1.2.3-beta.1+build5"), Some((1, 2, 3)));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("latest"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
    }

    #[test]
    fn compares_numerically() {
        assert!(parse_version("v2.10.0") > parse_version("2.9.9"));
        assert!(parse_version("v2.1.0") > parse_version("2.0.9"));
    }
}