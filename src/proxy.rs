use axum::{routing::post, Json, Router};
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::OnceLock;
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct MaskRequest { text: String }

#[derive(Serialize)]
struct MaskResponse { masked_text: String, findings_count: usize }

struct Masker {
    email: Regex, phone: Regex, card: Regex,
    openai_key: Regex, aws_key: Regex, github_key: Regex, password: Regex,
}

impl Masker {
    fn instance() -> &'static Self {
        static INSTANCE: OnceLock<Masker> = OnceLock::new();
        INSTANCE.get_or_init(|| Masker {
            email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
            phone: Regex::new(r"\b(?:\+7|8)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{2}[-.\s]?\d{2}\b").unwrap(),
            card: Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap(),
            openai_key: Regex::new(r"sk-[a-zA-Z0-9]{20,}").unwrap(),
            aws_key: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            github_key: Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(),
            password: Regex::new(r#"(?i)(password\s*[:=]\s*)([^\s,;&}]+)"#).unwrap(),
        })
    }
}

fn log_finding(finding_type: &str, mask_applied: &str) {
    let timestamp = Utc::now().to_rfc3339();
    let log_line = format!("[{}] SENSITIVE_DATA_DETECTED | Type: {} | Mask: {}\n", timestamp, finding_type, mask_applied);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("security_audit.log") {
        let _ = file.write_all(log_line.as_bytes());
    }
}

async fn handle_mask(Json(payload): Json<MaskRequest>) -> Json<MaskResponse> {
    let mut text = payload.text;
    let mut findings_count = 0;
    let masker = Masker::instance();

    text = masker.email.replace_all(&text, |_: &regex::Captures| { findings_count += 1; log_finding("EMAIL", "[EMAIL_MASKED]"); "[EMAIL_MASKED]".to_string() }).into_owned();
    text = masker.phone.replace_all(&text, |_: &regex::Captures| { findings_count += 1; log_finding("PHONE", "[PHONE_MASKED]"); "[PHONE_MASKED]".to_string() }).into_owned();
    text = masker.card.replace_all(&text, |_: &regex::Captures| { findings_count += 1; log_finding("CREDIT_CARD", "[CARD_MASKED]"); "[CARD_MASKED]".to_string() }).into_owned();
    text = masker.openai_key.replace_all(&text, |_: &regex::Captures| { findings_count += 1; log_finding("API_KEY_OPENAI", "[OPENAI_KEY_MASKED]"); "[OPENAI_KEY_MASKED]".to_string() }).into_owned();
    text = masker.aws_key.replace_all(&text, |_: &regex::Captures| { findings_count += 1; log_finding("API_KEY_AWS", "[AWS_KEY_MASKED]"); "[AWS_KEY_MASKED]".to_string() }).into_owned();
    text = masker.github_key.replace_all(&text, |_: &regex::Captures| { findings_count += 1; log_finding("API_KEY_GITHUB", "[GITHUB_KEY_MASKED]"); "[GITHUB_KEY_MASKED]".to_string() }).into_owned();
    text = masker.password.replace_all(&text, |caps: &regex::Captures| { findings_count += 1; log_finding("PASSWORD", "[PASSWORD_MASKED]"); format!("{}[PASSWORD_MASKED]", &caps[1]) }).into_owned();

    Json(MaskResponse { masked_text: text, findings_count })
}

pub fn start_proxy() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let addr = "127.0.0.1:8080";
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[-] Ошибка: не удалось запустить прокси на {}. Порт занят: {}", addr, e);
                return;
            }
        };
        println!("[+] DLP Proxy запущен на http://{}", addr);
        println!("[*] Отправь POST-запрос на /mask с JSON: {{\"text\": \"твой текст\"}}");
        
        let app = Router::new().route("/mask", post(handle_mask));
        axum::serve(listener, app).with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            println!("\n[!] Остановка прокси...");
        }).await.unwrap();
    });
}