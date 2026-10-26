use notify_rust::{Notification, Urgency};

pub fn notify_threat(file_name: &str, reason: &str) {
    let body = format!("Файл: {}\nПричина: {}", file_name, reason);
    let _ = Notification::new()
        .summary("🛡 AISEC: Угроза!")
        .body(&body)
        .urgency(Urgency::Critical)
        .show();
}

pub fn notify_info(title: &str, message: &str) {
    let _ = Notification::new()
        .summary(title)
        .body(message)
        .urgency(Urgency::Normal)
        .show();
}