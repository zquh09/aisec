use chrono::Local;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;

fn base62_encode(bytes: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::new();
    for &b in bytes {
        out.push(CHARSET[b as usize % 62] as char);
    }
    out
}

pub fn generate_canaries(count: usize, types: Vec<String>) {
    let mut bytes = [0u8; 48];
    OsRng.fill_bytes(&mut bytes);
    let rand_str = base62_encode(&bytes);

    let mut content = format!("# Canary Tokens Generated on {}\n\n", Local::now().format("%Y-%m-%d %H:%M:%S"));

    let gen_all = types.is_empty();
    for _ in 0..count {
        if gen_all || types.contains(&"aws".to_string()) {
            content.push_str(&format!("AWS: AKIA{}\n", &rand_str[..16].to_uppercase()));
        }
        if gen_all || types.contains(&"github".to_string()) {
            content.push_str(&format!("GitHub: ghp_{}\n", &rand_str[..36]));
        }
        if gen_all || types.contains(&"openai".to_string()) {
            content.push_str(&format!("OpenAI: sk-{}\n", &rand_str));
        }
        if gen_all || types.contains(&"stripe".to_string()) {
            content.push_str(&format!("Stripe: sk_live_{}\n", &rand_str[..24]));
        }
    }

    match fs::write("tokens.txt", content) {
        Ok(_) => println!("[+] Токены успешно сохранены в tokens.txt"),
        Err(e) => eprintln!("[-] Ошибка сохранения: {}", e),
    }
}