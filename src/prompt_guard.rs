use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum RiskLevel { Low, Medium, High }

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TriggeredRule {
    pub name: String,
    pub severity_score: u32,
    pub explanation: String,
    pub matched_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuardReport {
    pub total_score: u32,
    pub risk_level: RiskLevel,
    pub triggers: Vec<TriggeredRule>,
    pub is_safe: bool,
}

impl GuardReport {
    pub fn format_text(&self, explain: bool) -> String {
        let mut out = format!("=== AI PROMPT GUARD REPORT ===\nСтатус: {}\nУровень риска: {}\nСкоринг: {}\n==============================\n", 
            if self.is_safe { "SAFE" } else { "UNSAFE" }, self.risk_level, self.total_score);
        if !self.triggers.is_empty() {
            out.push_str("\nНайденные паттерны:\n");
            for (i, t) in self.triggers.iter().enumerate() {
                out.push_str(&format!(" {}. [{}] (Вес: {})\n", i+1, t.name, t.severity_score));
                if let Some(s) = &t.matched_snippet { out.push_str(&format!("    Фрагмент: \"{}\"\n", s)); }
                if explain { out.push_str(&format!("    Объяснение: {}\n", t.explanation)); }
            }
        }
        out
    }
}

struct GuardRule {
    name: &'static str,
    pattern_type: PatternType,
    severity_score: u32,
    explanation: &'static str,
}

enum PatternType { Regex(Regex), Base64Heuristic }

fn get_rules() -> &'static Vec<GuardRule> {
    static RULES: OnceLock<Vec<GuardRule>> = OnceLock::new();
    RULES.get_or_init(|| vec![
        GuardRule { name: "Direct Override", pattern_type: PatternType::Regex(Regex::new(r"(?i)(ignore|forget|disregard|bypass)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|directives)").unwrap()), severity_score: 10, explanation: "Попытка переопределения системного промпта." },
        GuardRule { name: "Roleplay Jailbreak", pattern_type: PatternType::Regex(Regex::new(r"(?i)(you are now|act as|pretend you are|switch to)\s+(DAN|AIM|APOPHIS|jailbreak|an unrestricted AI|a god mode)").unwrap()), severity_score: 9, explanation: "Смена роли (DAN и т.д.)." },
        GuardRule { name: "System Prompt Leakage", pattern_type: PatternType::Regex(Regex::new(r"(?i)(print|show|reveal|output|repeat|tell me)\s+(your|the)\s+(system prompt|initial instructions|hidden context|developer message)").unwrap()), severity_score: 8, explanation: "Попытка извлечения системного промпта." },
        GuardRule { name: "Jailbreak Keywords", pattern_type: PatternType::Regex(Regex::new(r"(?i)\b(jailbreak|uncensored mode|godmode|developer mode)\b").unwrap()), severity_score: 7, explanation: "Ключевые слова джейлбрейка." },
        GuardRule { name: "Obfuscation (Base64)", pattern_type: PatternType::Base64Heuristic, severity_score: 8, explanation: "Строка похожа на Base64 (обход фильтров)." },
    ])
}

fn is_suspicious_base64(word: &str) -> bool {
    if word.len() < 20 { return false; }
    if !word.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') { return false; }
    let entropy = calculate_entropy(word);
    let digit_ratio = word.chars().filter(|c| c.is_ascii_digit()).count() as f64 / word.len() as f64;
    entropy > 4.5 && digit_ratio > 0.05 && digit_ratio < 0.6
}

fn calculate_entropy(data: &str) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256]; let len = data.len() as f64;
    for b in data.bytes() { counts[b as usize] += 1; }
    let mut entropy = 0.0;
    for &c in &counts { if c > 0 { let p = c as f64 / len; entropy -= p * p.log2(); } }
    entropy
}

// БЕЗОПАСНОЕ извлечение без паники на UTF-8
fn extract_snippet(text: &str, start: usize, end: usize) -> String {
    let pad = 15;
    let s = start.saturating_sub(pad);
    let e = (end + pad).min(text.len());
    
    // Ищем ближайшие границы символов (char_indices), чтобы не разрезать русскую букву
    let safe_s = text.char_indices().map(|(i, _)| i).find(|&i| i >= s).unwrap_or(0);
    let safe_e = text.char_indices().map(|(i, _)| i).rev().find(|&i| i <= e).unwrap_or(text.len());

    let mut snippet = text[safe_s..safe_e].replace('\n', " ").replace('\r', "");
    if safe_s > 0 { snippet = format!("...{}", snippet); }
    if safe_e < text.len() { snippet = format!("{}...", snippet); }
    if snippet.len() > 100 { snippet = snippet.chars().take(100).collect::<String>() + "..."; }
    snippet
}

pub fn analyze_prompt(text: &str) -> GuardReport {
    let mut triggers = Vec::new(); let mut total_score = 0;
    for rule in get_rules() {
        match &rule.pattern_type {
            PatternType::Regex(re) => {
                if let Some(mat) = re.find(text) {
                    total_score += rule.severity_score;
                    triggers.push(TriggeredRule { name: rule.name.to_string(), severity_score: rule.severity_score, explanation: rule.explanation.to_string(), matched_snippet: Some(extract_snippet(text, mat.start(), mat.end())) });
                }
            }
            PatternType::Base64Heuristic => {
                for word in text.split_whitespace() {
                    let clean = word.trim_matches(|c| c == '"' || c == '\'' || c == '(' || c == ')' || c == '`');
                    if is_suspicious_base64(clean) {
                        total_score += rule.severity_score;
                        triggers.push(TriggeredRule { name: rule.name.to_string(), severity_score: rule.severity_score, explanation: rule.explanation.to_string(), matched_snippet: Some(clean.chars().take(40).collect::<String>() + "...") });
                        break;
                    }
                }
            }
        }
    }
    let risk = if total_score >= 15 { RiskLevel::High } else if total_score >= 7 { RiskLevel::Medium } else { RiskLevel::Low };
    GuardReport { total_score, risk_level: risk, triggers, is_safe: total_score == 0 }
}