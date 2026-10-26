//! # crack_detector — эвристический анализатор PE-файлов (кряк/репак vs. вредонос)
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use goblin::pe::PE;
use serde::Serialize;

use crate::scan::Finding;

const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
const MAX_SIDECAR_SIZE: u64 = 512 * 1024;
const MAX_SIDECAR_FILES: usize = 32;
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.2;
const MIN_ENTROPY_SECTION_SIZE: usize = 1024;
const PIRATE_SCORE_THRESHOLD: u32 = 2;
const MIN_NEEDLE_BYTES: usize = 5;
const ENTROPY_EXEMPT_SECTIONS: &[&str] = &[".rsrc"];

const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("upx0", "UPX"), ("upx1", "UPX"), (".aspack", "ASPack"), (".adata", "ASPack"),
    (".vmp0", "VMProtect"), (".vmp1", "VMProtect"), (".themida", "Themida"),
    (".enigma1", "Enigma Protector"), (".mpress1", "MPRESS"), (".petite", "Petite"), (".nsp0", "NsPack"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strength { Weak, Strong }

impl Strength {
    fn points(self) -> u32 { match self { Strength::Weak => 1, Strength::Strong => 2 } }
    fn label(self) -> &'static str { match self { Strength::Weak => "weak", Strength::Strong => "strong" } }
}

const FILENAME_TOKENS: &[(&str, Strength)] = &[
    ("crack", Strength::Strong), ("cracked", Strength::Strong), ("keygen", Strength::Strong),
    ("keymaker", Strength::Strong), ("nocd", Strength::Strong), ("nodvd", Strength::Strong),
    ("kmspico", Strength::Strong), ("kmsauto", Strength::Strong), ("patch", Strength::Weak),
    ("patcher", Strength::Weak), ("activator", Strength::Weak),
];

const FILENAME_EXACT: &[&str] = &[
    "steam_api.dll", "steam_api64.dll", "steamclient.dll", "steamclient64.dll",
    "steamclient_loader.exe", "cream_api.dll", "creamapi.dll", "uplay_r1_loader.dll",
    "uplay_r1_loader64.dll", "uplay_r2_loader.dll", "uplay_r2_loader64.dll",
    "3dmgame.dll", "unsteam.dll", "smartsteamemu.dll",
];

const STRING_MARKERS: &[(&str, Strength)] = &[
    ("r.g. mechanics", Strength::Strong), ("rg mechanics", Strength::Strong), ("r.g. механики", Strength::Strong),
    ("skidrow", Strength::Strong), ("razor1911", Strength::Strong), ("fitgirl", Strength::Strong),
    ("xatab", Strength::Strong), ("repack by", Strength::Strong), ("cracked by", Strength::Strong),
    ("crack by", Strength::Strong), ("keymaker", Strength::Strong), ("crack", Strength::Weak),
    ("keygen", Strength::Weak), ("no-cd", Strength::Weak), ("таблетка", Strength::Weak), ("кряк", Strength::Weak),
];

const SIDECAR_PHRASES: &[(&str, Strength)] = &[
    ("if you like this game", Strength::Strong), ("copy the crack", Strength::Strong),
    ("repack features", Strength::Strong), ("replace the original", Strength::Weak),
    ("install notes", Strength::Weak), ("release date", Strength::Weak),
];

const NETWORK_NEEDLES: &[&str] = &[
    "wininet.dll", "winhttp.dll", "ws2_32.dll", "wsock32.dll", "urlmon.dll",
    "urldownloadtofile", "internetopenurl", "internetreadfile", "httpsendrequest",
    "winhttpopen", "wsastartup",
];
const AUTOSTART_NEEDLES: &[&str] = &["currentversion\\run", "\\start menu\\programs\\startup"];
const RANSOM_NEEDLES: &[&str] = &["your files have been encrypted", "your files are encrypted", "decrypt your files", "ваши файлы зашифрованы"];
const CRYPTO_NEEDLES: &[&str] = &["cryptencrypt", "bcryptencrypt"];
const ENUM_NEEDLES: &[&str] = &["findfirstfile"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict { LikelyCrack, Suspicious, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Behavior { Network, Autostart, FileEncryption }

impl Behavior {
    pub fn as_str(self) -> &'static str {
        match self { Behavior::Network => "network", Behavior::Autostart => "autostart", Behavior::FileEncryption => "file_encryption" }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CrackReport {
    pub file_path: String,
    pub verdict: Verdict,
    pub pirate_score: u32,
    pub high_entropy: bool,
    pub behaviors: Vec<Behavior>,
    pub reasons: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub struct Sidecar { pub path: String, pub bytes: Vec<u8> }

#[derive(Debug)]
pub enum CrackError {
    Io(io::Error), TooLarge { size: u64, limit: u64 }, NotPe,
}

impl fmt::Display for CrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrackError::Io(e) => write!(f, "ошибка ввода-вывода: {e}"),
            CrackError::TooLarge { size, limit } => write!(f, "файл слишком большой: {size} байт (лимит {limit})"),
            CrackError::NotPe => write!(f, "файл не похож на PE (нет сигнатуры MZ)"),
        }
    }
}

impl std::error::Error for CrackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { CrackError::Io(e) => Some(e), _ => None }
    }
}

impl From<io::Error> for CrackError { fn from(e: io::Error) -> Self { CrackError::Io(e) } }

pub fn analyze_file(path: &Path) -> Result<CrackReport, CrackError> {
    let size = fs::metadata(path)?.len();
    if size > MAX_FILE_SIZE { return Err(CrackError::TooLarge { size, limit: MAX_FILE_SIZE }); }
    let bytes = fs::read(path)?;
    let sidecars = collect_sidecars(path);
    analyze_bytes(&path.to_string_lossy(), &bytes, &sidecars)
}

pub fn analyze_bytes(display_path: &str, bytes: &[u8], sidecars: &[Sidecar]) -> Result<CrackReport, CrackError> {
    if !bytes.starts_with(b"MZ") { return Err(CrackError::NotPe); }

    let file_name = display_path.rsplit(|c: char| c == '/' || c == '\\').next().unwrap_or(display_path).to_lowercase();
    let file_entropy = shannon_entropy(bytes);
    let folded = bytes.to_ascii_lowercase();

    let mut findings: Vec<Finding> = Vec::new();
    let mut pirate_score: u32 = 0;

    for (what, strength) in filename_markers(&file_name) {
        pirate_score += strength.points();
        findings.push(mk_finding(display_path, 0, "pirate_marker:filename", format!("{what} ({})", strength.label()), file_entropy));
    }

    let (pe_info, parse_error) = match parse_pe(bytes) {
        Ok(info) => (info, None),
        Err(e) => (PeInfo { sections: Vec::new(), imports: Imports::default() }, Some(e)),
    };

    let mut high_entropy = false;
    for s in &pe_info.sections {
        let exempt = ENTROPY_EXEMPT_SECTIONS.iter().any(|e| *e == s.name_lc);
        if s.size >= MIN_ENTROPY_SECTION_SIZE && !exempt && s.entropy >= HIGH_ENTROPY_THRESHOLD {
            high_entropy = true;
            findings.push(mk_finding(display_path, 0, "high_entropy_section", format!("{} ({} B)", s.name, s.size), s.entropy));
        }
        if let Some((_, packer)) = PACKER_SECTIONS.iter().find(|(n, _)| *n == s.name_lc) {
            findings.push(mk_finding(display_path, 0, "packer_section", format!("{} -> {packer}", s.name), s.entropy));
        }
    }

    for hit in scan_markers(&folded, STRING_MARKERS) {
        pirate_score += hit.strength.points();
        findings.push(mk_finding(display_path, 0, "pirate_marker:string", format!("{} @0x{:x} ({})", hit.text, hit.offset, hit.strength.label()), file_entropy));
    }

    let behavior_hits = detect_behaviors(&folded, &pe_info.imports);
    let mut behaviors: Vec<Behavior> = Vec::new();
    for h in &behavior_hits {
        behaviors.push(h.behavior);
        findings.push(mk_finding(display_path, 0, &format!("behavior:{}", h.behavior.as_str()), format!("{} ({})", h.evidence, if h.via_import { "import" } else { "string" }), file_entropy));
    }

    for sc in sidecars {
        let sc_folded = sc.bytes.to_ascii_lowercase();
        let sc_entropy = shannon_entropy(&sc.bytes);
        let mut hits = scan_markers(&sc_folded, STRING_MARKERS);
        hits.extend(scan_markers(&sc_folded, SIDECAR_PHRASES));
        for hit in hits {
            pirate_score += hit.strength.points();
            let line = 1 + sc_folded[..hit.offset].iter().filter(|&&b| b == b'\n').count();
            findings.push(mk_finding(&sc.path, line, "pirate_marker:sidecar_text", format!("{} ({})", hit.text, hit.strength.label()), sc_entropy));
        }
    }

    let verdict = decide_verdict(pirate_score, &behaviors, high_entropy);
    let reasons = explain(pirate_score, &behaviors, high_entropy, verdict, parse_error.as_deref());

    Ok(CrackReport { file_path: display_path.to_string(), verdict, pirate_score, high_entropy, behaviors, reasons, findings })
}

pub fn decide_verdict(pirate_score: u32, behaviors: &[Behavior], high_entropy: bool) -> Verdict {
    let has_pirate = pirate_score >= PIRATE_SCORE_THRESHOLD;
    let has_behavior = !behaviors.is_empty();
    match (has_pirate, has_behavior, high_entropy) {
        (true, false, _) => Verdict::LikelyCrack,
        (true, true, _) => Verdict::Suspicious,
        (false, true, true) => Verdict::Suspicious,
        (false, _, _) => Verdict::Unknown,
    }
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / len; -p * p.log2() }).sum()
}

struct SectionInfo { name: String, name_lc: String, size: usize, entropy: f64 }

#[derive(Default)]
struct Imports { dlls: HashSet<String>, funcs: HashSet<String> }

impl Imports {
    fn has(&self, needle: &str) -> bool {
        if needle.ends_with(".dll") { self.dlls.contains(needle) }
        else { self.funcs.iter().any(|f| f.starts_with(needle)) }
    }
}

struct PeInfo { sections: Vec<SectionInfo>, imports: Imports }

fn parse_pe(bytes: &[u8]) -> Result<PeInfo, String> {
    let pe = PE::parse(bytes).map_err(|e| e.to_string())?;
    let mut sections = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let name_len = s.name.iter().position(|&b| b == 0).unwrap_or(s.name.len());
        let name = String::from_utf8_lossy(&s.name[..name_len]).into_owned();
        let start = s.pointer_to_raw_data as usize;
        let want = s.size_of_raw_data as usize;
        let data: &[u8] = match bytes.get(start..) {
            Some(rest) => &rest[..want.min(rest.len())],
            None => &[],
        };
        sections.push(SectionInfo { name_lc: name.to_ascii_lowercase(), name, size: data.len(), entropy: shannon_entropy(data) });
    }
    let mut imports = Imports::default();
    for imp in &pe.imports {
        imports.dlls.insert(imp.dll.to_ascii_lowercase());
        imports.funcs.insert(imp.name.to_ascii_lowercase());
    }
    Ok(PeInfo { sections, imports })
}

fn filename_markers(file_name_lc: &str) -> Vec<(String, Strength)> {
    let mut hits: Vec<(String, Strength)> = Vec::new();
    if FILENAME_EXACT.iter().any(|n| *n == file_name_lc) { hits.push((file_name_lc.to_string(), Strength::Weak)); }
    let stem = match file_name_lc.rfind('.') { Some(i) if i > 0 => &file_name_lc[..i], _ => file_name_lc };
    for token in stem.split(|c: char| !c.is_alphanumeric()) {
        let token = token.trim_end_matches(|c: char| c.is_ascii_digit());
        if token.is_empty() { continue; }
        if let Some(&(word, strength)) = FILENAME_TOKENS.iter().find(|(w, _)| *w == token) {
            if !hits.iter().any(|(w, _)| w == word) { hits.push((word.to_string(), strength)); }
        }
    }
    hits
}

struct MarkerHit { text: &'static str, strength: Strength, offset: usize }

fn scan_markers(folded: &[u8], markers: &[(&'static str, Strength)]) -> Vec<MarkerHit> {
    markers.iter().filter_map(|&(text, strength)| {
        find_first_variant(folded, &needle_variants(text)).map(|offset| MarkerHit { text, strength, offset })
    }).collect()
}

fn needle_variants(text: &str) -> Vec<Vec<u8>> {
    let mut forms = vec![text.to_lowercase()];
    if !text.is_ascii() { forms.push(text.to_uppercase()); forms.push(capitalize(text)); }
    let mut out: Vec<Vec<u8>> = Vec::new();
    for form in forms {
        let folded: String = form.chars().map(|c| c.to_ascii_lowercase()).collect();
        out.push(folded.as_bytes().to_vec());
        out.push(folded.encode_utf16().flat_map(|u| u.to_le_bytes()).collect());
        if let Some(cp1251) = encode_cp1251(&folded) { out.push(cp1251); }
    }
    out.retain(|v| v.len() >= MIN_NEEDLE_BYTES);
    out.sort();
    out.dedup();
    out
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars.flat_map(|c| c.to_lowercase())).collect(),
        None => String::new(),
    }
}

fn encode_cp1251(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    for ch in s.chars() {
        let b = match ch {
            c if c.is_ascii() => c as u8,
            'Ё' => 0xA8, 'ё' => 0xB8, 'А'..='я' => (ch as u32 - 0x0410 + 0xC0) as u8, _ => return None,
        };
        out.push(b);
    }
    Some(out)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() { return None; }
    let first = needle[0];
    let last_start = hay.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        let p = hay[i..=last_start].iter().position(|&b| b == first)?;
        let s = i + p;
        if &hay[s..s + needle.len()] == needle { return Some(s); }
        i = s + 1;
    }
    None
}

fn find_first_variant(hay: &[u8], variants: &[Vec<u8>]) -> Option<usize> {
    variants.iter().filter_map(|v| find_subslice(hay, v)).min()
}

struct BehaviorHit { behavior: Behavior, evidence: String, via_import: bool }

fn first_present(needles: &[&'static str], folded: &[u8], imports: &Imports) -> Option<(&'static str, bool)> {
    for &n in needles {
        if imports.has(n) { return Some((n, true)); }
        if find_first_variant(folded, &needle_variants(n)).is_some() { return Some((n, false)); }
    }
    None
}

fn detect_behaviors(folded: &[u8], imports: &Imports) -> Vec<BehaviorHit> {
    let mut hits = Vec::new();
    if let Some((n, via_import)) = first_present(NETWORK_NEEDLES, folded, imports) {
        hits.push(BehaviorHit { behavior: Behavior::Network, evidence: n.to_string(), via_import });
    }
    let autostart = first_present(AUTOSTART_NEEDLES, folded, imports).or_else(|| {
        let a = first_present(&["schtasks"], folded, imports)?;
        first_present(&["/create"], folded, imports)?;
        Some(("schtasks /create", a.1))
    });
    if let Some((n, via_import)) = autostart {
        hits.push(BehaviorHit { behavior: Behavior::Autostart, evidence: n.to_string(), via_import });
    }
    let file_enc = first_present(RANSOM_NEEDLES, folded, imports).or_else(|| {
        let c = first_present(CRYPTO_NEEDLES, folded, imports)?;
        let e = first_present(ENUM_NEEDLES, folded, imports)?;
        Some(("crypto API + file enumeration", c.1 && e.1))
    });
    if let Some((n, via_import)) = file_enc {
        hits.push(BehaviorHit { behavior: Behavior::FileEncryption, evidence: n.to_string(), via_import });
    }
    hits
}

fn is_sidecar_ext(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).map(|e| matches!(e.to_ascii_lowercase().as_str(), "nfo" | "txt" | "diz")).unwrap_or(false)
}

fn collect_sidecars(path: &Path) -> Vec<Sidecar> {
    let dir = match path.parent() { Some(p) if !p.as_os_str().is_empty() => p, _ => Path::new(".") };
    let Ok(read_dir) = fs::read_dir(dir) else { return Vec::new(); };
    let mut paths: Vec<PathBuf> = read_dir.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_file() && is_sidecar_ext(p)).collect();
    paths.sort_by_key(|p| {
        let is_txt = p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("txt")).unwrap_or(false);
        (is_txt, p.clone())
    });
    let mut out = Vec::new();
    for p in paths.into_iter().take(MAX_SIDECAR_FILES) {
        let small_enough = fs::metadata(&p).map(|m| m.len() <= MAX_SIDECAR_SIZE).unwrap_or(false);
        if !small_enough { continue; }
        if let Ok(bytes) = fs::read(&p) { out.push(Sidecar { path: p.to_string_lossy().into_owned(), bytes }); }
    }
    out
}

fn mk_finding(path: &str, line: usize, kind: &str, value: String, entropy: f64) -> Finding {
    Finding { file_path: path.to_string(), line_number: line, secret_type: kind.to_string(), masked_value: value, entropy }
}

fn explain(pirate_score: u32, behaviors: &[Behavior], high_entropy: bool, verdict: Verdict, parse_error: Option<&str>) -> Vec<String> {
    let has_pirate = pirate_score >= PIRATE_SCORE_THRESHOLD;
    let mut r = Vec::new();
    if let Some(e) = parse_error { r.push(format!("PE не разобран ({e}): анализ только по имени и строкам.")); }
    if has_pirate { r.push(format!("Пиратские маркеры: {pirate_score} очк. (порог {PIRATE_SCORE_THRESHOLD}).")); }
    else if pirate_score > 0 { r.push(format!("Слабые пиратские признаки: {pirate_score} очк. — недостаточно.")); }
    if high_entropy { r.push("Есть секции с высокой энтропией (упаковка/шифрование).".to_string()); }
    if !behaviors.is_empty() {
        let list: Vec<&str> = behaviors.iter().map(|b| b.as_str()).collect();
        r.push(format!("Поведенческие признаки: {}.", list.join(", ")));
    }
    r.push(match (verdict, has_pirate) {
        (Verdict::LikelyCrack, _) => "LikelyCrack: есть пиратские маркеры, вредоносного поведения нет. Это НЕ гарантия безопасности.".to_string(),
        (Verdict::Suspicious, true) => "Suspicious: маркеры кряка + поведение вредоноса (возможен троян).".to_string(),
        (Verdict::Suspicious, false) => "Suspicious: высокая энтропия + поведение вредоноса без пиратских маркеров.".to_string(),
        (Verdict::Unknown, _) => "Unknown: недостаточно признаков.".to_string(),
    });
    r
}

#[cfg(test)]
mod tests {
    // Тесты опущены для экономии места, но в оригинале они были
}