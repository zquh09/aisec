//! src/yara_scanner.rs
//!
//! YARA-сканер на базе `yara-x`.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use yara_x::{Compiler, Rules, ScanResults, Scanner, SourceCode};

const RULES_DIR_NAME: &str = "rules";
const MAX_DIR_DEPTH: usize = 8;
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_IN_MEMORY_SIZE: u64 = 64 * 1024 * 1024;

pub fn init_yara() -> Result<Rules, String> {
    let (rules, problems) = init_yara_with_report()?;
    for p in &problems {
        eprintln!("[yara] {p}");
    }
    Ok(rules)
}

pub fn init_yara_with_report() -> Result<(Rules, Vec<String>), String> {
    let mut compiler = Compiler::new();
    let mut problems: Vec<String> = Vec::new();

    let Some(dir) = find_rules_dir() else {
        problems.push("Папка «rules» не найдена — YARA работает с пустым набором правил".into());
        return Ok((compiler.build(), problems));
    };

    let mut files: Vec<PathBuf> = Vec::new();
    collect_rule_files(&dir, 0, &mut files, &mut problems);
    files.sort();

    if files.is_empty() {
        problems.push(format!("В {} нет файлов .yar/.yara", dir.display()));
        return Ok((compiler.build(), problems));
    }

    let mut loaded = 0usize;
    for (idx, path) in files.iter().enumerate() {
        match add_rule_file(&mut compiler, path, idx) {
            Ok(()) => loaded += 1,
            Err(e) => problems.push(e),
        }
    }

    if loaded == 0 {
        return Err(format!("Не удалось скомпилировать ни одного файла правил:\n{}", problems.join("\n")));
    }

    Ok((compiler.build(), problems))
}

fn find_rules_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(RULES_DIR_NAME));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join(RULES_DIR_NAME));
    }

    candidates.into_iter().find(|p| p.is_dir())
}

fn collect_rule_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>, problems: &mut Vec<String>) {
    if depth > MAX_DIR_DEPTH { return; }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            problems.push(format!("Не удалось прочитать папку {}: {e}", dir.display()));
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rule_files(&path, depth + 1, out, problems);
        } else if is_rule_file(&path) {
            out.push(path);
        }
    }
}

fn is_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| { let e = e.to_ascii_lowercase(); e == "yar" || e == "yara" })
        .unwrap_or(false)
}

fn add_rule_file(compiler: &mut Compiler<'_>, path: &Path, idx: usize) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: не удалось прочитать файл: {e}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let source = text.trim_start_matches('\u{feff}');
    let origin = path.to_string_lossy().into_owned();

    let mut probe = Compiler::new();
    probe.add_source(SourceCode::from(source).with_origin(&origin))
        .map_err(|e| format!("{}: ошибка компиляции: {e}", path.display()))?;

    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("rules");
    let ns: String = stem.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    compiler.new_namespace(&format!("{ns}_{idx}"));

    compiler.add_source(SourceCode::from(source).with_origin(&origin))
        .map_err(|e| format!("{}: ошибка компиляции: {e}", path.display()))?;

    Ok(())
}

pub fn scan_with_yara(file_path: &Path, rules: &Rules) -> Result<Vec<String>, String> {
    let meta = fs::metadata(file_path).map_err(|e| format!("Не удалось открыть {}: {e}", file_path.display()))?;
    if !meta.is_file() { return Err(format!("{} — не файл", file_path.display())); }

    let mut scanner = Scanner::new(rules);
    scanner.set_timeout(SCAN_TIMEOUT);

    let names = if meta.len() <= MAX_IN_MEMORY_SIZE {
        let data = fs::read(file_path).map_err(|e| format!("Не удалось прочитать {}: {e}", file_path.display()))?;
        let results = scanner.scan(&data).map_err(|e| format!("YARA: ошибка сканирования {}: {e}", file_path.display()))?;
        matching_names(results)
    } else {
        let results = scanner.scan_file(file_path).map_err(|e| format!("YARA: ошибка сканирования {}: {e}", file_path.display()))?;
        matching_names(results)
    };

    Ok(names)
}

fn matching_names(results: ScanResults<'_, '_>) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for rule in results.matching_rules() {
        let id = rule.identifier().to_string();
        if !names.contains(&id) {
            names.push(id);
        }
    }
    names
}