use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, vec2, Align, Align2, Color32, CursorIcon, FontFamily, FontId, Frame, Layout, Margin,
    Rect, RichText, Rounding, ScrollArea, Sense, Stroke, TextEdit, TextStyle, Ui,
};

use crate::config::{self, AppConfig};
use crate::signature_check::{self, SignatureStatus};
use crate::virustotal;
use crate::report_export;
use crate::privacy_audit;

const BG: Color32 = Color32::from_rgb(0x12, 0x12, 0x12);
const PANEL: Color32 = Color32::from_rgb(0x1E, 0x1E, 0x1E);
const OUTPUT_BG: Color32 = Color32::from_rgb(0x0D, 0x0D, 0x0D);
const CONTROL: Color32 = Color32::from_rgb(0x2A, 0x2A, 0x2A);
const CONTROL_HOVER: Color32 = Color32::from_rgb(0x36, 0x36, 0x36);
const BORDER: Color32 = Color32::from_rgb(0x33, 0x33, 0x33);
const HOVER_BG: Color32 = Color32::from_rgb(0x29, 0x29, 0x29);
const SELECTED_BG: Color32 = Color32::from_rgb(0x2E, 0x27, 0x0A);

const ACCENT: Color32 = Color32::from_rgb(0xFF, 0xCC, 0x00);
const ACCENT_DIM: Color32 = Color32::from_rgb(0x8A, 0x70, 0x00);
const ON_ACCENT: Color32 = Color32::from_rgb(0x12, 0x12, 0x12);

const TEXT: Color32 = Color32::from_rgb(0xE6, 0xE6, 0xE6);
const TEXT_DIM: Color32 = Color32::from_rgb(0xB0, 0xB0, 0xB0);
const TEXT_MUTED: Color32 = Color32::from_rgb(0x80, 0x80, 0x80);
const OK: Color32 = Color32::from_rgb(0x4C, 0xAF, 0x50);
const DANGER: Color32 = Color32::from_rgb(0xFF, 0x5C, 0x5C);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab { Scan, Guard, Canary, Crack, Startup, Processes, Watcher, Privacy, Settings }

impl Tab {
    const ALL: [Tab; 9] = [Tab::Scan, Tab::Guard, Tab::Canary, Tab::Crack, Tab::Startup, Tab::Processes, Tab::Watcher, Tab::Privacy, Tab::Settings];
    fn icon(self) -> &'static str {
        match self { Tab::Scan => "📁", Tab::Guard => "🛡", Tab::Canary => "🎯", Tab::Crack => "🔬", Tab::Startup => "🚀", Tab::Processes => "📊", Tab::Watcher => "👁", Tab::Privacy => "🔒", Tab::Settings => "⚙️" }
    }
    fn title(self) -> &'static str {
        match self { Tab::Scan => "Сканер", Tab::Guard => "Защита", Tab::Canary => "Ловушки", Tab::Crack => "Анализ EXE", Tab::Startup => "Автозагрузка", Tab::Processes => "Процессы", Tab::Watcher => "Наблюдение", Tab::Privacy => "Приватность", Tab::Settings => "Настройки" }
    }
    fn tooltip(self) -> &'static str {
        match self {
            Tab::Scan => "Сканирование папки на секреты.",
            Tab::Guard => "Проверка промптов на инъекции.",
            Tab::Canary => "Генерация ловушек.",
            Tab::Crack => "Анализ EXE на кряк/вирус.",
            Tab::Startup => "Программы в автозагрузке.",
            Tab::Processes => "Список процессов (CPU, RAM, подозрительные пути).",
            Tab::Watcher => "Слежка за папкой Загрузок на новые EXE/DLL.",
            Tab::Privacy => "Аудит утечек DNS, IPv6 и локальных IP.",
            Tab::Settings => "API ключи и конфигурация.",
        }
    }
}

struct Outcome { ok: bool, text: String }
enum JobPoll<T> { Pending, Done(T), Crashed }

struct Job<T> { rx: Receiver<T> }
impl<T: Send + 'static> Job<T> {
    fn spawn<F>(ctx: egui::Context, work: F) -> Self where F: FnOnce() -> T + Send + 'static {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || { let result = work(); let _ = tx.send(result); ctx.request_repaint(); });
        Self { rx }
    }
    fn poll(&self) -> JobPoll<T> {
        match self.rx.try_recv() {
            Ok(value) => JobPoll::Done(value),
            Err(TryRecvError::Empty) => JobPoll::Pending,
            Err(TryRecvError::Disconnected) => JobPoll::Crashed,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Status { #[default] Idle, Running, Done, Failed }

#[derive(Default)]
struct Runner {
    job: Option<Job<Outcome>>,
    status: Status,
    started: Option<Instant>,
    elapsed: Duration,
    text: String,
}

impl Runner {
    fn is_running(&self) -> bool { self.job.is_some() }
    fn start<F>(&mut self, ctx: &egui::Context, initial_text: String, work: F) where F: FnOnce() -> Outcome + Send + 'static {
        if self.is_running() { return; }
        self.text = initial_text;
        self.status = Status::Running;
        self.started = Some(Instant::now());
        self.elapsed = Duration::ZERO;
        self.job = Some(Job::spawn(ctx.clone(), work));
    }
    fn fail(&mut self, message: impl Into<String>) { self.text = message.into(); self.status = Status::Failed; self.elapsed = Duration::ZERO; }
    fn clear(&mut self) { self.text.clear(); self.status = Status::Idle; self.elapsed = Duration::ZERO; }
    fn push_text(&mut self, extra: &str) {
        if extra.is_empty() { return; }
        if !self.text.is_empty() && !self.text.ends_with('\n') { self.text.push('\n'); }
        self.text.push_str(extra);
    }
    fn poll(&mut self) {
        let Some(job) = &self.job else { return; };
        let result = match job.poll() {
            JobPoll::Pending => return,
            JobPoll::Done(outcome) => Some(outcome),
            JobPoll::Crashed => None,
        };
        self.job = None;
        self.elapsed = self.started.take().map(|s| s.elapsed()).unwrap_or_default();
        match result {
            Some(outcome) => { self.push_text(&outcome.text); self.status = if outcome.ok { Status::Done } else { Status::Failed }; }
            None => { self.push_text("✖ Ошибка: задача аварийно завершилась."); self.status = Status::Failed; }
        }
    }
}

#[derive(Default)]
struct ScanState { path: String, excludes: String, json: bool, runner: Runner }
struct GuardState { prompt: String, explain: bool, runner: Runner }
#[derive(Default)]
struct CanaryState { count: usize, types: String, runner: Runner }
#[derive(Default)]
struct CrackState { path: String, runner: Runner }
#[derive(Default)]
struct StartupState { runner: Runner }
#[derive(Default)]
struct ProcessState { runner: Runner }
#[derive(Default)]
struct PrivacyState { runner: Runner }
struct WatcherState { path: String, log: String, rx: Option<Receiver<String>> }

pub struct AisecApp {
    tab: Tab,
    config: AppConfig,
    scan: ScanState,
    guard: GuardState,
    canary: CanaryState,
    crack: CrackState,
    startup: StartupState,
    process: ProcessState,
    privacy: PrivacyState,
    watcher: WatcherState,
    settings_vt_key: String,
    settings_saved_at: Option<Instant>,
}

impl AisecApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);
        let cfg = config::load_config();
        let key = cfg.vt_api_key.clone();
        Self {
            tab: Tab::Scan,
            scan: ScanState { path: cfg.scan_path.clone(), ..Default::default() },
            watcher: WatcherState { path: cfg.watcher_path.clone(), log: String::new(), rx: None },
            config: cfg,
            guard: GuardState { prompt: String::new(), explain: true, runner: Runner::default() },
            canary: CanaryState { count: 5, types: "api_key, token, password".to_owned(), runner: Runner::default() },
            crack: CrackState::default(),
            startup: StartupState::default(),
            process: ProcessState::default(),
            privacy: PrivacyState::default(),
            settings_vt_key: key,
            settings_saved_at: None,
        }
    }

    fn runners(&self) -> [&Runner; 7] { [&self.scan.runner, &self.guard.runner, &self.canary.runner, &self.crack.runner, &self.startup.runner, &self.process.runner, &self.privacy.runner] }

    fn poll_jobs(&mut self) {
        self.scan.runner.poll(); self.guard.runner.poll(); self.canary.runner.poll(); self.crack.runner.poll(); self.startup.runner.poll(); self.process.runner.poll(); self.privacy.runner.poll();
        if let Some(rx) = &self.watcher.rx {
            while let Ok(msg) = rx.try_recv() { self.watcher.log.push_str(&format!("{}\n", msg)); }
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Option<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().find_map(|f| f.path.clone()));
        if let Some(path) = dropped {
            let text = path.display().to_string();
            match self.tab {
                Tab::Scan => self.scan.path = text,
                Tab::Crack => self.crack.path = text,
                Tab::Watcher => self.watcher.path = text,
                _ => {}
            }
        }
    }

    fn show_sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar").exact_width(220.0).resizable(false)
            .frame(Frame::none().fill(PANEL).inner_margin(Margin::symmetric(12.0, 16.0)))
            .show(ctx, |ui| {
                ui.label(RichText::new("🛡 AISEC").size(22.0).strong().color(ACCENT));
                ui.label(RichText::new("AI Security Toolkit").size(12.0).color(TEXT_MUTED));
                ui.add_space(12.0); ui.separator(); ui.add_space(8.0);
                ui.spacing_mut().item_spacing.y = 4.0;
                for tab in Tab::ALL {
                    let selected = self.tab == tab;
                    let response = sidebar_tab(ui, tab, selected).on_hover_cursor(CursorIcon::PointingHand).on_hover_ui(|ui| { ui.set_max_width(240.0); ui.label(RichText::new(tab.tooltip()).size(12.0).color(TEXT_DIM)); });
                    if response.clicked() { self.tab = tab; }
                }
                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| { ui.label(RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).size(11.5).color(TEXT_MUTED)); });
            });
    }

    fn show_central(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().frame(Frame::none().fill(BG).inner_margin(Margin::same(22.0)))
            .show(ctx, |ui| match self.tab {
                Tab::Scan => self.ui_scan(ui, ctx),
                Tab::Guard => self.ui_guard(ui, ctx),
                Tab::Canary => self.ui_canary(ui, ctx),
                Tab::Crack => self.ui_crack(ui, ctx),
                Tab::Startup => self.ui_startup(ui, ctx),
                Tab::Processes => self.ui_processes(ui, ctx),
                Tab::Watcher => self.ui_watcher(ui),
                Tab::Privacy => self.ui_privacy(ui, ctx),
                Tab::Settings => self.ui_settings(ui),
            });
    }

    // ... (ui_scan, launch_scan, ui_guard, launch_guard, ui_canary, launch_canary, ui_crack, launch_crack, launch_virustotal, ui_startup, launch_startup, ui_processes, ui_watcher, ui_settings - оставляем без изменений, они уже есть в файле) ...
    // ВСТАВЬ ИХ СЮДА, Я ПОКАЖУ ТОЛЬКО НОВОЕ ДЛЯ ПРИМЕРА. 
    // НО ТАК КАК ТЫ ПРОСИЛ ФАЙЛ ЦЕЛИКОМ, Я СКОПИРУЮ ВСЁ.

    fn ui_scan(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "📁", "Сканер", "Проверка файла или папки.");
        card(ui, |ui| {
            field_label(ui, "Путь для сканирования");
            ui.add(TextEdit::singleline(&mut self.scan.path).hint_text(r"C:\Users\Downloads").desired_width(f32::INFINITY).font(TextStyle::Monospace));
            ui.add_space(6.0);
            field_label(ui, "Исключения (по одному пути в строке)");
            ui.add(TextEdit::multiline(&mut self.scan.excludes).hint_text("Необязательно").desired_rows(3).desired_width(f32::INFINITY).font(TextStyle::Monospace));
            ui.add_space(6.0);
            ui.checkbox(&mut self.scan.json, "Отчёт в формате JSON");
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let busy = self.scan.runner.is_running();
            if ui.add_enabled(!busy, primary_button("▶ Запустить сканирование")).clicked() { 
                self.config.scan_path = self.scan.path.clone();
                config::save_config(&self.config);
                self.launch_scan(ctx); 
            }
            if ui.add_enabled(!self.scan.runner.text.is_empty(), secondary_button("Экспорт в HTML")).clicked() {
                let text = self.scan.runner.text.clone();
                if report_export::export_html("report_scan.html", "Результаты сканирования", &text).is_ok() {
                    self.scan.runner.push_text("\n✔ Отчёт сохранён в report_scan.html");
                }
            }
            output_actions(ui, &mut self.scan.runner);
        });
        ui.add_space(2.0); status_line(ui, &self.scan.runner);
        output_box(ui, "scan_output", &self.scan.runner, "Здесь появится результат.");
    }

    fn launch_scan(&mut self, ctx: &egui::Context) {
        let path_text = clean_path(&self.scan.path);
        if path_text.is_empty() { self.scan.runner.fail("✖ Укажите путь."); return; }
        let path = PathBuf::from(&path_text);
        if !path.exists() { self.scan.runner.fail(format!("✖ Путь не найден: {path_text}")); return; }
        let excludes: Vec<PathBuf> = self.scan.excludes.lines().map(clean_path).filter(|s| !s.is_empty()).map(PathBuf::from).collect();
        let json = self.scan.json;
        self.scan.runner.start(ctx, format!("▶ Сканирование: {path_text}\n"), move || {
            match crate::scan::start_scan(path, excludes, json) {
                Ok(()) => Outcome { ok: true, text: "✔ Готово.".to_owned() },
                Err(e) => Outcome { ok: false, text: format!("✖ Ошибка: {e}") },
            }
        });
    }

    fn ui_guard(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "🛡", "Защита промптов", "Анализ текста промпта на инъекции.");
        card(ui, |ui| {
            field_label(ui, "Текст промпта");
            ui.push_id("guard_input_scroll", |ui| { ScrollArea::vertical().max_height(190.0).show(ui, |ui| { ui.add(TextEdit::multiline(&mut self.guard.prompt).hint_text("Вставьте промпт…").desired_rows(7).desired_width(f32::INFINITY).font(TextStyle::Monospace)); }); });
            ui.add_space(6.0);
            ui.checkbox(&mut self.guard.explain, "Подробное объяснение");
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let busy = self.guard.runner.is_running();
            if ui.add_enabled(!busy, primary_button("▶ Проверить промпт")).clicked() { self.launch_guard(ctx); }
            if ui.add_enabled(!busy && !self.guard.prompt.is_empty(), secondary_button("Очистить ввод")).clicked() { self.guard.prompt.clear(); }
            output_actions(ui, &mut self.guard.runner);
        });
        ui.add_space(2.0); status_line(ui, &self.guard.runner);
        output_box(ui, "guard_output", &self.guard.runner, "Здесь появится отчёт.");
    }

    fn launch_guard(&mut self, ctx: &egui::Context) {
        if self.guard.prompt.trim().is_empty() { self.guard.runner.fail("✖ Введите текст."); return; }
        let prompt = self.guard.prompt.clone(); let explain = self.guard.explain;
        self.guard.runner.start(ctx, String::new(), move || {
            let report = crate::prompt_guard::analyze_prompt(&prompt);
            Outcome { ok: true, text: report.format_text(explain) }
        });
    }

    fn ui_canary(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "🎯", "Ловушки", "Генерация canary-ловушек.");
        card(ui, |ui| {
            field_label(ui, "Количество ловушек");
            ui.add(egui::Slider::new(&mut self.canary.count, 1..=100).text("шт."));
            ui.add_space(6.0);
            field_label(ui, "Типы ловушек");
            ui.add(TextEdit::singleline(&mut self.canary.types).hint_text("api_key, token, password").desired_width(f32::INFINITY).font(TextStyle::Monospace));
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let busy = self.canary.runner.is_running();
            if ui.add_enabled(!busy, primary_button("▶ Сгенерировать")).clicked() { self.launch_canary(ctx); }
            output_actions(ui, &mut self.canary.runner);
        });
        ui.add_space(2.0); status_line(ui, &self.canary.runner);
        output_box(ui, "canary_output", &self.canary.runner, "Здесь появится журнал.");
    }

    fn launch_canary(&mut self, ctx: &egui::Context) {
        let types: Vec<String> = self.canary.types.split(',').map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()).collect();
        if types.is_empty() { self.canary.runner.fail("✖ Укажите тип."); return; }
        let count = self.canary.count.max(1);
        self.canary.runner.start(ctx, format!("▶ Генерация {} шт.\n", count), move || {
            crate::canary::generate_canaries(count, types);
            Outcome { ok: true, text: "✔ Готово.".to_owned() }
        });
    }

    fn ui_crack(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "🔬", "Анализ EXE", "Поиск признаков взлома и проверка по базам.");
        card(ui, |ui| {
            field_label(ui, "Путь к файлу");
            ui.add(TextEdit::singleline(&mut self.crack.path).hint_text(r"C:\Program Files\App\app.exe").desired_width(f32::INFINITY).font(TextStyle::Monospace));
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let busy = self.crack.runner.is_running();
            if ui.add_enabled(!busy, primary_button("▶ Локальный анализ")).clicked() { self.launch_crack(ctx); }
            
            let has_key = !self.settings_vt_key.is_empty();
            if ui.add_enabled(!busy && has_key, secondary_button("☁ VirusTotal")).clicked() { 
                self.launch_virustotal(ctx); 
            }
            if ui.add_enabled(!self.crack.runner.text.is_empty(), secondary_button("Экспорт в HTML")).clicked() {
                let text = self.crack.runner.text.clone();
                if report_export::export_html("report_crack.html", "Анализ EXE", &text).is_ok() {
                    self.crack.runner.push_text("\n✔ Отчёт сохранён в report_crack.html");
                }
            }
            output_actions(ui, &mut self.crack.runner);
        });
        ui.add_space(2.0); status_line(ui, &self.crack.runner);
        output_box(ui, "crack_output", &self.crack.runner, "Здесь появится вердикт.");
    }

    fn launch_crack(&mut self, ctx: &egui::Context) {
        let path_text = clean_path(&self.crack.path);
        if path_text.is_empty() { self.crack.runner.fail("✖ Укажите путь."); return; }
        let path = PathBuf::from(&path_text);
        if !path.is_file() { self.crack.runner.fail(format!("✖ Файл не найден: {path_text}")); return; }
        
        self.crack.runner.start(ctx, String::new(), move || {
            let sig_status = signature_check::check_signature(&path);
            let sig_text = match sig_status {
                SignatureStatus::Valid(signer) => format!("Подпись: ✔ Валидна ({})", signer),
                SignatureStatus::Invalid => "Подпись: ✖ Недействительна (взломана!)".to_string(),
                SignatureStatus::Unsigned => "Подпись: ⚠ Отсутствует".to_string(),
            };

            match crate::crack_detector::analyze_file(&path) {
                Ok(report) => {
                    let mut lines = vec![
                        format!("Файл: {}", path.display()),
                        sig_text,
                        format!("Вердикт: {}", dbg_text(&report.verdict)),
                        format!("Pirate score: {}", dbg_text(&report.pirate_score)),
                        "Причины:".to_owned()
                    ];
                    for reason in report.reasons.iter() { lines.push(format!("  • {}", dbg_text(reason))); }
                    Outcome { ok: true, text: lines.join("\n") }
                }
                Err(e) => Outcome { ok: false, text: format!("✖ Ошибка: {e:?}") },
            }
        });
    }

    fn launch_virustotal(&mut self, ctx: &egui::Context) {
        let path_text = clean_path(&self.crack.path);
        let path = PathBuf::from(&path_text);
        let key = self.settings_vt_key.clone();
        
        self.crack.runner.start(ctx, "▶ Отправка хеша в VirusTotal...\n".to_string(), move || {
            match virustotal::check_virustotal(&path, &key) {
                Ok(report) => {
                    let color = if report.positives > 0 { "🔴 ОПАСНО" } else { "🟢 ЧИСТО" };
                    let text = format!("VirusTotal: {}\nНайдено {} угроз из {} антивирусов.\nСсылка: {}", color, report.positives, report.total, report.permalink);
                    Outcome { ok: true, text }
                }
                Err(e) => Outcome { ok: false, text: format!("✖ Ошибка VT: {e}") },
            }
        });
    }

    fn ui_startup(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "🚀", "Автозагрузка", "Проверка программ в автозагрузке.");
        card(ui, |ui| { ui.label(RichText::new("Нажмите кнопку, чтобы собрать список.").color(TEXT_DIM)); });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let busy = self.startup.runner.is_running();
            if ui.add_enabled(!busy, primary_button("▶ Проверить")).clicked() { self.launch_startup(ctx); }
            output_actions(ui, &mut self.startup.runner);
        });
        ui.add_space(2.0); status_line(ui, &self.startup.runner);
        output_box(ui, "startup_output", &self.startup.runner, "Здесь появится отчёт.");
    }

    fn launch_startup(&mut self, ctx: &egui::Context) {
        self.startup.runner.start(ctx, String::new(), move || {
            let report = crate::startup_check::scan_startup();
            Outcome { ok: true, text: report.format() }
        });
    }

    fn ui_processes(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "📊", "Процессы", "Список активных процессов. Подозрительные пути помечены.");
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let busy = self.process.runner.is_running();
            if ui.add_enabled(!busy, primary_button("▶ Обновить список")).clicked() {
                self.process.runner.start(ctx, String::new(), move || {
                    let text = crate::process_scanner::scan_processes();
                    Outcome { ok: true, text }
                });
            }
            output_actions(ui, &mut self.process.runner);
        });
        ui.add_space(2.0); status_line(ui, &self.process.runner);
        output_box(ui, "process_output", &self.process.runner, "Нажмите кнопку для получения списка.");
    }

    fn ui_privacy(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "🔒", "Приватность", "Аудит утечек DNS, IPv6 и локальных IP (без обхода блокировок).");
        card(ui, |ui| { 
            ui.label(RichText::new("Программа проверит, не раскрываете ли вы свои данные. Это диагностика, а не VPN.").color(TEXT_DIM)); 
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let busy = self.privacy.runner.is_running();
            if ui.add_enabled(!busy, primary_button("▶ Запустить аудит")).clicked() {
                self.privacy.runner.start(ctx, String::new(), move || {
                    let report = privacy_audit::run_privacy_audit();
                    let mut out = String::new();
                    
                    out.push_str(if report.dns_leak { "🔴 DNS-утечка: ОБНАРУЖЕНА\n" } else { "🟢 DNS-утечка: НЕТ\n" });
                    out.push_str(if report.ipv6_active { "🟡 IPv6 активен: ДА (риск утечки)\n" } else { "🟢 IPv6 активен: НЕТ\n" });
                    out.push_str(if report.webrtc_leak { "🟡 Локальный IP раскрыт: ДА\n" } else { "🟢 Локальный IP раскрыт: НЕТ\n" });
                    
                    if !report.warnings.is_empty() {
                        out.push_str("\nПредупреждения:\n");
                        for w in report.warnings { out.push_str(&format!(" - {}\n", w)); }
                    }
                    Outcome { ok: true, text: out }
                });
            }
            output_actions(ui, &mut self.privacy.runner);
        });
        ui.add_space(2.0); status_line(ui, &self.privacy.runner);
        output_box(ui, "privacy_output", &self.privacy.runner, "Нажмите кнопку для диагностики сети.");
    }

    fn ui_watcher(&mut self, ui: &mut Ui) {
        page_header(ui, "👁", "Наблюдение", "Слежка за папкой на новые EXE/DLL. Файлы проверяются в фоне.");
        card(ui, |ui| {
            field_label(ui, "Путь к папке (например, Downloads)");
            ui.add(TextEdit::singleline(&mut self.watcher.path).hint_text(r"C:\Users\Downloads").desired_width(f32::INFINITY).font(TextStyle::Monospace));
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(self.watcher.rx.is_none(), primary_button("▶ Начать наблюдение")).clicked() {
                let path = clean_path(&self.watcher.path);
                if !path.is_empty() {
                    self.config.watcher_path = path.clone();
                    config::save_config(&self.config);
                    
                    let (tx, rx) = mpsc::channel();
                    crate::watcher::start_watching(&path, tx);
                    self.watcher.rx = Some(rx);
                    self.watcher.log.push_str(&format!("▶ Наблюдение запущено: {}\n", path));
                }
            }
            if ui.add_enabled(self.watcher.rx.is_some(), secondary_button("Остановить")).clicked() {
                self.watcher.rx = None;
                self.watcher.log.push_str("■ Наблюдение остановлено.\n");
            }
            if ui.add_enabled(!self.watcher.log.is_empty(), secondary_button("Очистить лог")).clicked() {
                self.watcher.log.clear();
            }
        });
        ui.add_space(4.0);
        ui.separator();
        ui.add_space(4.0);
        egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(&self.watcher.log).monospace().size(13.5).color(TEXT)).selectable(true));
        });
    }

    fn ui_settings(&mut self, ui: &mut Ui) {
        page_header(ui, "⚙️", "Настройки", "Конфигурация API и ключи.");
        card(ui, |ui| {
            field_label(ui, "VirusTotal API Key");
            ui.add(TextEdit::singleline(&mut self.settings_vt_key).hint_text("Вставьте ваш API ключ с virustotal.com").desired_width(f32::INFINITY).font(TextStyle::Monospace));
            ui.add_space(10.0);
            if ui.button("Сохранить ключ").clicked() {
                self.config.vt_api_key = self.settings_vt_key.clone();
                config::save_config(&self.config);
                self.settings_saved_at = Some(Instant::now());
            }
            if let Some(saved) = self.settings_saved_at {
                if saved.elapsed().as_secs() < 2 {
                    ui.colored_label(OK, "✔ Сохранено");
                } else {
                    self.settings_saved_at = None;
                }
            }
        });
    }
}

impl eframe::App for AisecApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_jobs(); self.handle_dropped_files(ctx);
        if self.runners().iter().any(|r| r.is_running()) || self.watcher.rx.is_some() { ctx.request_repaint_after(Duration::from_millis(100)); }
        self.show_sidebar(ctx); self.show_central(ctx);
    }
}

pub fn run_gui() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("AI Security Toolkit")
        .with_inner_size([1100.0, 720.0])
        .with_min_inner_size([860.0, 540.0]);

    if let Ok(icon_bytes) = std::fs::read("icon.png") {
        if let Ok(icon) = eframe::icon_data::from_png_bytes(&icon_bytes) {
            viewport = viewport.with_icon(icon);
        }
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    
    eframe::run_native("AI Security Toolkit", options, Box::new(|cc| Ok(Box::new(AisecApp::new(cc)))))
}

fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG; v.window_fill = PANEL; v.window_stroke = Stroke::new(1.0_f32, BORDER);
    v.extreme_bg_color = OUTPUT_BG; v.faint_bg_color = PANEL; v.hyperlink_color = ACCENT;
    v.selection.bg_fill = Color32::from_rgba_unmultiplied(0xFF, 0xCC, 0x00, 70);
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    let r = Rounding::same(6.0);
    v.widgets.noninteractive.bg_fill = PANEL; v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER); v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT); v.widgets.noninteractive.rounding = r;
    v.widgets.inactive.bg_fill = CONTROL; v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER); v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT); v.widgets.inactive.rounding = r;
    v.widgets.hovered.bg_fill = CONTROL_HOVER; v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT_DIM); v.widgets.hovered.fg_stroke = Stroke::new(1.5_f32, Color32::WHITE); v.widgets.hovered.rounding = r;
    v.widgets.active.bg_fill = CONTROL_HOVER; v.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT); v.widgets.active.fg_stroke = Stroke::new(1.5_f32, ACCENT); v.widgets.active.rounding = r;
    ctx.set_visuals(v);
    ctx.style_mut(|style| {
        style.text_styles = [(TextStyle::Heading, FontId::new(24.0, FontFamily::Proportional)), (TextStyle::Body, FontId::new(14.5, FontFamily::Proportional)), (TextStyle::Button, FontId::new(14.5, FontFamily::Proportional)), (TextStyle::Monospace, FontId::new(13.5, FontFamily::Monospace)), (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional))].into();
        style.spacing.item_spacing = vec2(10.0, 8.0); style.spacing.button_padding = vec2(14.0, 7.0); style.spacing.interact_size.y = 30.0;
    });
}

fn sidebar_tab(ui: &mut Ui, tab: Tab, selected: bool) -> egui::Response {
    let size = vec2(ui.available_width(), 46.0); let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let hovered = response.hovered(); let background = if selected { SELECTED_BG } else if hovered { HOVER_BG } else { Color32::TRANSPARENT };
        let color = if selected { ACCENT } else if hovered { Color32::WHITE } else { TEXT_DIM };
        let painter = ui.painter(); painter.rect_filled(rect, Rounding::same(8.0), background);
        if selected { let bar = Rect::from_min_size(rect.left_top() + vec2(0.0, 9.0), vec2(3.0, rect.height() - 18.0)); painter.rect_filled(bar, Rounding::same(2.0), ACCENT); }
        painter.text(rect.left_center() + vec2(18.0, 0.0), Align2::LEFT_CENTER, tab.icon(), FontId::proportional(19.0), color);
        painter.text(rect.left_center() + vec2(52.0, 0.0), Align2::LEFT_CENTER, tab.title(), FontId::proportional(15.5), color);
    }
    response
}

fn page_header(ui: &mut Ui, icon: &str, title: &str, subtitle: &str) {
    ui.label(RichText::new(format!("{icon}  {title}")).size(26.0).strong().color(ACCENT));
    ui.label(RichText::new(subtitle).size(13.0).color(TEXT_DIM)); ui.add_space(10.0);
}
fn field_label(ui: &mut Ui, text: &str) { ui.label(RichText::new(text).size(13.0).strong().color(TEXT_DIM)); }
fn card(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) { Frame::none().fill(PANEL).stroke(Stroke::new(1.0_f32, BORDER)).rounding(Rounding::same(10.0)).inner_margin(Margin::same(16.0)).show(ui, |ui| { ui.set_width(ui.available_width()); add_contents(ui); }); ui.add_space(6.0); }
fn primary_button(label: &str) -> impl egui::Widget { egui::Button::new(RichText::new(label).strong().color(ON_ACCENT)).fill(ACCENT).stroke(Stroke::NONE).rounding(Rounding::same(6.0)).min_size(vec2(200.0, 34.0)) }
fn secondary_button(label: &str) -> impl egui::Widget { egui::Button::new(RichText::new(label).color(TEXT)).fill(CONTROL).stroke(Stroke::new(1.0_f32, BORDER)).rounding(Rounding::same(6.0)).min_size(vec2(110.0, 34.0)) }

fn output_actions(ui: &mut Ui, runner: &mut Runner) {
    if ui.add_enabled(!runner.text.is_empty(), secondary_button("Копировать")).clicked() { ui.ctx().copy_text(runner.text.clone()); }
    let can_clear = !runner.is_running() && (!runner.text.is_empty() || runner.status != Status::Idle);
    if ui.add_enabled(can_clear, secondary_button("Очистить")).clicked() { runner.clear(); }
}

fn status_line(ui: &mut Ui, runner: &Runner) {
    ui.horizontal(|ui| match runner.status {
        Status::Idle => { ui.label(RichText::new("Готово к запуску").size(13.0).color(TEXT_MUTED)); }
        Status::Running => { ui.add(egui::Spinner::new().size(14.0).color(ACCENT)); let secs = runner.started.map(|s| s.elapsed().as_secs_f32()).unwrap_or(0.0); ui.label(RichText::new(format!("Выполняется… {secs:.1} с")).size(13.0).color(ACCENT)); }
        Status::Done => { ui.label(RichText::new(format!("✔ Завершено за {:.1} с", runner.elapsed.as_secs_f32())).size(13.0).color(OK)); }
        Status::Failed => { let text = if runner.elapsed.is_zero() { "✖ Ошибка".to_owned() } else { format!("✖ Ошибка после {:.1} с", runner.elapsed.as_secs_f32()) }; ui.label(RichText::new(text).size(13.0).color(DANGER)); }
    });
}

fn output_box(ui: &mut Ui, key: &str, runner: &Runner, placeholder: &str) {
    let total = ui.available_height().max(160.0);
    Frame::none().fill(OUTPUT_BG).stroke(Stroke::new(1.0_f32, BORDER)).rounding(Rounding::same(8.0)).inner_margin(Margin::same(12.0)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.push_id(key, |ui| { ScrollArea::vertical().auto_shrink([false, false]).max_height(total - 28.0).show(ui, |ui| {
            ui.set_width(ui.available_width());
            if runner.text.is_empty() { let message = if runner.is_running() { "Выполняется…" } else { placeholder }; ui.label(RichText::new(message).monospace().color(TEXT_MUTED)); }
            else { ui.add(egui::Label::new(RichText::new(&runner.text).monospace().size(13.5).color(TEXT)).selectable(true)); }
        }); });
    });
}

fn clean_path(raw: &str) -> String { raw.trim().trim_matches('"').trim().to_owned() }
fn dbg_text<T: Debug>(value: &T) -> String { format!("{value:?}").trim_matches('"').to_owned() }