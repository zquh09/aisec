use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};
use std::sync::Arc;
use chrono::{DateTime, Local};

use eframe::egui::{
    self, vec2, Align, Align2, Color32, CursorIcon, FontFamily, FontId, Frame, Layout, Margin,
    Rect, RichText, Rounding, ScrollArea, Sense, Stroke, TextEdit, TextStyle, Ui,
};

use crate::config::{self, AppConfig};
use crate::signature_check::{self, SignatureStatus};
use crate::virustotal;
use crate::report_export;
use crate::privacy_audit;
use crate::full_scan;
use crate::hash_scanner;
use crate::quarantine;
use crate::network_monitor;
use crate::yara_scanner;
use crate::file_integrity;
use crate::yara_manager;
use crate::system_check;
use crate::real_time_protection;
use crate::notifications;
use crate::ransomware_shield;
use crate::scheduler_audit;
use crate::process_killer;
use crate::tray;
use crate::updater;

const BG_DARK: Color32 = Color32::from_rgb(18, 18, 18);
const PANEL_BG: Color32 = Color32::from_rgb(30, 30, 30);
const ACCENT_YELLOW: Color32 = Color32::from_rgb(255, 204, 0);
const TEXT_PRIMARY: Color32 = Color32::from_rgb(240, 240, 240);
const TEXT_MUTED: Color32 = Color32::from_rgb(160, 160, 160);
const OUTPUT_BG: Color32 = Color32::from_rgb(12, 12, 12);
const OK: Color32 = Color32::from_rgb(76, 175, 80);
const DANGER: Color32 = Color32::from_rgb(255, 92, 92);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab { Dashboard, RealTime, Ransomware, Scheduler, System, FullScan, Network, Quarantine, Scan, Yara, Integrity, Guard, Canary, Crack, Startup, Processes, Watcher, Privacy, Settings }

impl Tab {
    const ALL: [Tab; 19] = [Tab::Dashboard, Tab::RealTime, Tab::Ransomware, Tab::Scheduler, Tab::System, Tab::FullScan, Tab::Network, Tab::Quarantine, Tab::Scan, Tab::Yara, Tab::Integrity, Tab::Guard, Tab::Canary, Tab::Crack, Tab::Startup, Tab::Processes, Tab::Watcher, Tab::Privacy, Tab::Settings];
    
    fn icon(self) -> &'static str {
        match self { 
            Tab::Dashboard => "⌂", Tab::RealTime => "◉", Tab::Ransomware => "☣", Tab::Scheduler => "⏱", Tab::System => "☼", 
            Tab::FullScan => "❖", Tab::Network => "☍", Tab::Quarantine => "✖", Tab::Scan => "⌕", Tab::Yara => "✚", 
            Tab::Integrity => "❉", Tab::Guard => "☗", Tab::Canary => "◎", Tab::Crack => "⚒", Tab::Startup => "⏻", 
            Tab::Processes => "≡", Tab::Watcher => "◉", Tab::Privacy => "⌬", Tab::Settings => "⚙" 
        }
    }
    
    fn title(self) -> &'static str {
        match self { 
            Tab::Dashboard => "Главная", Tab::RealTime => "Защита (RTP)", Tab::Ransomware => "Анти-Шифровальщик", Tab::Scheduler => "Планировщик", 
            Tab::System => "Система", Tab::FullScan => "Сканер ПК", Tab::Network => "Сеть", Tab::Quarantine => "Карантин", 
            Tab::Scan => "Секреты", Tab::Yara => "YARA", Tab::Integrity => "Целостность", Tab::Guard => "Защита промптов", 
            Tab::Canary => "Ловушки", Tab::Crack => "Анализ EXE", Tab::Startup => "Автозагрузка", Tab::Processes => "Процессы", 
            Tab::Watcher => "Наблюдение", Tab::Privacy => "Приватность", Tab::Settings => "Настройки" 
        }
    }
    
    fn tooltip(self) -> &'static str {
        match self {
            Tab::Dashboard => "Общий статус.",
            Tab::RealTime => "Защита в реальном времени (RTP).",
            Tab::Ransomware => "Защита от шифрования файлов.",
            Tab::Scheduler => "Проверка задач Windows.",
            Tab::System => "Проверка HOSTS и Defender.",
            Tab::FullScan => "Полное сканирование.",
            Tab::Network => "TCP-подключения.",
            Tab::Quarantine => "Зашифрованные файлы.",
            Tab::Scan => "Сканирование на секреты.",
            Tab::Yara => "Сигнатуры YARA.",
            Tab::Integrity => "Контроль изменений.",
            Tab::Guard => "Защита LLM от инъекций.",
            Tab::Canary => "Генерация ловушек.",
            Tab::Crack => "Анализ EXE.",
            Tab::Startup => "Автозагрузка.",
            Tab::Processes => "Процессы (Kill PID).",
            Tab::Watcher => "Слежка за папкой.",
            Tab::Privacy => "Утечки DNS.",
            Tab::Settings => "Настройки.",
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
#[derive(Default)]
struct FullScanState { rx: Option<Receiver<String>>, log: String, last_virus: Option<PathBuf> }
#[derive(Default)]
struct NetworkState { runner: Runner }
#[derive(Default)]
struct QuarantineState { files: Vec<PathBuf>, log: String }
#[derive(Default)]
struct YaraState { path: String, rules: Option<Arc<yara_x::Rules>>, runner: Runner, update_rx: Option<Receiver<Result<usize, String>>>, status: String }
#[derive(Default)]
struct IntegrityState { runner: Runner }
#[derive(Default)]
struct SystemState { runner: Runner }
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

struct RtpState {
    is_running: bool,
    log: String,
    rx: Option<Receiver<String>>,
    watcher: Option<notify::RecommendedWatcher>,
}
impl Default for RtpState {
    fn default() -> Self { Self { is_running: false, log: String::new(), rx: None, watcher: None } }
}

struct RansomwareState {
    rx: Option<Receiver<String>>,
    log: String,
}
impl Default for RansomwareState {
    fn default() -> Self { Self { rx: None, log: String::new() } }
}

pub struct AisecApp {
    tab: Tab,
    config: AppConfig,
    scan: ScanState,
    full_scan: FullScanState,
    network: NetworkState,
    quarantine: QuarantineState,
    yara: YaraState,
    integrity: IntegrityState,
    system: SystemState,
    guard: GuardState,
    canary: CanaryState,
    crack: CrackState,
    startup: StartupState,
    process: ProcessState,
    privacy: PrivacyState,
    watcher: WatcherState,
    rtp: RtpState,
    ransomware: RansomwareState,
    scheduler: SystemState,
    kill_pid_input: String,
    settings_vt_key: String,
    settings_whitelist: String,
    settings_saved_at: Option<Instant>,
    last_scan_time: Option<DateTime<Local>>,
    
    // Поля для трея и обновлений
    tray: Option<tray_icon::TrayIcon>,
    allow_quit: bool,
    update_rx: Option<Receiver<Result<Option<String>, String>>>,
    update_url: Option<String>,
}

impl AisecApp {
    fn new(cc: &eframe::CreationContext<'_>, tray_icon: Option<tray_icon::TrayIcon>) -> Self {
        let mut fonts = egui::FontDefinitions::default();
        
        if let Ok(font_data) = std::fs::read("resources/Inter-Regular.ttf") {
            fonts.font_data.insert("Inter".to_owned(), egui::FontData::from_owned(font_data));
            if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
                family.insert(0, "Inter".to_owned());
            }
        }
        
        if let Ok(font_data) = std::fs::read(r"C:\Windows\Fonts\seguisym.ttf") {
            fonts.font_data.insert("seguisym".to_owned(), egui::FontData::from_owned(font_data));
            if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
                family.push("seguisym".to_owned());
            }
        }
        if let Ok(font_data) = std::fs::read(r"C:\Windows\Fonts\seguiemj.ttf") {
            fonts.font_data.insert("seguiemj".to_owned(), egui::FontData::from_owned(font_data));
            if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
                family.push("seguiemj".to_owned());
            }
        }
        
        cc.egui_ctx.set_fonts(fonts);

        apply_theme(&cc.egui_ctx);
        let cfg = config::load_config();
        let key = cfg.vt_api_key.clone();
        let wl = cfg.whitelist.join("\n");
        
        // Запускаем фоновый поток проверки обновлений
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || { let _ = tx.send(updater::check_for_updates()); });
        
        Self {
            tab: Tab::Dashboard,
            scan: ScanState { path: cfg.scan_path.clone(), ..Default::default() },
            full_scan: FullScanState::default(),
            network: NetworkState::default(),
            quarantine: QuarantineState { files: Self::get_quarantine_files(), log: String::new() },
            yara: YaraState::default(),
            integrity: IntegrityState::default(),
            system: SystemState::default(),
            watcher: WatcherState { path: cfg.watcher_path.clone(), log: String::new(), rx: None },
            rtp: RtpState::default(),
            ransomware: RansomwareState::default(),
            scheduler: SystemState::default(),
            kill_pid_input: String::new(),
            config: cfg,
            guard: GuardState { prompt: String::new(), explain: true, runner: Runner::default() },
            canary: CanaryState { count: 5, types: "api_key, token, password".to_owned(), runner: Runner::default() },
            crack: CrackState::default(),
            startup: StartupState::default(),
            process: ProcessState::default(),
            privacy: PrivacyState::default(),
            settings_vt_key: key,
            settings_whitelist: wl,
            settings_saved_at: None,
            last_scan_time: None,
            
            tray: tray_icon,
            allow_quit: false,
            update_rx: Some(rx),
            update_url: None,
        }
    }

    fn get_quarantine_files() -> Vec<PathBuf> {
        let mut files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(quarantine::QUARANTINE_DIR) {
            for entry in entries.flatten() {
                if entry.path().is_file() { files.push(entry.path()); }
            }
        }
        files
    }

    fn poll_jobs(&mut self) {
        self.scan.runner.poll();
        self.guard.runner.poll();
        self.canary.runner.poll();
        self.crack.runner.poll();
        self.startup.runner.poll();
        self.process.runner.poll();
        self.privacy.runner.poll();
        self.network.runner.poll();
        self.yara.runner.poll();
        self.integrity.runner.poll();
        self.system.runner.poll();
        self.scheduler.runner.poll();

        if let Some(rx) = &self.yara.update_rx {
            match rx.try_recv() {
                Ok(Ok(n)) => {
                    self.yara.status = format!("✅ Сохранено файлов: {n}");
                    self.yara.update_rx = None;
                    if let Ok(r) = yara_scanner::init_yara() { self.yara.rules = Some(Arc::new(r)); }
                }
                Ok(Err(e)) => { self.yara.status = format!("❌ {e}"); self.yara.update_rx = None; }
                Err(TryRecvError::Disconnected) => self.yara.update_rx = None,
                Err(TryRecvError::Empty) => {}
            }
        }

        if let Some(rx) = &self.rtp.rx {
            while let Ok(msg) = rx.try_recv() {
                self.rtp.log.push_str(&format!("{}\n---\n", msg));
            }
        }

        if let Some(rx) = &self.ransomware.rx {
            while let Ok(msg) = rx.try_recv() {
                self.ransomware.log.push_str(&format!("{}\n---\n", msg));
            }
        }

        if let Some(rx) = &self.watcher.rx {
            while let Ok(msg) = rx.try_recv() { self.watcher.log.push_str(&format!("{}\n", msg)); }
        }
        if let Some(rx) = &self.full_scan.rx {
            while let Ok(msg) = rx.try_recv() { 
                if msg.contains("НАЙДЕН ВИРУС") {
                    if let Some(path_str) = msg.strip_prefix("⚠ НАЙДЕН ВИРУС: ") {
                        self.full_scan.last_virus = Some(PathBuf::from(path_str));
                    }
                    self.full_scan.log.push_str(&format!("{}\n", msg));
                } else if !msg.contains("Проверено") {
                    self.full_scan.log.push_str(&format!("{}\n", msg)); 
                } else if self.full_scan.log.lines().count() % 10 == 0 {
                    self.full_scan.log.push_str(&format!("{}\n", msg));
                }
            }
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
                Tab::Yara => self.yara.path = text,
                _ => {}
            }
        }
    }

    fn show_sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar").exact_width(240.0).resizable(false)
            .frame(Frame::none().fill(PANEL_BG).inner_margin(Margin::symmetric(16.0, 20.0)))
            .show(ctx, |ui| {
                ui.label(RichText::new("AISEC").size(24.0).strong().color(ACCENT_YELLOW));
                ui.label(RichText::new("AI Security Toolkit").size(12.0).color(TEXT_MUTED));
                ui.add_space(24.0); 
                
                ScrollArea::vertical().show(ui, |ui| {
                    for tab in Tab::ALL {
                        let selected = self.tab == tab;
                        let response = sidebar_tab(ui, tab, selected);
                        if response.clicked() { 
                            self.tab = tab; 
                            if self.tab == Tab::Quarantine { self.quarantine.files = Self::get_quarantine_files(); }
                        }
                    }
                });
                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| { 
                    ui.label(RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).size(11.5).color(TEXT_MUTED)); 
                });
            });
    }

    fn show_central(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().frame(Frame::none().fill(BG_DARK).inner_margin(Margin::same(30.0)))
            .show(ctx, |ui| match self.tab {
                Tab::Dashboard => self.ui_dashboard(ui),
                Tab::RealTime => self.ui_rtp(ui),
                Tab::Ransomware => self.ui_ransomware(ui),
                Tab::Scheduler => self.ui_scheduler(ui, ctx),
                Tab::System => self.ui_system(ui, ctx),
                Tab::FullScan => self.ui_full_scan(ui),
                Tab::Network => self.ui_network(ui, ctx),
                Tab::Quarantine => self.ui_quarantine(ui),
                Tab::Scan => self.ui_scan(ui, ctx),
                Tab::Yara => self.ui_yara(ui, ctx),
                Tab::Integrity => self.ui_integrity(ui, ctx),
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

    fn ui_rtp(&mut self, ui: &mut Ui) {
        page_header(ui, "Защита в реальном времени", "Автоматическая проверка новых файлов в фоне.");
        card(ui, |ui| {
            ui.label(RichText::new("Программа следит за папками: Downloads, Desktop, Temp, Startup.").color(TEXT_MUTED));
            ui.label(RichText::new("Если найден вирус, он будет автоматически отправлен в карантин.").color(TEXT_MUTED));
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if !self.rtp.is_running {
                if ui.add(primary_button("Включить защиту")).clicked() {
                    let db = hash_scanner::load_db();
                    let rules = self.yara.rules.clone();
                    let whitelist = self.config.whitelist.clone();
                    let key = self.config.quarantine_key.clone();
                    
                    let (tx, rx) = mpsc::channel();
                    match real_time_protection::start_rtp(key, db, rules, whitelist, tx) {
                        Ok(watcher) => {
                            self.rtp.watcher = Some(watcher);
                            self.rtp.rx = Some(rx);
                            self.rtp.is_running = true;
                            self.rtp.log.push_str("✅ Защита в реальном времени ВКЛЮЧЕНА.\n");
                            notifications::notify_info("AISEC", "Защита в реальном времени активирована.");
                        }
                        Err(e) => self.rtp.log.push_str(&format!("❌ Ошибка запуска: {}\n", e)),
                    }
                }
            } else {
                if ui.add(secondary_button("Выключить защиту")).clicked() {
                    self.rtp.watcher = None;
                    self.rtp.rx = None;
                    self.rtp.is_running = false;
                    self.rtp.log.push_str("🛑 Защита в реальном времени ВЫКЛЮЧЕНА.\n");
                }
                ui.colored_label(OK, "◉ Защита активна");
            }
        });
        ui.add_space(10.0); ui.separator(); ui.add_space(10.0);
        ui.label(RichText::new("Лог заблокированных угроз:").strong());
        ui.add_space(10.0);
        Frame::none().fill(OUTPUT_BG).stroke(Stroke::new(0.5_f32, Color32::from_gray(48))).rounding(Rounding::same(14.0)).inner_margin(Margin::same(16.0)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ScrollArea::vertical().auto_shrink([false, false]).max_height(ui.available_height() - 20.0).show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new(&self.rtp.log).monospace().size(13.5).color(TEXT_PRIMARY)).selectable(true));
            });
        });
    }

    fn ui_ransomware(&mut self, ui: &mut Ui) {
        page_header(ui, "Анти-Шифровальщик", "Слежка за массовым изменением файлов.");
        card(ui, |ui| { ui.label(RichText::new("Если за 5 секунд изменится более 30 файлов, сработает тревога.").color(TEXT_MUTED)); });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if self.ransomware.rx.is_none() {
                if ui.add(primary_button("▶ Запустить защиту")).clicked() {
                    let (tx, rx) = mpsc::channel();
                    self.ransomware.rx = Some(rx);
                    thread::spawn(move || { let _ = ransomware_shield::start_ransomware_shield(tx); });
                    self.ransomware.log.push_str("▶ Мониторинг запущен...\n");
                }
            } else {
                if ui.add(secondary_button("Остановить")).clicked() {
                    self.ransomware.rx = None;
                    self.ransomware.log.push_str("■ Мониторинг остановлен.\n");
                }
                ui.colored_label(OK, "◉ Мониторинг активен");
            }
        });
        ui.add_space(10.0); ui.separator(); ui.add_space(10.0);
        Frame::none().fill(OUTPUT_BG).stroke(Stroke::new(0.5_f32, Color32::from_gray(48))).rounding(Rounding::same(14.0)).inner_margin(Margin::same(16.0)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ScrollArea::vertical().auto_shrink([false, false]).max_height(ui.available_height() - 20.0).show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new(&self.ransomware.log).monospace().size(13.5).color(TEXT_PRIMARY)).selectable(true));
            });
        });
    }

    fn ui_scheduler(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Планировщик задач", "Поиск скрытых задач Windows.");
        card(ui, |ui| { ui.label(RichText::new("Вирусы часто закрепляются в системе через Планировщик.").color(TEXT_MUTED)); });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.scheduler.runner.is_running();
            if ui.add_enabled(!busy, primary_button("▶ Проверить задачи")).clicked() {
                self.scheduler.runner.start(ctx, String::new(), move || {
                    let tasks = scheduler_audit::get_suspicious_scheduled_tasks();
                    if tasks.is_empty() { Outcome { ok: true, text: "Подозрительных задач не найдено.".to_string() } }
                    else {
                        let mut out = format!("Найдено {} подозрительных задач:\n\n", tasks.len());
                        for t in tasks { out.push_str(&format!("⚠ {}\n\n", t)); }
                        Outcome { ok: false, text: out }
                    }
                });
            }
            output_actions(ui, &mut self.scheduler.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.scheduler.runner);
        output_box(ui, "scheduler_output", &self.scheduler.runner, "Нажмите кнопку для проверки.");
    }

    fn ui_processes(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Процессы", "Список активных процессов. Подозрительные пути помечены.");
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.process.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Обновить список")).clicked() {
                self.process.runner.start(ctx, String::new(), move || {
                    let text = crate::process_scanner::scan_processes();
                    Outcome { ok: true, text }
                });
            }
            output_actions(ui, &mut self.process.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.process.runner);
        
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Завершить процесс по PID:").color(TEXT_MUTED));
            ui.add(TextEdit::singleline(&mut self.kill_pid_input).desired_width(80.0));
            if ui.button("☠ Убить").clicked() {
                if let Ok(pid) = self.kill_pid_input.trim().parse::<u32>() {
                    match process_killer::kill_process_by_pid(pid) {
                        Ok(_) => self.process.runner.push_text(&format!("\n✔ Процесс {} успешно завершен.", pid)),
                        Err(e) => self.process.runner.push_text(&format!("\n✖ Ошибка: {}", e)),
                    }
                }
            }
        });
        output_box(ui, "process_output", &self.process.runner, "Нажмите кнопку для получения списка.");
    }

    fn ui_dashboard(&mut self, ui: &mut Ui) {
        page_header(ui, "Главная", "Общий статус безопасности вашей системы.");
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);

            // Уведомление об обновлении
            if let Some(url) = &self.update_url {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("🚀 Доступна новая версия!").color(ACCENT_YELLOW).strong());
                        ui.hyperlink_to("Скачать", url);
                    });
                });
                ui.add_space(10.0);
            }

            let is_scanning = self.full_scan.rx.is_some() || self.scan.runner.is_running() || self.yara.runner.is_running();
            let has_viruses = self.full_scan.last_virus.is_some() || !self.quarantine.files.is_empty();

            if is_scanning {
                ui.horizontal(|ui| { ui.add(egui::Spinner::new().size(20.0).color(ACCENT_YELLOW)); ui.label(RichText::new("Выполняется сканирование...").color(ACCENT_YELLOW)); });
                ui.add_space(20.0);
            }

            let (rect, _) = ui.allocate_exact_size(vec2(200.0, 200.0), Sense::hover());
            let painter = ui.painter_at(rect);
            let center = rect.center();
            let radius = 90.0;
            let (circle_color, status_text) = if has_viruses { (Color32::from_rgb(220, 50, 50), "Есть риски") } else { (Color32::from_rgb(50, 180, 50), "Защищено") };

            painter.circle_filled(center, radius, circle_color);
            painter.circle_stroke(center, radius, Stroke::new(3.0_f32, Color32::WHITE));
            painter.text(center, Align2::CENTER_CENTER, status_text, FontId::proportional(24.0), Color32::WHITE);
            ui.add_space(40.0);

            ui.group(|ui| {
                ui.set_min_width(400.0);
                ui.horizontal(|ui| {
                    ui.label("Последнее сканирование:");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if let Some(time) = self.last_scan_time { ui.label(time.format("%d.%m.%Y %H:%M").to_string()); } else { ui.label("Не выполнялось"); }
                    });
                });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("База вирусов:");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let count = if PathBuf::from("virus_hashes.txt").exists() { "Активна" } else { "Не скачана" };
                        ui.label(count);
                    });
                });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Защита (RTP):");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if self.rtp.is_running { ui.colored_label(OK, "Включена"); } else { ui.colored_label(DANGER, "Выключена"); }
                    });
                });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Карантин:");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| { ui.label(format!("{} файлов", self.quarantine.files.len())); });
                });
            });
        });
    }

    fn ui_system(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Система", "Проверка HOSTS-файла и статуса Windows Defender.");
        card(ui, |ui| { ui.label(RichText::new("Программа проверит, не заблокированы ли сайты антивирусов и включена ли защита.").color(TEXT_MUTED)); });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.system.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Проверить систему")).clicked() {
                self.system.runner.start(ctx, String::new(), move || {
                    let mut out = String::new();
                    out.push_str(&format!("{}\n\n", system_check::check_windows_defender()));
                    let hosts = system_check::check_hosts_file();
                    if hosts.is_empty() { out.push_str("Файл HOSTS в порядке. Блокировок нет."); }
                    else { out.push_str("Внимание! Найдены подозрительные записи:\n"); for h in hosts { out.push_str(&format!(" - {}\n", h)); } }
                    Outcome { ok: true, text: out }
                });
            }
            output_actions(ui, &mut self.system.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.system.runner);
        output_box(ui, "system_output", &self.system.runner, "Нажмите кнопку для проверки.");
    }

    fn ui_yara(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "YARA-сканер", "Поиск по сигнатурам вредоносного кода.");
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let busy_update = self.yara.update_rx.is_some();
                if ui.add_enabled(!busy_update, secondary_button("Скачать базу YARA")).clicked() {
                    let (tx, rx) = mpsc::channel();
                    self.yara.update_rx = Some(rx);
                    self.yara.status = "Загрузка правил с GitHub...".into();
                    let ctx = ctx.clone();
                    thread::spawn(move || { let _ = tx.send(yara_manager::update_yara_rules()); ctx.request_repaint(); });
                }
                if busy_update { ui.spinner(); }
                if ui.add_enabled(self.yara.rules.is_none(), primary_button("Загрузить правила")).clicked() {
                    match yara_scanner::init_yara() {
                        Ok(r) => { self.yara.rules = Some(Arc::new(r)); self.yara.status = "Правила загружены!".to_string(); }
                        Err(e) => self.yara.runner.fail(format!("Ошибка: {}", e)),
                    }
                }
                if self.yara.rules.is_some() { ui.colored_label(OK, "Правила активны"); }
            });
            if !self.yara.status.is_empty() { ui.label(RichText::new(&self.yara.status).color(ACCENT_YELLOW)); }
            ui.add_space(10.0);
            field_label(ui, "Путь к файлу для проверки");
            ui.add(TextEdit::singleline(&mut self.yara.path).hint_text(r"C:\file.exe").desired_width(f32::INFINITY).font(TextStyle::Monospace));
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.yara.runner.is_running();
            let has_rules = self.yara.rules.is_some();
            if ui.add_enabled(!busy && has_rules, primary_button("Сканировать")).clicked() {
                let path = PathBuf::from(clean_path(&self.yara.path));
                let rules = self.yara.rules.clone().unwrap();
                self.yara.runner.start(ctx, String::new(), move || {
                    match yara_scanner::scan_with_yara(&path, &rules) {
                        Ok(hits) if hits.is_empty() => Outcome { ok: true, text: "Чисто. Совпадений нет.".to_string() },
                        Ok(hits) => Outcome { ok: false, text: format!("ВНИМАНИЕ! Найдены совпадения:\n{}", hits.join("\n")) },
                        Err(e) => Outcome { ok: false, text: format!("Ошибка: {}", e) },
                    }
                });
            }
            output_actions(ui, &mut self.yara.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.yara.runner);
        output_box(ui, "yara_output", &self.yara.runner, "Здесь появятся сработавшие правила.");
    }

    fn ui_integrity(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Целостность", "Проверка изменений файлов в папках автозагрузки.");
        card(ui, |ui| { ui.label(RichText::new("Программа запоминает хеши файлов и сообщает, если их подменили.").color(TEXT_MUTED)); });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.integrity.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Проверить")).clicked() {
                self.integrity.runner.start(ctx, String::new(), move || {
                    let warnings = file_integrity::check_integrity();
                    if warnings.is_empty() { Outcome { ok: true, text: "Изменений не обнаружено. Все файлы на месте.".to_string() } }
                    else { Outcome { ok: false, text: warnings.join("\n") } }
                });
            }
            if ui.add_enabled(!busy, secondary_button("Принять изменения")).clicked() {
                self.integrity.runner.start(ctx, String::new(), move || {
                    match file_integrity::rebuild_baseline() {
                        Ok(count) => Outcome { ok: true, text: format!("База обновлена. Запомнено {} файлов.", count) },
                        Err(e) => Outcome { ok: false, text: format!("Ошибка: {}", e) },
                    }
                });
            }
            output_actions(ui, &mut self.integrity.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.integrity.runner);
        output_box(ui, "integrity_output", &self.integrity.runner, "Нажмите кнопку для проверки.");
    }

    fn ui_full_scan(&mut self, ui: &mut Ui) {
        page_header(ui, "Сканер ПК", "Полная проверка диска по базе хешей MalwareBazaar.");
        card(ui, |ui| { ui.label(RichText::new("Нажмите «Обновить базу», чтобы скачать свежие хеши.").color(TEXT_MUTED)); });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.full_scan.rx.is_some();
            if ui.add_enabled(!busy, secondary_button("Обновить базу")).clicked() {
                let (tx, rx) = mpsc::channel();
                self.full_scan.rx = Some(rx);
                self.full_scan.log.push_str("Загрузка базы MalwareBazaar...\n");
                thread::spawn(move || {
                    let res = hash_scanner::update_virus_db();
                    let _ = tx.send(match res { Ok(_) => "База успешно обновлена!".to_string(), Err(e) => format!("Ошибка: {}", e) });
                });
            }
            if ui.add_enabled(!busy, primary_button("Начать сканирование")).clicked() {
                let (tx, rx) = mpsc::channel();
                self.full_scan.rx = Some(rx);
                self.full_scan.log.clear();
                self.full_scan.last_virus = None;
                self.last_scan_time = Some(Local::now());
                thread::spawn(move || {
                    let db = hash_scanner::load_db();
                    let _ = tx.send(format!("База загружена ({} хешей). Начинаем...", db.len()));
                    full_scan::scan_system_path("C:\\", &db, tx.clone());
                });
            }
            if ui.add_enabled(self.full_scan.last_virus.is_some(), secondary_button("В карантин")).clicked() {
                if let Some(virus_path) = self.full_scan.last_virus.take() {
                    match quarantine::move_to_quarantine(&virus_path, &self.config.quarantine_key) {
                        Ok(dest) => self.full_scan.log.push_str(&format!("\nФайл зашифрован и перемещен в карантин: {:?}\n", dest)),
                        Err(e) => self.full_scan.log.push_str(&format!("\nОшибка карантина: {}\n", e)),
                    }
                }
            }
            if ui.button("Очистить лог").clicked() { self.full_scan.log.clear(); self.full_scan.rx = None; }
        });
        ui.add_space(10.0); ui.separator(); ui.add_space(10.0);
        Frame::none().fill(OUTPUT_BG).stroke(Stroke::new(0.5_f32, Color32::from_gray(48))).rounding(Rounding::same(14.0)).inner_margin(Margin::same(16.0)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ScrollArea::vertical().auto_shrink([false, false]).max_height(ui.available_height() - 20.0).show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new(&self.full_scan.log).monospace().size(13.5).color(TEXT_PRIMARY)).selectable(true));
            });
        });
    }

    fn ui_network(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Сеть", "Активные TCP-подключения и прослушиваемые порты.");
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.network.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Обновить соединения")).clicked() {
                self.network.runner.start(ctx, String::new(), move || { let text = network_monitor::get_connections(); Outcome { ok: true, text } });
            }
            output_actions(ui, &mut self.network.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.network.runner);
        output_box(ui, "network_output", &self.network.runner, "Нажмите кнопку для получения списка.");
    }

    fn ui_quarantine(&mut self, ui: &mut Ui) {
        page_header(ui, "Карантин", "Файлы здесь зашифрованы ChaCha20 и безопасны.");
        ui.horizontal(|ui| { if ui.button("Обновить список").clicked() { self.quarantine.files = Self::get_quarantine_files(); } });
        ui.add_space(10.0); ui.separator(); ui.add_space(10.0);
        if self.quarantine.files.is_empty() { ui.label(RichText::new("Карантин пуст.").color(OK)); }
        else {
            ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                for file in &self.quarantine.files {
                    ui.horizontal(|ui| {
                        let file_name = file.file_name().unwrap_or_default().to_string_lossy();
                        ui.label(RichText::new(format!("{}", file_name)).monospace().color(TEXT_MUTED));
                        if ui.button("Восстановить").clicked() {
                            let dest = std::env::current_dir().unwrap_or_default();
                            match quarantine::restore_from_quarantine(file, &dest, &self.config.quarantine_key) {
                                Ok(path) => self.quarantine.log = format!("Восстановлен: {:?}", path),
                                Err(e) => self.quarantine.log = format!("Ошибка: {}", e),
                            }
                        }
                        if ui.button("Удалить").clicked() { let _ = std::fs::remove_file(file); self.quarantine.log = "Удален.".to_string(); }
                    });
                    ui.add_space(8.0);
                }
            });
        }
        ui.add_space(10.0); ui.label(RichText::new(&self.quarantine.log).color(ACCENT_YELLOW));
    }

    fn ui_scan(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Сканер секретов", "Проверка файла или папки на ключи и пароли.");
        card(ui, |ui| {
            field_label(ui, "Путь для сканирования");
            ui.add(TextEdit::singleline(&mut self.scan.path).hint_text(r"C:\Users\Downloads").desired_width(f32::INFINITY).font(TextStyle::Monospace));
            ui.add_space(10.0);
            field_label(ui, "Исключения (по одному пути в строке)");
            ui.add(TextEdit::multiline(&mut self.scan.excludes).hint_text("Необязательно").desired_rows(3).desired_width(f32::INFINITY).font(TextStyle::Monospace));
            ui.add_space(10.0);
            ui.checkbox(&mut self.scan.json, "Отчёт в формате JSON");
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.scan.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Запустить сканирование")).clicked() { self.config.scan_path = self.scan.path.clone(); config::save_config(&self.config); self.launch_scan(ctx); }
            if ui.add_enabled(!self.scan.runner.text.is_empty(), secondary_button("Экспорт в HTML")).clicked() {
                let text = self.scan.runner.text.clone();
                if report_export::export_html("report_scan.html", "Результаты сканирования", &text).is_ok() { self.scan.runner.push_text("\nОтчёт сохранён в report_scan.html"); }
            }
            output_actions(ui, &mut self.scan.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.scan.runner);
        output_box(ui, "scan_output", &self.scan.runner, "Здесь появится результат.");
    }

    fn launch_scan(&mut self, ctx: &egui::Context) {
        let path_text = clean_path(&self.scan.path);
        if path_text.is_empty() { self.scan.runner.fail("Укажите путь."); return; }
        let path = PathBuf::from(&path_text);
        if !path.exists() { self.scan.runner.fail(format!("Путь не найден: {path_text}")); return; }
        let excludes: Vec<PathBuf> = self.scan.excludes.lines().map(clean_path).filter(|s| !s.is_empty()).map(PathBuf::from).collect();
        let json = self.scan.json;
        self.scan.runner.start(ctx, format!("Сканирование: {path_text}\n"), move || {
            match crate::scan::start_scan(path, excludes, json) {
                Ok(()) => Outcome { ok: true, text: "Готово.".to_owned() },
                Err(e) => Outcome { ok: false, text: format!("Ошибка: {e}") },
            }
        });
    }

    fn ui_guard(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Защита промптов", "Анализ текста на prompt injection.");
        card(ui, |ui| {
            field_label(ui, "Текст промпта");
            ui.push_id("guard_input_scroll", |ui| { ScrollArea::vertical().max_height(190.0).show(ui, |ui| { ui.add(TextEdit::multiline(&mut self.guard.prompt).hint_text("Вставьте промпт…").desired_rows(7).desired_width(f32::INFINITY).font(TextStyle::Monospace)); }); });
            ui.add_space(10.0); ui.checkbox(&mut self.guard.explain, "Подробное объяснение");
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.guard.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Проверить промпт")).clicked() { self.launch_guard(ctx); }
            if ui.add_enabled(!busy && !self.guard.prompt.is_empty(), secondary_button("Очистить ввод")).clicked() { self.guard.prompt.clear(); }
            output_actions(ui, &mut self.guard.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.guard.runner);
        output_box(ui, "guard_output", &self.guard.runner, "Здесь появится отчёт.");
    }

    fn launch_guard(&mut self, ctx: &egui::Context) {
        if self.guard.prompt.trim().is_empty() { self.guard.runner.fail("Введите текст."); return; }
        let prompt = self.guard.prompt.clone(); let explain = self.guard.explain;
        self.guard.runner.start(ctx, String::new(), move || {
            let report = crate::prompt_guard::analyze_prompt(&prompt);
            Outcome { ok: true, text: report.format_text(explain) }
        });
    }

    fn ui_canary(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Ловушки", "Генерация canary-ловушек.");
        card(ui, |ui| {
            field_label(ui, "Количество ловушек");
            ui.add(egui::Slider::new(&mut self.canary.count, 1..=100).text("шт."));
            ui.add_space(10.0);
            field_label(ui, "Типы ловушек");
            ui.add(TextEdit::singleline(&mut self.canary.types).hint_text("api_key, token, password").desired_width(f32::INFINITY).font(TextStyle::Monospace));
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.canary.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Сгенерировать")).clicked() { self.launch_canary(ctx); }
            output_actions(ui, &mut self.canary.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.canary.runner);
        output_box(ui, "canary_output", &self.canary.runner, "Здесь появится журнал.");
    }

    fn launch_canary(&mut self, ctx: &egui::Context) {
        let types: Vec<String> = self.canary.types.split(',').map(|t| t.trim().to_owned()).filter(|t| !t.is_empty()).collect();
        if types.is_empty() { self.canary.runner.fail("Укажите тип."); return; }
        let count = self.canary.count.max(1);
        self.canary.runner.start(ctx, format!("Генерация {} шт.\n", count), move || {
            crate::canary::generate_canaries(count, types);
            Outcome { ok: true, text: "Готово.".to_owned() }
        });
    }

    fn ui_crack(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Анализ EXE", "Поиск признаков взлома и проверка по базам.");
        card(ui, |ui| {
            field_label(ui, "Путь к файлу");
            ui.add(TextEdit::singleline(&mut self.crack.path).hint_text(r"C:\Program Files\App\app.exe").desired_width(f32::INFINITY).font(TextStyle::Monospace));
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.crack.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Локальный анализ")).clicked() { self.launch_crack(ctx); }
            let has_key = !self.settings_vt_key.is_empty();
            if ui.add_enabled(!busy && has_key, secondary_button("VirusTotal")).clicked() { self.launch_virustotal(ctx); }
            if ui.add_enabled(!self.crack.runner.text.is_empty(), secondary_button("Экспорт в HTML")).clicked() {
                let text = self.crack.runner.text.clone();
                if report_export::export_html("report_crack.html", "Анализ EXE", &text).is_ok() { self.crack.runner.push_text("\nОтчёт сохранён в report_crack.html"); }
            }
            output_actions(ui, &mut self.crack.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.crack.runner);
        output_box(ui, "crack_output", &self.crack.runner, "Здесь появится вердикт.");
    }

    fn launch_crack(&mut self, ctx: &egui::Context) {
        let path_text = clean_path(&self.crack.path);
        if path_text.is_empty() { self.crack.runner.fail("Укажите путь."); return; }
        let path = PathBuf::from(&path_text);
        if !path.is_file() { self.crack.runner.fail(format!("Файл не найден: {path_text}")); return; }
        
        self.crack.runner.start(ctx, String::new(), move || {
            let sig_status = signature_check::check_signature(&path);
            let sig_text = match sig_status {
                SignatureStatus::Valid(signer) => format!("Подпись: Валидна ({})", signer),
                SignatureStatus::Invalid => "Подпись: Недействительна (взломана!)".to_string(),
                SignatureStatus::Unsigned => "Подпись: Отсутствует".to_string(),
            };
            match crate::crack_detector::analyze_file(&path) {
                Ok(report) => {
                    let mut lines = vec![format!("Файл: {}", path.display()), sig_text, format!("Вердикт: {}", dbg_text(&report.verdict)), format!("Pirate score: {}", dbg_text(&report.pirate_score)), "Причины:".to_owned()];
                    for reason in report.reasons.iter() { lines.push(format!("  • {}", dbg_text(reason))); }
                    Outcome { ok: true, text: lines.join("\n") }
                }
                Err(e) => Outcome { ok: false, text: format!("Ошибка: {e:?}") },
            }
        });
    }

    fn launch_virustotal(&mut self, ctx: &egui::Context) {
        let path_text = clean_path(&self.crack.path);
        let path = PathBuf::from(&path_text);
        let key = self.settings_vt_key.clone();
        self.crack.runner.start(ctx, "Отправка хеша в VirusTotal...\n".to_string(), move || {
            match virustotal::check_virustotal(&path, &key) {
                Ok(report) => {
                    let color = if report.positives > 0 { "ОПАСНО" } else { "ЧИСТО" };
                    let text = format!("VirusTotal: {}\nНайдено {} угроз из {} антивирусов.\nСсылка: {}", color, report.positives, report.total, report.permalink);
                    Outcome { ok: true, text }
                }
                Err(e) => Outcome { ok: false, text: format!("Ошибка VT: {e}") },
            }
        });
    }

    fn ui_startup(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Автозагрузка", "Проверка программ в автозагрузке.");
        card(ui, |ui| { ui.label(RichText::new("Нажмите кнопку, чтобы собрать список.").color(TEXT_MUTED)); });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.startup.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Проверить")).clicked() { self.launch_startup(ctx); }
            output_actions(ui, &mut self.startup.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.startup.runner);
        output_box(ui, "startup_output", &self.startup.runner, "Здесь появится отчёт.");
    }

    fn launch_startup(&mut self, ctx: &egui::Context) {
        self.startup.runner.start(ctx, String::new(), move || {
            let report = crate::startup_check::scan_startup();
            Outcome { ok: true, text: report.format() }
        });
    }

    fn ui_privacy(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        page_header(ui, "Приватность", "Аудит утечек DNS, IPv6 и локальных IP.");
        card(ui, |ui| { ui.label(RichText::new("Программа проверит, не раскрываете ли вы свои данные.").color(TEXT_MUTED)); });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            let busy = self.privacy.runner.is_running();
            if ui.add_enabled(!busy, primary_button("Запустить аудит")).clicked() {
                self.privacy.runner.start(ctx, String::new(), move || {
                    let report = privacy_audit::run_privacy_audit();
                    let mut out = String::new();
                    out.push_str(if report.dns_leak { "DNS-утечка: ОБНАРУЖЕНА\n" } else { "DNS-утечка: НЕТ\n" });
                    out.push_str(if report.ipv6_active { "IPv6 активен: ДА (риск утечки)\n" } else { "IPv6 активен: НЕТ\n" });
                    out.push_str(if report.webrtc_leak { "Локальный IP раскрыт: ДА\n" } else { "Локальный IP раскрыт: НЕТ\n" });
                    if !report.warnings.is_empty() {
                        out.push_str("\nПредупреждения:\n");
                        for w in report.warnings { out.push_str(&format!(" - {}\n", w)); }
                    }
                    Outcome { ok: true, text: out }
                });
            }
            output_actions(ui, &mut self.privacy.runner);
        });
        ui.add_space(10.0); status_line(ui, &self.privacy.runner);
        output_box(ui, "privacy_output", &self.privacy.runner, "Нажмите кнопку для диагностики сети.");
    }

    fn ui_watcher(&mut self, ui: &mut Ui) {
        page_header(ui, "Наблюдение", "Слежка за папкой на новые EXE/DLL.");
        card(ui, |ui| {
            field_label(ui, "Путь к папке (например, Downloads)");
            ui.add(TextEdit::singleline(&mut self.watcher.path).hint_text(r"C:\Users\Downloads").desired_width(f32::INFINITY).font(TextStyle::Monospace));
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(self.watcher.rx.is_none(), primary_button("Начать наблюдение")).clicked() {
                let path = clean_path(&self.watcher.path);
                if !path.is_empty() {
                    self.config.watcher_path = path.clone();
                    config::save_config(&self.config);
                    let (tx, rx) = mpsc::channel();
                    crate::watcher::start_watching(&path, tx);
                    self.watcher.rx = Some(rx);
                    self.watcher.log.push_str(&format!("Наблюдение запущено: {}\n", path));
                }
            }
            if ui.add_enabled(self.watcher.rx.is_some(), secondary_button("Остановить")).clicked() {
                self.watcher.rx = None;
                self.watcher.log.push_str("Наблюдение остановлено.\n");
            }
            if ui.add_enabled(!self.watcher.log.is_empty(), secondary_button("Очистить лог")).clicked() { self.watcher.log.clear(); }
        });
        ui.add_space(10.0); ui.separator(); ui.add_space(10.0);
        egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(&self.watcher.log).monospace().size(13.5).color(TEXT_PRIMARY)).selectable(true));
        });
    }

    fn ui_settings(&mut self, ui: &mut Ui) {
        page_header(ui, "Настройки", "Конфигурация API и белый список.");
        card(ui, |ui| {
            field_label(ui, "VirusTotal API Key");
            ui.add(TextEdit::singleline(&mut self.settings_vt_key).hint_text("Вставьте ваш API ключ").desired_width(f32::INFINITY).font(TextStyle::Monospace));
            ui.add_space(10.0);
            field_label(ui, "Белый список папок (по одной в строке)");
            ui.add(TextEdit::multiline(&mut self.settings_whitelist).hint_text("C:\\Games\\Cyberpunk 2077\nD:\\Pirate Games").desired_rows(5).desired_width(f32::INFINITY).font(TextStyle::Monospace));
            ui.add_space(10.0);
            if ui.button("Сохранить настройки").clicked() {
                self.config.vt_api_key = self.settings_vt_key.clone();
                self.config.whitelist = self.settings_whitelist.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
                config::save_config(&self.config);
                self.settings_saved_at = Some(Instant::now());
            }
            if let Some(saved) = self.settings_saved_at {
                if saved.elapsed().as_secs() < 2 { ui.colored_label(OK, "Сохранено"); } else { self.settings_saved_at = None; }
            }
        });
    }
}

impl eframe::App for AisecApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Логика трея
        if let Some(t) = &self.tray {
            match tray::handle_tray_events(t) {
                Some(tray::TrayAction::Open) => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                Some(tray::TrayAction::Quit) => {
                    self.allow_quit = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                _ => {}
            }
        }

        // 2. Скрытие в трей
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested && self.tray.is_some() && !self.allow_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // 3. Оживляем окно
        ctx.request_repaint_after(Duration::from_millis(200));

        // 4. Проверка обновлений
        if let Some(rx) = &self.update_rx {
            match rx.try_recv() {
                Ok(Ok(Some(url))) => { self.update_url = Some(url); self.update_rx = None; }
                Ok(Ok(None)) => { self.update_rx = None; }
                Ok(Err(_)) => { self.update_rx = None; }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => { self.update_rx = None; }
            }
        }

        self.poll_jobs(); 
        self.handle_dropped_files(ctx);
        
        if self.watcher.rx.is_some() || self.full_scan.rx.is_some() || self.yara.update_rx.is_some() || self.rtp.rx.is_some() || self.ransomware.rx.is_some() { 
            ctx.request_repaint_after(Duration::from_millis(100)); 
        }
        
        self.show_sidebar(ctx); 
        self.show_central(ctx);
    }
}

pub fn run_gui() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default().with_title("AI Security Toolkit").with_inner_size([1100.0, 720.0]).with_min_inner_size([860.0, 540.0]);
    if let Ok(icon_bytes) = std::fs::read("icon.png") {
        if let Ok(icon) = eframe::icon_data::from_png_bytes(&icon_bytes) { viewport = viewport.with_icon(icon); }
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    
    eframe::run_native("AI Security Toolkit", options, Box::new(|cc| {
        // Создаем иконку в трее
        let tray_icon = tray::create_tray("icon.png").ok();
        Ok(Box::new(AisecApp::new(cc, tray_icon)))
    }))
}

fn apply_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    let mut visuals = egui::Visuals::dark();
    
    visuals.dark_mode = true;
    visuals.window_fill = BG_DARK;
    visuals.panel_fill = PANEL_BG;
    visuals.extreme_bg_color = Color32::from_rgb(12, 12, 12);
    visuals.faint_bg_color = Color32::from_rgb(38, 38, 38);
    
    visuals.selection.bg_fill = ACCENT_YELLOW;
    visuals.selection.stroke = Stroke::new(1.0_f32, Color32::BLACK);
    
    visuals.window_rounding = Rounding::same(14.0);
    visuals.menu_rounding = Rounding::same(10.0);
    
    visuals.widgets.noninteractive.bg_fill = PANEL_BG;
    visuals.widgets.noninteractive.rounding = Rounding::same(8.0);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(0.5_f32, Color32::from_gray(60));
    
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(34, 34, 34);
    visuals.widgets.inactive.rounding = Rounding::same(8.0);
    visuals.widgets.inactive.fg_stroke = Stroke::new(0.5_f32, Color32::from_gray(80));
    
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(46, 46, 46);
    visuals.widgets.hovered.rounding = Rounding::same(8.0);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, ACCENT_YELLOW);
    
    visuals.widgets.active.bg_fill = ACCENT_YELLOW;
    visuals.widgets.active.rounding = Rounding::same(8.0);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::BLACK);
    
    style.visuals = visuals;
    style.spacing.item_spacing = vec2(10.0, 10.0);
    style.spacing.button_padding = vec2(14.0, 7.0);
    style.spacing.interact_size.y = 36.0;
    ctx.set_style(style);
}

fn sidebar_tab(ui: &mut Ui, tab: Tab, selected: bool) -> egui::Response {
    ui.add_space(4.0);
    let bg_color = if selected { Color32::from_rgba_premultiplied(255, 204, 0, 25) } else { Color32::TRANSPARENT };
    let text_color = if selected { ACCENT_YELLOW } else { TEXT_MUTED };
    let desired_size = egui::vec2(ui.available_width(), 40.0);
    
    let (rect, response) = ui.allocate_exact_size(desired_size, egui::Sense::click());
    
    if ui.is_rect_visible(rect) {
        let fill = if response.hovered() && !selected { Color32::from_rgb(40, 40, 40) } else { bg_color };
        
        ui.painter().rect(
            rect,
            Rounding::same(10.0),
            fill,
            if selected { Stroke::new(1.0_f32, ACCENT_YELLOW) } 
            else if response.hovered() { Stroke::new(0.5_f32, Color32::from_gray(70)) } 
            else { Stroke::NONE },
        );
        
        let content_rect = rect.shrink2(egui::vec2(16.0, 0.0));
        let mut galley_pos = content_rect.min + egui::vec2(0.0, (40.0 - 16.0) / 2.0);
        
        let symbol_galley = ui.painter().layout_no_wrap(tab.icon().to_string(), egui::FontId::proportional(16.0), text_color);
        ui.painter().galley(galley_pos, symbol_galley, text_color);
        
        galley_pos.x += 28.0;
        
        let text_galley = ui.painter().layout_no_wrap(tab.title().to_string(), egui::FontId::proportional(14.0), if selected { TEXT_PRIMARY } else { TEXT_MUTED });
        ui.painter().galley(galley_pos, text_galley, if selected { TEXT_PRIMARY } else { TEXT_MUTED });
    }
    
    response.on_hover_cursor(CursorIcon::PointingHand).on_hover_ui(|ui| { ui.label(RichText::new(tab.tooltip()).size(12.0).color(TEXT_MUTED)); })
}

fn page_header(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.vertical(|ui| {
        ui.add_space(4.0);
        ui.label(RichText::new(title).size(24.0).strong().color(TEXT_PRIMARY));
        ui.add_space(4.0);
        ui.label(RichText::new(subtitle).size(14.0).color(TEXT_MUTED));
        ui.add_space(16.0);
        
        let stroke = Stroke::new(0.5_f32, Color32::from_gray(45));
        let rect = ui.available_rect_before_wrap();
        ui.painter().hline(rect.x_range(), rect.min.y, stroke);
        ui.add_space(16.0);
    });
}

fn field_label(ui: &mut Ui, text: &str) { 
    ui.label(RichText::new(text).size(13.0).strong().color(TEXT_MUTED)); 
}

fn card(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) { 
    Frame::none()
        .fill(PANEL_BG)
        .rounding(Rounding::same(14.0))
        .stroke(Stroke::new(0.5_f32, Color32::from_gray(48)))
        .inner_margin(Margin::same(20.0))
        .show(ui, |ui| { 
            ui.set_width(ui.available_width()); 
            add_contents(ui); 
        }); 
    ui.add_space(10.0); 
}

fn primary_button(text: &str) -> impl egui::Widget {
    egui::Button::new(RichText::new(text).color(Color32::BLACK).size(14.0).strong())
        .fill(ACCENT_YELLOW)
        .rounding(Rounding::same(8.0))
        .min_size(egui::vec2(120.0, 36.0))
}

fn secondary_button(text: &str) -> impl egui::Widget {
    egui::Button::new(RichText::new(text).color(TEXT_PRIMARY).size(14.0))
        .fill(Color32::from_rgb(38, 38, 38))
        .stroke(Stroke::new(0.5_f32, Color32::from_gray(70)))
        .rounding(Rounding::same(8.0))
        .min_size(egui::vec2(120.0, 36.0))
}

fn output_actions(ui: &mut Ui, runner: &mut Runner) {
    if ui.add_enabled(!runner.text.is_empty(), egui::Button::new("Копировать").fill(Color32::from_rgb(38, 38, 38)).min_size(vec2(100.0, 36.0))).clicked() { ui.ctx().copy_text(runner.text.clone()); }
    let can_clear = !runner.is_running() && (!runner.text.is_empty() || runner.status != Status::Idle);
    if ui.add_enabled(can_clear, egui::Button::new("Очистить").fill(Color32::from_rgb(38, 38, 38)).min_size(vec2(100.0, 36.0))).clicked() { runner.clear(); }
}

fn status_line(ui: &mut Ui, runner: &Runner) {
    ui.horizontal(|ui| match runner.status {
        Status::Idle => { ui.label(RichText::new("Готово к запуску").size(13.0).color(TEXT_MUTED)); }
        Status::Running => { ui.add(egui::Spinner::new().size(14.0).color(ACCENT_YELLOW)); let secs = runner.started.map(|s| s.elapsed().as_secs_f32()).unwrap_or(0.0); ui.label(RichText::new(format!("Выполняется… {secs:.1} с")).size(13.0).color(ACCENT_YELLOW)); }
        Status::Done => { ui.label(RichText::new(format!("Завершено за {:.1} с", runner.elapsed.as_secs_f32())).size(13.0).color(OK)); }
        Status::Failed => { let text = if runner.elapsed.is_zero() { "Ошибка".to_owned() } else { format!("Ошибка после {:.1} с", runner.elapsed.as_secs_f32()) }; ui.label(RichText::new(text).size(13.0).color(DANGER)); }
    });
}

fn output_box(ui: &mut Ui, key: &str, runner: &Runner, placeholder: &str) {
    let total = ui.available_height().max(160.0);
    Frame::none().fill(OUTPUT_BG).stroke(Stroke::new(0.5_f32, Color32::from_gray(48))).rounding(Rounding::same(14.0)).inner_margin(Margin::same(16.0)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.push_id(key, |ui| { ScrollArea::vertical().auto_shrink([false, false]).max_height(total - 28.0).show(ui, |ui| {
            ui.set_width(ui.available_width());
            if runner.text.is_empty() { let message = if runner.is_running() { "Выполняется…" } else { placeholder }; ui.label(RichText::new(message).monospace().color(TEXT_MUTED)); }
            else { ui.add(egui::Label::new(RichText::new(&runner.text).monospace().size(14.0).color(TEXT_PRIMARY)).selectable(true)); }
        }); });
    });
}

fn clean_path(raw: &str) -> String { raw.trim().trim_matches('"').trim().to_owned() }
fn dbg_text<T: Debug>(value: &T) -> String { format!("{value:?}").trim_matches('"').to_owned() }