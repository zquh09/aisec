use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

const MENU_ID_OPEN: &str = "aisec.tray.open";
const MENU_ID_QUIT: &str = "aisec.tray.quit";
const TOOLTIP: &str = "AI Security Toolkit";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Open,
    Quit,
    #[allow(dead_code)]
    None,
}

fn load_icon(icon_path: &str) -> Result<Icon, String> {
    let rgba = image::open(icon_path)
        .map_err(|e| format!("Не удалось открыть иконку '{icon_path}': {e}"))?
        .into_rgba8();

    let (width, height) = rgba.dimensions();

    Icon::from_rgba(rgba.into_raw(), width, height)
        .map_err(|e| format!("Некорректные данные иконки '{icon_path}': {e}"))
}

pub fn create_tray(icon_path: &str) -> Result<TrayIcon, String> {
    let icon = load_icon(icon_path)?;

    let open_item = MenuItem::with_id(MENU_ID_OPEN, "Открыть AISEC", true, None);
    let quit_item = MenuItem::with_id(MENU_ID_QUIT, "Выход", true, None);

    let menu = Menu::new();
    menu.append_items(&[&open_item, &PredefinedMenuItem::separator(), &quit_item])
        .map_err(|e| format!("Не удалось собрать меню трея: {e}"))?;

    TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip(TOOLTIP)
        .with_icon(icon)
        .build()
        .map_err(|e| format!("Не удалось создать иконку в трее: {e}"))
}

pub fn handle_tray_events(tray: &TrayIcon) -> Option<TrayAction> {
    while let Ok(event) = MenuEvent::receiver().try_recv() {
        match event.id.0.as_str() {
            MENU_ID_OPEN => return Some(TrayAction::Open),
            MENU_ID_QUIT => return Some(TrayAction::Quit),
            _ => {}
        }
    }

    while let Ok(event) = TrayIconEvent::receiver().try_recv() {
        if let TrayIconEvent::Click {
            id,
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = event
        {
            if id == *tray.id() {
                return Some(TrayAction::Open);
            }
        }
    }

    None
}