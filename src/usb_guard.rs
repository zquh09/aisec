use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM, HINSTANCE};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
    TranslateMessage, CW_USEDEFAULT, HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE,
    WNDCLASSW, WM_DEVICECHANGE,
};
use std::sync::mpsc;

const DBT_DEVICEARRIVAL: usize = 0x8000;
const DBT_DEVTYP_VOLUME: u32 = 0x00000002;

#[repr(C)]
struct DevBroadcastHdr {
    dbch_size: u32,
    dbch_devicetype: u32,
    dbch_reserved: u32,
}

#[repr(C)]
struct DevBroadcastVolume {
    dbch_size: u32,
    dbch_devicetype: u32,
    dbch_reserved: u32,
    dbcv_unitmask: u32,
    dbcv_flags: u16,
}

unsafe extern "system" fn wnd_proc(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if message == WM_DEVICECHANGE && wparam.0 == DBT_DEVICEARRIVAL && lparam.0 != 0 {
        let header = lparam.0 as *const DevBroadcastHdr;
        if (*header).dbch_devicetype == DBT_DEVTYP_VOLUME {
            let volume = lparam.0 as *const DevBroadcastVolume;
            let mask = (*volume).dbcv_unitmask;
            for i in 0..26 {
                if (mask & (1 << i)) != 0 {
                    let drive_letter = (b'A' + i as u8) as char;
                    let drive_path = format!("{}:\\", drive_letter);
                    
                    std::thread::spawn(move || {
                        println!("[USB Guard] Подключено устройство: {}", drive_path);
                        let db = crate::hash_scanner::load_db();
                        let (tx, _rx) = mpsc::channel();
                        let _ = crate::full_scan::scan_system_path(&drive_path, &db, tx);
                    });
                    break;
                }
            }
        }
    }
    DefWindowProcW(window, message, wparam, lparam)
}

pub fn start_usb_listener() -> Result<(), String> {
    unsafe {
        let hmodule = GetModuleHandleW(None).map_err(|e| format!("HINSTANCE error: {}", e))?;
        let hinstance = HINSTANCE::from(hmodule);
        let class_name = windows::core::w!("AISecUSBGuardClass");
        
        let wc = WNDCLASSW { 
            lpfnWndProc: Some(wnd_proc), 
            hInstance: hinstance, 
            lpszClassName: class_name, 
            ..Default::default() 
        };
        
        if RegisterClassW(&wc) == 0 { 
            return Err("Не удалось зарегистрировать класс".to_string()); 
        }

        let _hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0), 
            class_name, 
            windows::core::w!("AISecHidden"),
            WINDOW_STYLE(0), 
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
            HWND_MESSAGE, 
            None, 
            hinstance, 
            None,
        ).map_err(|e| format!("Не удалось создать окно: {}", e))?;

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}