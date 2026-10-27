use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use walkdir::WalkDir;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::{
    FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA,
};

const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;

pub fn find_ads_and_hidden(dir: &Path) -> Vec<String> {
    let mut results = Vec::new();

    for entry_result in WalkDir::new(dir).follow_links(false).into_iter() {
        let entry = match entry_result { Ok(e) => e, Err(_) => continue };
        let path = entry.path();

        if let Ok(meta) = fs::metadata(path) {
            let attrs = meta.file_attributes();
            if (attrs & FILE_ATTRIBUTE_HIDDEN) != 0 {
                results.push(format!("{} [Скрытый]", path.display()));
            }
            if (attrs & FILE_ATTRIBUTE_SYSTEM) != 0 {
                results.push(format!("{} [Системный]", path.display()));
            }
        }

        if path.is_file() {
            for stream in check_ads(path) {
                results.push(format!("{} [ADS: {}]", path.display(), stream));
            }
        }
    }
    results
}

fn check_ads(path: &Path) -> Vec<String> {
    let mut ads_list = Vec::new();
    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide_path.push(0);
    let mut find_data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };

    unsafe {
        let handle = FindFirstStreamW(
            wide_path.as_ptr(),
            FindStreamInfoStandard,
            &mut find_data as *mut _ as *mut _,
            0,
        );

        if handle == INVALID_HANDLE_VALUE { return ads_list; }

        loop {
            let name_slice = &find_data.cStreamName;
            let len = name_slice.iter().position(|&c| c == 0).unwrap_or(name_slice.len());
            let stream_name = String::from_utf16_lossy(&name_slice[..len]);

            if stream_name != "::$DATA" && !stream_name.is_empty() {
                let clean = stream_name.strip_prefix(':').unwrap_or(&stream_name).split(':').next().unwrap_or(&stream_name);
                if !clean.is_empty() { ads_list.push(clean.to_string()); }
            }

            if FindNextStreamW(handle, &mut find_data as *mut _ as *mut _) == 0 { break; }
        }
        let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    ads_list
}