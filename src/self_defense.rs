use std::fs::OpenOptions;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::OnceLock;

static EXE_LOCK: OnceLock<std::fs::File> = OnceLock::new();

const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;

pub fn lock_executable() -> io::Result<()> {
    if EXE_LOCK.get().is_some() { return Ok(()); }
    let path: PathBuf = std::env::current_exe()?;
    // Открываем без FILE_SHARE_DELETE -> Windows не даст удалить или переименовать файл
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)?;
    EXE_LOCK.set(file).map_err(|_| {
        io::Error::new(io::ErrorKind::AlreadyExists, "Уже открыт")
    })?;
    Ok(())
}