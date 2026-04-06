use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

const TRACE_ENV_VAR: &str = "WIN_PROXYCHAINS_TRACE_FILE";

static TRACE_LOCK: Mutex<()> = Mutex::new(());
static TRACE_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

fn trace_path() -> Option<&'static PathBuf> {
    TRACE_PATH
        .get_or_init(|| {
            let value: OsString = std::env::var_os(TRACE_ENV_VAR)?;
            if value.is_empty() {
                return None;
            }
            Some(PathBuf::from(value))
        })
        .as_ref()
}

pub fn log(message: impl AsRef<str>) {
    let Some(path) = trace_path() else {
        return;
    };

    let _guard = TRACE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let pid = unsafe { GetCurrentProcessId() };
    let tid = unsafe { GetCurrentThreadId() };

    let _ = writeln!(
        file,
        "[{timestamp_ms} pid={pid} tid={tid}] {}",
        message.as_ref()
    );
}
