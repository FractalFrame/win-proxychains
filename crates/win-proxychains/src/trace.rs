pub fn log(_message: impl AsRef<str>) {
    #[cfg(debug_assertions)]
    {
        let mut wide: alloc::vec::Vec<u16> = alloc::format!("win-proxychains: {}", _message.as_ref())
            .encode_utf16()
            .collect();
        wide.push(0);
        unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW(wide.as_ptr());
        }
    }
}
