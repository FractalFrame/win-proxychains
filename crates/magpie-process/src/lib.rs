// Copyright (c) 2026 FractalFrame <https://fractalframe.eu>
// Part of the win-proxychains project. Licensed under BSL-1.1; see LICENCE.md.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod pe_file;
mod process;
mod scoped_handle;

#[cfg(feature = "global-allocator")]
#[global_allocator]
static GLOBAL_ALLOCATOR: winapi_allocator::WinApiAllocator = winapi_allocator::WinApiAllocator::new();

pub use winapi_allocator::WinApiAllocator;
pub use pe_file::{ParsedNtHeaders, ParsedPeFile, SectionTable};
pub use process::{
    AnalysedModuleInfo, MemoryInfo, MemoryMap, MemorySection, ModuleInfo, Process, ProcessBuilder,
    Section, Thread,
};
pub use scoped_handle::ScopedHandle;
