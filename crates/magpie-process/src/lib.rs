// Copyright (c) 2026 FractalFrame <https://fractalframe.eu>
// Part of the win-proxychains project. Licensed under BSL-1.1; see LICENCE.md.

pub mod pe_file;
mod process;
mod scoped_handle;

pub use pe_file::{ParsedNtHeaders, ParsedPeFile, SectionTable};
pub use process::{
    AnalysedModuleInfo, MemoryInfo, MemoryMap, MemorySection, ModuleInfo, Process, ProcessBuilder,
    Section, Thread,
};
pub use scoped_handle::ScopedHandle;
