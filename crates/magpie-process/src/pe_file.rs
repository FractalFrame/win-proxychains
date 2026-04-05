// Copyright (c) 2026 FractalFrame <https://fractalframe.eu>
// Part of the win-proxychains project. Licensed under BSL-1.1; see LICENCE.md.

use std::{
    fmt,
    ffi::{CStr, c_void},
    mem,
};

use anyhow::Result;
use windows_sys::Win32::System::{
    Diagnostics::Debug::{
        IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT,
        IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_FILE_HEADER,
        IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR32_MAGIC,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_SECTION_HEADER,
    },
    SystemInformation::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386},
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64
    },
};

pub type SectionTable = IMAGE_SECTION_HEADER;

#[repr(C)]
#[derive(Clone, Copy)]
struct ImageNtHeadersPrefix {
    signature: u32,
    file_header: IMAGE_FILE_HEADER,
}

#[derive(Clone, Copy)]
pub struct ParsedPeFile<'a> {
    bytes: &'a [u8],
    file_header: IMAGE_FILE_HEADER,
    size_of_image: usize,
    size_of_headers: usize,
    image_base: u64,
    sections_offset: usize,
}

impl fmt::Debug for ParsedPeFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedPeFile")
            .field("machine", &self.machine())
            .field("size_of_image", &self.size_of_image)
            .field("size_of_headers", &self.size_of_headers)
            .field("image_base", &self.image_base)
            .field("section_count", &self.file_header.NumberOfSections)
            .finish()
    }
}

impl<'a> ParsedPeFile<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let dos_header = read::<IMAGE_DOS_HEADER>(bytes, 0)?;
        let e_magic = dos_header.e_magic;
        if e_magic != IMAGE_DOS_SIGNATURE {
            anyhow::bail!("invalid DOS header signature: {:#x}", e_magic);
        }

        let e_lfanew = dos_header.e_lfanew;
        let nt_header_offset = usize::try_from(e_lfanew)
            .map_err(|_| anyhow::anyhow!("invalid NT header offset: {}", e_lfanew))?;
        let nt_header_prefix = read::<ImageNtHeadersPrefix>(bytes, nt_header_offset)?;
        let nt_signature = nt_header_prefix.signature;
        if nt_signature != IMAGE_NT_SIGNATURE {
            anyhow::bail!("invalid NT header signature: {:#x}", nt_signature);
        }

        let file_header = nt_header_prefix.file_header;
        let machine = file_header.Machine;
        let (size_of_image, size_of_headers, image_base) = match machine {
            IMAGE_FILE_MACHINE_I386 => {
                let nt_headers = read::<IMAGE_NT_HEADERS32>(bytes, nt_header_offset)?;
                let optional_header_magic = nt_headers.OptionalHeader.Magic;
                if optional_header_magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
                    anyhow::bail!(
                        "invalid PE32 optional header magic: {:#x}",
                        optional_header_magic
                    );
                }

                (
                    nt_headers.OptionalHeader.SizeOfImage as usize,
                    nt_headers.OptionalHeader.SizeOfHeaders as usize,
                    nt_headers.OptionalHeader.ImageBase as u64,
                )
            }
            IMAGE_FILE_MACHINE_AMD64 => {
                let nt_headers = read::<IMAGE_NT_HEADERS64>(bytes, nt_header_offset)?;
                let optional_header_magic = nt_headers.OptionalHeader.Magic;
                if optional_header_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                    anyhow::bail!(
                        "invalid PE32+ optional header magic: {:#x}",
                        optional_header_magic
                    );
                }

                (
                    nt_headers.OptionalHeader.SizeOfImage as usize,
                    nt_headers.OptionalHeader.SizeOfHeaders as usize,
                    nt_headers.OptionalHeader.ImageBase,
                )
            }
            machine => anyhow::bail!("unsupported PE machine: {machine:#x}"),
        };

        let sections_offset = nt_header_offset
            .checked_add(mem::size_of::<u32>() + mem::size_of::<IMAGE_FILE_HEADER>())
            .and_then(|offset| offset.checked_add(file_header.SizeOfOptionalHeader as usize))
            .ok_or_else(|| anyhow::anyhow!("section table offset overflowed"))?;
        let sections_size = usize::from(file_header.NumberOfSections)
            .checked_mul(mem::size_of::<IMAGE_SECTION_HEADER>())
            .ok_or_else(|| anyhow::anyhow!("section table size overflowed"))?;
        if sections_offset
            .checked_add(sections_size)
            .ok_or_else(|| anyhow::anyhow!("section table bounds overflowed"))?
            > bytes.len()
        {
            anyhow::bail!("section table is outside the file");
        }

        Ok(Self {
            bytes,
            file_header,
            size_of_image,
            size_of_headers,
            image_base,
            sections_offset,
        })
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn file_header(&self) -> IMAGE_FILE_HEADER {
        self.file_header
    }

    pub fn machine(&self) -> u16 {
        self.file_header.Machine
    }

    pub fn is_64(&self) -> bool {
        self.file_header.Machine == IMAGE_FILE_MACHINE_AMD64
    }

    pub fn size_of_image(&self) -> usize {
        self.size_of_image
    }

    pub fn size_of_headers(&self) -> usize {
        self.size_of_headers
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn sections(&self) -> Result<Vec<IMAGE_SECTION_HEADER>> {
        let mut sections = Vec::with_capacity(self.file_header.NumberOfSections as usize);

        for index in 0..self.file_header.NumberOfSections as usize {
            let offset = self
                .sections_offset
                .checked_add(index * mem::size_of::<IMAGE_SECTION_HEADER>())
                .ok_or_else(|| anyhow::anyhow!("section offset overflowed"))?;
            sections.push(read::<IMAGE_SECTION_HEADER>(self.bytes, offset)?);
        }

        Ok(sections)
    }

    pub fn section_tables(&self) -> Result<Vec<SectionTable>> {
        self.sections()
    }
}

pub enum ParsedNtHeaders<'a> {
    Pe32 {
        image_base: *const u8,
        nt_headers: &'a IMAGE_NT_HEADERS32,
    },
    Pe64 {
        image_base: *const u8,
        nt_headers: &'a IMAGE_NT_HEADERS64,
    },
}

impl<'a> ParsedNtHeaders<'a> {
    pub fn parse(image_base: *const c_void) -> Result<Self> {
        let dos_header = unsafe { &*(image_base as *const IMAGE_DOS_HEADER) };
        let e_magic = dos_header.e_magic;
        if e_magic != IMAGE_DOS_SIGNATURE {
            anyhow::bail!("invalid DOS header signature: {:#x}", e_magic);
        }

        let e_lfanew = dos_header.e_lfanew;
        let nt_header_offset = usize::try_from(e_lfanew)
            .map_err(|_| anyhow::anyhow!("invalid NT header offset: {}", e_lfanew))?;
        let image_base = image_base as *const u8;

        let nt_header_prefix =
            unsafe { &*(image_base.add(nt_header_offset) as *const ImageNtHeadersPrefix) };
        let nt_signature = nt_header_prefix.signature;
        if nt_signature != IMAGE_NT_SIGNATURE {
            anyhow::bail!("invalid NT header signature: {:#x}", nt_signature);
        }

        match nt_header_prefix.file_header.Machine {
            IMAGE_FILE_MACHINE_I386 => Ok(Self::Pe32 {
                image_base,
                nt_headers: unsafe {
                    &*(image_base.add(nt_header_offset) as *const IMAGE_NT_HEADERS32)
                },
            }),
            IMAGE_FILE_MACHINE_AMD64 => Ok(Self::Pe64 {
                image_base,
                nt_headers: unsafe {
                    &*(image_base.add(nt_header_offset) as *const IMAGE_NT_HEADERS64)
                },
            }),
            machine => anyhow::bail!("unsupported PE machine: {machine:#x}"),
        }
    }

    pub fn size_of_image(&self) -> usize {
        match self {
            Self::Pe32 { nt_headers, .. } => nt_headers.OptionalHeader.SizeOfImage as usize,
            Self::Pe64 { nt_headers, .. } => nt_headers.OptionalHeader.SizeOfImage as usize,
        }
    }

    pub fn image_base(&self) -> *const u8 {
        match self {
            Self::Pe32 { image_base, .. } => *image_base,
            Self::Pe64 { image_base, .. } => *image_base,
        }
    }

    pub fn image_bytes(&self) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts(self.image_base(), self.size_of_image()) }
    }

    pub fn image_data_directory(&self, index: usize) -> Option<IMAGE_DATA_DIRECTORY> {
        match self {
            Self::Pe32 { nt_headers, .. } => {
                let count = nt_headers.OptionalHeader.NumberOfRvaAndSizes as usize;
                if count > index {
                    Some(nt_headers.OptionalHeader.DataDirectory[index])
                } else {
                    None
                }
            }
            Self::Pe64 { nt_headers, .. } => {
                let count = nt_headers.OptionalHeader.NumberOfRvaAndSizes as usize;
                if count > index {
                    Some(nt_headers.OptionalHeader.DataDirectory[index])
                } else {
                    None
                }
            }
        }
    }

    pub fn import_directory(&self) -> Option<IMAGE_DATA_DIRECTORY> {
        self.image_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT as usize)
    }

    pub fn export_directory(&self) -> Option<IMAGE_DATA_DIRECTORY> {
        self.image_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT as usize)
    }

    pub fn reloc_directory(&self) -> Option<IMAGE_DATA_DIRECTORY> {
        self.image_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC as usize)
    }

    pub fn tls_directory(&self) -> Option<IMAGE_DATA_DIRECTORY> {
        self.image_data_directory(IMAGE_DIRECTORY_ENTRY_TLS as usize)
    }

    pub fn import_descriptors(&self) -> Result<Option<Vec<IMAGE_IMPORT_DESCRIPTOR>>> {
        let Some(import_directory) = self.import_directory() else {
            return Ok(None);
        };
        if import_directory.VirtualAddress == 0 || import_directory.Size == 0 {
            return Ok(None);
        }

        let descriptor_size = mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        let descriptor_count = import_directory.Size as usize / descriptor_size;
        if descriptor_count == 0 {
            anyhow::bail!("import directory is too small to contain any descriptors");
        }

        let mut descriptors = Vec::with_capacity(descriptor_count);
        for index in 0..descriptor_count {
            let byte_offset = index
                .checked_mul(descriptor_size)
                .ok_or_else(|| anyhow::anyhow!("import descriptor table offset overflowed"))?;
            let byte_offset = u32::try_from(byte_offset)
                .map_err(|_| anyhow::anyhow!("import descriptor table offset overflowed"))?;
            let descriptor_rva = import_directory
                .VirtualAddress
                .checked_add(byte_offset)
                .ok_or_else(|| anyhow::anyhow!("import descriptor RVA overflowed"))?;
            descriptors.push(self.read::<IMAGE_IMPORT_DESCRIPTOR>(descriptor_rva)?);
        }

        Ok(Some(descriptors))
    }

    pub fn slice(&self, rva: u32, size: usize) -> Result<&'a [u8]> {
        let start = rva as usize;
        let end = start
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("RVA overflow"))?;

        self.image_bytes()
            .get(start..end)
            .ok_or_else(|| anyhow::anyhow!("RVA out of bounds"))
    }

    pub fn c_string(&self, rva: u32) -> Result<&'a CStr> {
        let tail = self
            .image_bytes()
            .get(rva as usize..)
            .ok_or_else(|| anyhow::anyhow!("RVA out of bounds"))?;
        let nul_offset = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| anyhow::anyhow!("missing NUL"))?;

        CStr::from_bytes_with_nul(&tail[..=nul_offset])
            .map_err(|e| anyhow::anyhow!("invalid string: {e}"))
    }

    pub fn read<T: Copy>(&self, rva: u32) -> Result<T> {
        let bytes = self.slice(rva, mem::size_of::<T>())?;

        Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
    }

    pub fn u32s(&self, rva: u32, count: usize) -> Result<Vec<u32>> {
        let bytes = self.slice(
            rva,
            count
                .checked_mul(mem::size_of::<u32>())
                .ok_or_else(|| anyhow::anyhow!("size overflow"))?,
        )?;

        Ok(bytes
            .chunks_exact(mem::size_of::<u32>())
            .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("u32 chunk size")))
            .collect())
    }

    pub fn u16s(&self, rva: u32, count: usize) -> Result<Vec<u16>> {
        let bytes = self.slice(
            rva,
            count
                .checked_mul(mem::size_of::<u16>())
                .ok_or_else(|| anyhow::anyhow!("size overflow"))?,
        )?;

        Ok(bytes
            .chunks_exact(mem::size_of::<u16>())
            .map(|chunk| u16::from_le_bytes(chunk.try_into().expect("u16 chunk size")))
            .collect())
    }

    pub fn directory_contains_rva(&self, directory: IMAGE_DATA_DIRECTORY, rva: u32) -> bool {
        let start = directory.VirtualAddress as usize;
        let end = start.saturating_add(directory.Size as usize);
        let rva = rva as usize;

        rva >= start && rva < end
    }

    pub fn is_64(&self) -> bool {
        matches!(self, Self::Pe64 { .. })
    }

    pub fn thunk_entry_size(&self) -> usize {
        if self.is_64() {
            mem::size_of::<u64>()
        } else {
            mem::size_of::<u32>()
        }
    }

    pub fn read_import_lookup_entry(&self, thunk_rva: u32) -> Result<u64> {
        if self.is_64() {
            Ok(self.read::<u64>(thunk_rva)?)
        } else {
            Ok(self.read::<u32>(thunk_rva)? as u64)
        }
    }

    pub fn is_ordinal_import(&self, thunk_entry: u64) -> bool {
        if self.is_64() {
            thunk_entry & IMAGE_ORDINAL_FLAG64 != 0
        } else {
            (thunk_entry as u32) & IMAGE_ORDINAL_FLAG32 != 0
        }
    }

    pub fn import_ordinal(&self, thunk_entry: u64) -> u16 {
        (thunk_entry & 0xffff) as u16
    }

    pub fn import_name(&self, thunk_entry: u64) -> Result<&'a CStr> {
        let name_rva = u32::try_from(thunk_entry)
            .map_err(|_| anyhow::anyhow!("invalid import RVA"))?
            .checked_add(mem::size_of::<u16>() as u32)
            .ok_or_else(|| anyhow::anyhow!("import name RVA overflowed"))?;

        self.c_string(name_rva)
    }

    pub fn write_import_address(&self, thunk_rva: u32, proc_address: usize) -> Result<()> {
        let offset = thunk_rva as usize;
        let entry_size = self.thunk_entry_size();
        let end = offset
            .checked_add(entry_size)
            .ok_or_else(|| anyhow::anyhow!("IAT entry overflowed the image bounds"))?;
        if end > self.size_of_image() {
            anyhow::bail!(
                "IAT entry [{offset:#x}, {end:#x}) is outside the image size {:#x}",
                self.size_of_image()
            );
        }

        let patch_address = unsafe { self.image_base().add(offset) as *mut u8 };
        if self.is_64() {
            unsafe {
                std::ptr::write_unaligned(patch_address as *mut u64, proc_address as u64);
            }
        } else {
            let proc_address = u32::try_from(proc_address).map_err(|_| {
                anyhow::anyhow!("resolved import address does not fit in u32: {proc_address:#x}")
            })?;
            unsafe {
                std::ptr::write_unaligned(patch_address as *mut u32, proc_address);
            }
        }

        Ok(())
    }

    pub fn va(&self, rva: u32) -> Result<u64> {
        let address = (self.image_base() as usize)
            .checked_add(rva as usize)
            .ok_or_else(|| anyhow::anyhow!("address overflow"))?;

        Ok(address as u64)
    }

    pub fn is_null_import_descriptor(import_descriptor: &IMAGE_IMPORT_DESCRIPTOR) -> bool {
        import_descriptor.TimeDateStamp == 0
            && import_descriptor.ForwarderChain == 0
            && import_descriptor.Name == 0
            && import_descriptor.FirstThunk == 0
    }
}

fn read<T: Copy>(bytes: &[u8], offset: usize) -> Result<T> {
    let end = offset
        .checked_add(mem::size_of::<T>())
        .ok_or_else(|| anyhow::anyhow!("file offset overflow"))?;
    let bytes = bytes
        .get(offset..end)
        .ok_or_else(|| anyhow::anyhow!("file offset out of bounds"))?;

    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER_0;

    fn write_struct<T: Copy>(bytes: &mut [u8], offset: usize, value: &T) {
        let size = mem::size_of::<T>();
        let raw = unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size) };
        bytes[offset..offset + size].copy_from_slice(raw);
    }

    fn build_pe32_fixture() -> Vec<u8> {
        let nt_header_offset = 0x80usize;
        let section_offset = nt_header_offset + mem::size_of::<IMAGE_NT_HEADERS32>();
        let mut bytes = vec![0u8; section_offset + mem::size_of::<IMAGE_SECTION_HEADER>()];

        let mut dos_header: IMAGE_DOS_HEADER = unsafe { mem::zeroed() };
        dos_header.e_magic = IMAGE_DOS_SIGNATURE;
        dos_header.e_lfanew = nt_header_offset as i32;
        write_struct(&mut bytes, 0, &dos_header);

        let mut nt_headers: IMAGE_NT_HEADERS32 = unsafe { mem::zeroed() };
        nt_headers.Signature = IMAGE_NT_SIGNATURE;
        nt_headers.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
        nt_headers.FileHeader.NumberOfSections = 1;
        nt_headers.FileHeader.SizeOfOptionalHeader =
            u16::try_from(mem::size_of_val(&nt_headers.OptionalHeader)).unwrap();
        nt_headers.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        nt_headers.OptionalHeader.SizeOfImage = 0x5000;
        nt_headers.OptionalHeader.SizeOfHeaders = 0x400;
        nt_headers.OptionalHeader.ImageBase = 0x0040_0000;
        write_struct(&mut bytes, nt_header_offset, &nt_headers);

        let mut section: IMAGE_SECTION_HEADER = unsafe { mem::zeroed() };
        section.Name.copy_from_slice(b".text\0\0\0");
        section.Misc = IMAGE_SECTION_HEADER_0 {
            VirtualSize: 0x1234,
        };
        section.VirtualAddress = 0x1000;
        section.SizeOfRawData = 0x600;
        section.PointerToRawData = 0x400;
        write_struct(&mut bytes, section_offset, &section);

        bytes
    }

    fn build_pe64_fixture() -> Vec<u8> {
        let nt_header_offset = 0x80usize;
        let section_offset = nt_header_offset + mem::size_of::<IMAGE_NT_HEADERS64>();
        let mut bytes = vec![0u8; section_offset + mem::size_of::<IMAGE_SECTION_HEADER>()];

        let mut dos_header: IMAGE_DOS_HEADER = unsafe { mem::zeroed() };
        dos_header.e_magic = IMAGE_DOS_SIGNATURE;
        dos_header.e_lfanew = nt_header_offset as i32;
        write_struct(&mut bytes, 0, &dos_header);

        let mut nt_headers: IMAGE_NT_HEADERS64 = unsafe { mem::zeroed() };
        nt_headers.Signature = IMAGE_NT_SIGNATURE;
        nt_headers.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt_headers.FileHeader.NumberOfSections = 1;
        nt_headers.FileHeader.SizeOfOptionalHeader =
            u16::try_from(mem::size_of_val(&nt_headers.OptionalHeader)).unwrap();
        nt_headers.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt_headers.OptionalHeader.SizeOfImage = 0x7000;
        nt_headers.OptionalHeader.SizeOfHeaders = 0x400;
        nt_headers.OptionalHeader.ImageBase = 0x0000_0001_4000_0000;
        write_struct(&mut bytes, nt_header_offset, &nt_headers);

        let mut section: IMAGE_SECTION_HEADER = unsafe { mem::zeroed() };
        section.Name.copy_from_slice(b".rdata\0\0");
        section.Misc = IMAGE_SECTION_HEADER_0 {
            VirtualSize: 0x5678,
        };
        section.VirtualAddress = 0x2000;
        section.SizeOfRawData = 0x800;
        section.PointerToRawData = 0x400;
        write_struct(&mut bytes, section_offset, &section);

        bytes
    }

    #[test]
    fn parses_pe32_images() {
        let bytes = build_pe32_fixture();
        let parsed = ParsedPeFile::parse(&bytes).expect("PE32 fixture should parse");
        let sections = parsed.sections().expect("section headers should parse");

        assert!(!parsed.is_64());
        assert_eq!(parsed.machine(), IMAGE_FILE_MACHINE_I386);
        assert_eq!(parsed.size_of_image(), 0x5000);
        assert_eq!(parsed.size_of_headers(), 0x400);
        assert_eq!(parsed.image_base(), 0x0040_0000);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].Name, *b".text\0\0\0");
        assert_eq!(unsafe { sections[0].Misc.VirtualSize }, 0x1234);
        assert_eq!(sections[0].VirtualAddress, 0x1000);
        assert_eq!(sections[0].SizeOfRawData, 0x600);
    }

    #[test]
    fn parses_pe64_images() {
        let bytes = build_pe64_fixture();
        let parsed = ParsedPeFile::parse(&bytes).expect("PE64 fixture should parse");
        let sections = parsed.sections().expect("section headers should parse");

        assert!(parsed.is_64());
        assert_eq!(parsed.machine(), IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(parsed.size_of_image(), 0x7000);
        assert_eq!(parsed.size_of_headers(), 0x400);
        assert_eq!(parsed.image_base(), 0x0000_0001_4000_0000);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].Name, *b".rdata\0\0");
        assert_eq!(unsafe { sections[0].Misc.VirtualSize }, 0x5678);
        assert_eq!(sections[0].VirtualAddress, 0x2000);
        assert_eq!(sections[0].SizeOfRawData, 0x800);
    }

    #[test]
    fn parsed_pe_file_exposes_section_headers() {
        let bytes = build_pe32_fixture();
        let parsed = ParsedPeFile::parse(&bytes).expect("PE32 fixture should parse");
        let sections = parsed.sections().expect("section headers should parse");

        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].Name, *b".text\0\0\0");
        assert_eq!(unsafe { sections[0].Misc.VirtualSize }, 0x1234);
        assert_eq!(sections[0].VirtualAddress, 0x1000);
    }
}
