//! FOX Binary Format Parsers
//!
//! P0: PE32 / PE32+ (Windows)
//! Future: ELF, Mach-O

pub mod elf;
pub mod macho;
pub mod pe;

use fox_arch::Architecture;
use fox_core::{FoxError, FoxResult};
use serde::{Deserialize, Serialize};

/// Detected binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    PE32,
    PE32Plus,
    ELF32,
    ELF64,
    MachO32,
    MachO64,
    Unknown,
}

impl BinaryFormat {
    pub fn display_name(&self) -> &'static str {
        match self {
            BinaryFormat::PE32 => "PE32 (Windows 32-bit)",
            BinaryFormat::PE32Plus => "PE32+ (Windows 64-bit)",
            BinaryFormat::ELF32 => "ELF32",
            BinaryFormat::ELF64 => "ELF64",
            BinaryFormat::MachO32 => "Mach-O 32-bit",
            BinaryFormat::MachO64 => "Mach-O 64-bit",
            BinaryFormat::Unknown => "Unknown",
        }
    }
}

/// A loaded binary with parsed metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binary {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub entry_point: u64,
    pub image_base: u64,
    pub size: usize,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<Relocation>,
    pub strings: Vec<BinaryString>,
    pub raw_data: Vec<u8>,
}

impl Binary {
    /// Detect binary format from raw bytes.
    pub fn detect_format(data: &[u8]) -> BinaryFormat {
        if data.len() >= 2 && &data[0..2] == b"MZ" {
            // PE: check e_lfanew at offset 0x3C
            if data.len() >= 0x40 {
                let e_lfanew =
                    u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
                if e_lfanew + 4 < data.len() && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
                    // Check Optional Header magic
                    if e_lfanew + 0x18 < data.len() {
                        let magic =
                            u16::from_le_bytes([data[e_lfanew + 0x18], data[e_lfanew + 0x19]]);
                        return match magic {
                            0x10B => BinaryFormat::PE32,
                            0x20B => BinaryFormat::PE32Plus,
                            _ => BinaryFormat::Unknown,
                        };
                    }
                }
            }
        }
        if data.len() >= 4 && &data[0..4] == b"\x7FELF" && data.len() >= 5 {
            return match data[4] {
                1 => BinaryFormat::ELF32,
                2 => BinaryFormat::ELF64,
                _ => BinaryFormat::Unknown,
            };
        }
        if data.len() >= 4 {
            let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            if matches!(magic, 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE) {
                return match magic {
                    0xFEEDFACE | 0xCEFAEDFE => BinaryFormat::MachO32,
                    0xFEEDFACF | 0xCFFAEDFE => BinaryFormat::MachO64,
                    _ => BinaryFormat::Unknown,
                };
            }
        }
        BinaryFormat::Unknown
    }

    /// Load and parse a binary from raw bytes.
    pub fn load(data: Vec<u8>) -> FoxResult<Self> {
        let format = Self::detect_format(&data);
        match format {
            BinaryFormat::PE32 | BinaryFormat::PE32Plus => pe::PE::parse(&data, format),
            _ => Err(FoxError::UnsupportedBinaryFormat(
                format.display_name().to_string(),
            )),
        }
    }

    /// Get section data by name.
    pub fn section_data(&self, name: &str) -> Option<&[u8]> {
        self.sections
            .iter()
            .find(|s| s.name == name)
            .map(|s| &self.raw_data[s.raw_offset..s.raw_offset + s.raw_size])
    }

    /// Get executable sections.
    pub fn executable_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.is_executable()).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u32,
    pub raw_offset: usize,
    pub raw_size: usize,
    pub characteristics: u32,
}

impl Section {
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x20000000 != 0 // IMAGE_SCN_MEM_EXECUTE
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & 0x40000000 != 0 // IMAGE_SCN_MEM_READ
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x80000000 != 0 // IMAGE_SCN_MEM_WRITE
    }

    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.virtual_address && addr < self.virtual_address + self.virtual_size as u64
    }

    /// Convert RVA to file offset within this section.
    pub fn rva_to_offset(&self, rva: u64) -> Option<usize> {
        if self.contains_address(rva) {
            Some(self.raw_offset + (rva - self.virtual_address) as usize)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub dll_name: String,
    pub functions: Vec<ImportFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub iat_address: u64,
    pub hint: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: Option<String>,
    pub ordinal: u16,
    pub address: u64,
    pub is_forwarded: bool,
    pub forward_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relocation {
    pub virtual_address: u64,
    pub relocation_type: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryString {
    pub address: u64,
    pub value: String,
    pub length: usize,
}
