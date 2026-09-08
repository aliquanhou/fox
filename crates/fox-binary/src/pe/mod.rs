//! PE (Portable Executable) Parser
//!
//! P0 capabilities:
//! - PE Header (DOS + NT + Optional + Section Table)
//! - Sections
//! - Imports
//! - Exports
//! - Relocations
//! - Strings
//! - Entry Point
//! - Architecture Detection

use crate::{
    Binary, BinaryFormat, BinaryString, Export, Import, ImportFunction, Relocation, Section,
};
use fox_arch::Architecture;
use fox_core::{FoxError, FoxResult};

pub struct PE;

impl PE {
    pub fn parse(data: &[u8], format: BinaryFormat) -> FoxResult<Binary> {
        let is_64 = matches!(format, BinaryFormat::PE32Plus);

        // DOS Header
        if data.len() < 0x40 {
            return Err(FoxError::ParseError {
                offset: 0,
                message: "File too small for DOS header".into(),
            });
        }
        let e_lfanew = read_u32(data, 0x3C)? as usize;

        // PE Signature
        if e_lfanew + 4 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(FoxError::ParseError {
                offset: e_lfanew,
                message: "Invalid PE signature".into(),
            });
        }

        // COFF File Header (at e_lfanew + 4)
        let coff_offset = e_lfanew + 4;
        let machine = read_u16(data, coff_offset)?;
        let number_of_sections = read_u16(data, coff_offset + 2)? as usize;
        let size_of_optional_header = read_u16(data, coff_offset + 16)? as usize;
        let characteristics = read_u16(data, coff_offset + 18)?;

        let architecture = match machine {
            0x014C => Architecture::X86,   // IMAGE_FILE_MACHINE_I386
            0x8664 => Architecture::X64,   // IMAGE_FILE_MACHINE_AMD64
            0xAA64 => Architecture::ARM64, // IMAGE_FILE_MACHINE_ARM64
            other => {
                return Err(FoxError::UnsupportedArchitecture(format!(
                    "machine=0x{:04X}",
                    other
                )))
            }
        };

        // Optional Header
        let opt_offset = coff_offset + 20;
        let entry_point_rva = read_u32(data, opt_offset + 16)? as u64;
        let image_base = if is_64 {
            read_u64(data, opt_offset + 24)?
        } else {
            read_u32(data, opt_offset + 28)? as u64
        };

        // Data directories
        let dd_offset = if is_64 {
            opt_offset + 112
        } else {
            opt_offset + 96
        };
        let import_dd_rva = read_u32(data, dd_offset + 8)? as u64; // Import Table is directory index 1
        let import_dd_size = read_u32(data, dd_offset + 12)? as usize;
        let export_dd_rva = read_u32(data, dd_offset)? as u64; // Export Table is directory index 0
        let export_dd_size = read_u32(data, dd_offset + 4)? as usize;
        let reloc_dd_rva = read_u32(data, dd_offset + 40)? as u64; // Base Relocation is directory index 5
        let reloc_dd_size = read_u32(data, dd_offset + 44)? as usize;

        // Section Table
        let section_table_offset = opt_offset + size_of_optional_header;
        let mut sections = Vec::with_capacity(number_of_sections);
        for i in 0..number_of_sections {
            let sec_off = section_table_offset + i * 40;
            if sec_off + 40 > data.len() {
                break;
            }
            let name_bytes = &data[sec_off..sec_off + 8];
            let name = String::from_utf8_lossy(name_bytes.split(|&b| b == 0).next().unwrap_or(b""))
                .to_string();
            let virtual_size = read_u32(data, sec_off + 8)?;
            let virtual_address = read_u32(data, sec_off + 12)? as u64;
            let raw_size = read_u32(data, sec_off + 16)? as usize;
            let raw_offset = read_u32(data, sec_off + 20)? as usize;
            let sec_characteristics = read_u32(data, sec_off + 36)?;

            sections.push(Section {
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                characteristics: sec_characteristics,
            });
        }

        // Helper: RVA to file offset
        let rva_to_offset = |rva: u64| -> Option<usize> {
            sections
                .iter()
                .find(|s| {
                    rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size as u64
                })
                .map(|s| s.raw_offset + (rva - s.virtual_address) as usize)
        };

        // Parse Imports
        let imports = if import_dd_rva != 0 && import_dd_size > 0 {
            Self::parse_imports(data, import_dd_rva, &rva_to_offset, is_64)?
        } else {
            Vec::new()
        };

        // Parse Exports
        let exports = if export_dd_rva != 0 && export_dd_size > 0 {
            Self::parse_exports(data, export_dd_rva, &rva_to_offset)?
        } else {
            Vec::new()
        };

        // Parse Relocations
        let relocations = if reloc_dd_rva != 0 && reloc_dd_size > 0 {
            Self::parse_relocations(data, reloc_dd_rva, reloc_dd_size, &rva_to_offset)?
        } else {
            Vec::new()
        };

        // Extract Strings
        let strings = Self::extract_strings(data, &sections, image_base);

        let _ = characteristics; // used for validation if needed

        Ok(Binary {
            format,
            architecture,
            entry_point: image_base + entry_point_rva,
            image_base,
            size: data.len(),
            sections,
            imports,
            exports,
            relocations,
            strings,
            raw_data: data.to_vec(),
        })
    }

    fn parse_imports(
        data: &[u8],
        import_rva: u64,
        rva_to_offset: &dyn Fn(u64) -> Option<usize>,
        is_64: bool,
    ) -> FoxResult<Vec<Import>> {
        let mut imports = Vec::new();
        let mut current_rva = import_rva;
        let entry_size = if is_64 { 8 } else { 4 };

        while let Some(offset) = rva_to_offset(current_rva) {
            if offset + 20 > data.len() {
                break;
            }

            // IMAGE_IMPORT_DESCRIPTOR
            let original_first_thunk = read_u32(data, offset)? as u64;
            let name_rva = read_u32(data, offset + 12)? as u64;
            let first_thunk = read_u32(data, offset + 16)? as u64;

            // Empty descriptor marks end
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }

            let dll_name = if name_rva != 0 {
                if let Some(name_off) = rva_to_offset(name_rva) {
                    read_cstring(data, name_off)
                } else {
                    "<unknown>".to_string()
                }
            } else {
                "<unknown>".to_string()
            };

            let thunk_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            let mut functions = Vec::new();

            if thunk_rva != 0 {
                let mut thunk_idx = 0;
                while let Some(thunk_off) = rva_to_offset(thunk_rva + thunk_idx * entry_size as u64)
                {
                    if thunk_off + entry_size > data.len() {
                        break;
                    }

                    let thunk_value = if is_64 {
                        read_u64(data, thunk_off)?
                    } else {
                        read_u32(data, thunk_off)? as u64
                    };

                    if thunk_value == 0 {
                        break;
                    }

                    let iat_addr = first_thunk + thunk_idx * entry_size as u64;

                    if thunk_value & (1u64 << (if is_64 { 63 } else { 31 })) != 0 {
                        // Import by ordinal
                        let ordinal = (thunk_value & 0xFFFF) as u16;
                        functions.push(ImportFunction {
                            name: None,
                            ordinal: Some(ordinal),
                            iat_address: iat_addr,
                            hint: 0,
                        });
                    } else {
                        // Import by name
                        let hint_name_rva = thunk_value & 0x7FFFFFFF;
                        if let Some(hn_off) = rva_to_offset(hint_name_rva) {
                            let hint = if hn_off + 2 <= data.len() {
                                read_u16(data, hn_off)?
                            } else {
                                0
                            };
                            let name = read_cstring(data, hn_off + 2);
                            functions.push(ImportFunction {
                                name: Some(name),
                                ordinal: None,
                                iat_address: iat_addr,
                                hint,
                            });
                        }
                    }
                    thunk_idx += 1;
                }
            }

            imports.push(Import {
                dll_name,
                functions,
            });
            current_rva += 20; // size of IMAGE_IMPORT_DESCRIPTOR
        }

        Ok(imports)
    }

    fn parse_exports(
        data: &[u8],
        export_rva: u64,
        rva_to_offset: &dyn Fn(u64) -> Option<usize>,
    ) -> FoxResult<Vec<Export>> {
        let offset = match rva_to_offset(export_rva) {
            Some(o) => o,
            None => return Ok(Vec::new()),
        };
        if offset + 40 > data.len() {
            return Ok(Vec::new());
        }

        let number_of_functions = read_u32(data, offset + 20)? as usize;
        let number_of_names = read_u32(data, offset + 24)? as usize;
        let address_of_functions = read_u32(data, offset + 28)? as u64;
        let address_of_names = read_u32(data, offset + 32)? as u64;
        let address_of_name_ordinals = read_u32(data, offset + 36)? as u64;
        let base_ordinal = read_u32(data, offset + 16)?;

        let mut exports = Vec::new();

        // Build name -> ordinal mapping
        let mut name_by_ordinal: std::collections::HashMap<u16, String> =
            std::collections::HashMap::new();
        for i in 0..number_of_names {
            let name_ptr_off = match rva_to_offset(address_of_names + i as u64 * 4) {
                Some(o) => o,
                None => continue,
            };
            let name_rva = read_u32(data, name_ptr_off)? as u64;
            let ord_idx_off = match rva_to_offset(address_of_name_ordinals + i as u64 * 2) {
                Some(o) => o,
                None => continue,
            };
            let ord_idx = read_u16(data, ord_idx_off)?;
            if let Some(name_off) = rva_to_offset(name_rva) {
                name_by_ordinal.insert(ord_idx, read_cstring(data, name_off));
            }
        }

        for i in 0..number_of_functions {
            let func_off = match rva_to_offset(address_of_functions + i as u64 * 4) {
                Some(o) => o,
                None => continue,
            };
            let func_rva = read_u32(data, func_off)? as u64;
            if func_rva == 0 {
                continue;
            }

            let ordinal = (base_ordinal + i as u32) as u16;
            let name = name_by_ordinal.get(&(i as u16)).cloned();

            // Check if forwarded
            let is_forwarded = export_rva != 0 && {
                let export_end = export_rva + 40; // approximate
                func_rva >= export_rva && func_rva < export_end + 1024
            };

            let forward_name = if is_forwarded {
                rva_to_offset(func_rva).map(|o| read_cstring(data, o))
            } else {
                None
            };

            exports.push(Export {
                name,
                ordinal,
                address: func_rva,
                is_forwarded,
                forward_name,
            });
        }

        Ok(exports)
    }

    fn parse_relocations(
        data: &[u8],
        reloc_rva: u64,
        reloc_size: usize,
        rva_to_offset: &dyn Fn(u64) -> Option<usize>,
    ) -> FoxResult<Vec<Relocation>> {
        let mut relocations = Vec::new();
        let mut current_rva = reloc_rva;
        let end_rva = reloc_rva + reloc_size as u64;

        while current_rva < end_rva {
            let offset = match rva_to_offset(current_rva) {
                Some(o) => o,
                None => break,
            };
            if offset + 8 > data.len() {
                break;
            }

            let page_rva = read_u32(data, offset)? as u64;
            let block_size = read_u32(data, offset + 4)? as usize;

            if block_size == 0 {
                break;
            }

            let num_entries = (block_size - 8) / 2;
            for i in 0..num_entries {
                let entry_off = offset + 8 + i * 2;
                if entry_off + 2 > data.len() {
                    break;
                }
                let entry = read_u16(data, entry_off)?;
                let rel_type = (entry >> 12) as u8;
                let offset_in_page = (entry & 0x0FFF) as u64;

                if rel_type != 0 {
                    // 0 = absolute (padding)
                    relocations.push(Relocation {
                        virtual_address: page_rva + offset_in_page,
                        relocation_type: rel_type,
                    });
                }
            }

            current_rva += block_size as u64;
        }

        Ok(relocations)
    }

    fn extract_strings(data: &[u8], sections: &[Section], image_base: u64) -> Vec<BinaryString> {
        let mut strings = Vec::new();
        let min_length = 4;

        for section in sections {
            if !section.is_readable() {
                continue;
            }
            let start = section.raw_offset;
            let end = (start + section.raw_size).min(data.len());
            if start >= end {
                continue;
            }

            let section_data = &data[start..end];
            let mut i = 0;
            while i < section_data.len() {
                if section_data[i].is_ascii_graphic() || section_data[i] == b' ' {
                    let str_start = i;
                    while i < section_data.len()
                        && (section_data[i].is_ascii_graphic() || section_data[i] == b' ')
                    {
                        i += 1;
                    }
                    let len = i - str_start;
                    if len >= min_length && i < section_data.len() && section_data[i] == 0 {
                        let value =
                            String::from_utf8_lossy(&section_data[str_start..str_start + len])
                                .to_string();
                        let rva = section.virtual_address + str_start as u64;
                        strings.push(BinaryString {
                            address: image_base + rva,
                            value,
                            length: len,
                        });
                        i += 1; // skip null terminator
                    }
                } else {
                    i += 1;
                }
            }
        }

        strings
    }
}

// --- Helper functions ---

fn read_u16(data: &[u8], offset: usize) -> FoxResult<u16> {
    if offset + 2 > data.len() {
        return Err(FoxError::ParseError {
            offset,
            message: "u16 read out of bounds".into(),
        });
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> FoxResult<u32> {
    if offset + 4 > data.len() {
        return Err(FoxError::ParseError {
            offset,
            message: "u32 read out of bounds".into(),
        });
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn read_u64(data: &[u8], offset: usize) -> FoxResult<u64> {
    if offset + 8 > data.len() {
        return Err(FoxError::ParseError {
            offset,
            message: "u64 read out of bounds".into(),
        });
    }
    Ok(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

fn read_cstring(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pe_format() {
        // Minimal PE32 header
        let mut data = vec![0u8; 0x100];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes()); // PE32 magic

        assert_eq!(Binary::detect_format(&data), BinaryFormat::PE32);
    }

    #[test]
    fn test_detect_unknown_format() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        assert_eq!(Binary::detect_format(&data), BinaryFormat::Unknown);
    }

    #[test]
    fn test_read_helpers() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u16(&data, 0).unwrap(), 0x0201);
        assert_eq!(read_u32(&data, 0).unwrap(), 0x04030201);
        assert_eq!(read_u64(&data, 0).unwrap(), 0x0807060504030201);
    }
}
