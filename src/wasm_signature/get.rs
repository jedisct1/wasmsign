use super::super::errors::*;
use super::super::signature::*;
use byteorder::{ByteOrder, LittleEndian};
use parity_wasm::elements::*;

pub fn get_signature(module: &Module, signature_symbol: &str) -> Result<Signature, WError> {
    // Get the global ID of the exported name matching the signature symbol

    let export_section = module.export_section().unwrap();
    let export_entry = match export_section
        .entries()
        .iter()
        .find(|export_entry| export_entry.field() == signature_symbol)
    {
        None => Err(WError::ParseError(format!(
            "Symbol {} not found",
            signature_symbol
        )))?,
        Some(export_entry) => export_entry,
    };
    let global_id = match export_entry.internal() {
        Internal::Global(global_id) => *global_id,
        _ => Err(WError::ParseError(
            "Wrong type for the signature global".to_string(),
        ))?,
    };

    // Get the offset of the data segment with address of the signature

    let global_section = module.global_section().unwrap();
    let global_entries = global_section.entries();
    if global_entries.len() <= global_id as usize {
        Err(WError::ParseError(
            "Global section is too short".to_string(),
        ))?;
    }
    let global_entry = &global_entries[global_id as usize];
    let global_entry_type = global_entry.global_type();
    if global_entry_type.is_mutable() {
        Err(WError::ParseError("Signature is mutable".to_string()))?;
    }
    match global_entry_type.content_type() {
        ValueType::I32 => {}
        _ => Err(WError::ParseError(
            "Unexpected type for the signature global entry".to_string(),
        ))?,
    }
    let global_entry_code = global_entry.init_expr().code();
    if global_entry_code.len() != 2 {
        Err(WError::ParseError(
            "Unexpected length for the global entry code".to_string(),
        ))?;
    }
    if global_entry_code[1] != Instruction::End {
        Err(WError::ParseError(
            "End not found in the global entry code".to_string(),
        ))?;
    }
    let ref_data_segment_offset = match global_entry_code[0] {
        Instruction::I32Const(ref_data_segment_offset) => ref_data_segment_offset,
        _ => Err(WError::ParseError("Unexpected offset type".to_string()))?,
    };

    // Get the address of the signature

    let data_section = module.data_section().unwrap();
    let ref_data_segment = match data_section.entries().iter().find(|data_segment| {
        let instructions = data_segment.offset().code();
        if instructions.len() != 2 {
            return false;
        }
        match instructions[1] {
            Instruction::End => {}
            _ => return false,
        }
        let offset = match instructions[0] {
            Instruction::I32Const(offset) => offset,
            _ => return false,
        };
        offset == ref_data_segment_offset
    }) {
        None => Err(WError::ParseError(
            "Reference data segment not found".to_string(),
        ))?,
        Some(ref_data_segment) => ref_data_segment,
    };
    let ref_data_segment_value = ref_data_segment.value();
    if ref_data_segment_value.len() != 4 {
        Err(WError::ParseError(
            "Encoded reference is too short".to_string(),
        ))?
    }
    let data_segment_offset = LittleEndian::read_i32(ref_data_segment_value);
    if data_segment_offset < 0 {
        Err(WError::ParseError(
            "Negative data segment offset".to_string(),
        ))?
    }

    // Get the signature

    let data_segment = match data_section.entries().iter().find(|data_segment| {
        let instructions = data_segment.offset().code();
        if instructions.len() != 2 {
            return false;
        }
        match instructions[1] {
            Instruction::End => {}
            _ => return false,
        }
        let offset = match instructions[0] {
            Instruction::I32Const(offset) => offset,
            _ => return false,
        };
        offset == data_segment_offset
    }) {
        None => Err(WError::ParseError("Data segment not found".to_string()))?,
        Some(data_segment) => data_segment,
    };
    let data_segment_value = data_segment.value();
    Signature::from_bytes(data_segment_value)
}
