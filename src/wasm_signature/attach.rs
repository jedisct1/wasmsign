use super::super::errors::*;
use super::super::signature::*;
use byteorder::{LittleEndian, WriteBytesExt};
use parity_wasm::elements::*;
use std::{i32, u32};

pub fn attach_signature(
    mut module: Module,
    signature: &Signature,
    signature_symbol: &str,
) -> Result<Module, WError> {
    // Find the offset after the last entry in the data section

    let data_section = module.data_section().unwrap();
    let last_data_segment = data_section
        .entries()
        .iter()
        .map(|data_segment| {
            let instructions = data_segment.offset().code();
            if instructions.len() != 2 {
                panic!("Multiple offsets")
            }
            match instructions[1] {
                Instruction::End => {}
                _ => panic!("Missing End opcode after offset"),
            }
            let offset = match instructions[0] {
                Instruction::I32Const(offset) => offset,
                _ => panic!("Unexpected offset type"),
            };
            if offset < 0 {
                panic!("Negative offset")
            }
            let len = data_segment.value().len();
            if (u32::MAX as usize - offset as usize) < len {
                panic!("Overflow")
            }
            (offset, len as u32)
        })
        .max_by_key(|&(_offset, len)| len)
        .ok_or_else(|| WError::ParseError("No entry in data segment".to_string()))?;

    // Add the signature to the data section

    if (i32::MAX as u32 - last_data_segment.0 as u32) < last_data_segment.1 {
        Err(WError::UsageError(
            "Data section is full, offset would overflow",
        ))?;
    }
    let new_data_segment_offset = last_data_segment.0 + last_data_segment.1 as i32;
    let new_data_segment_index = data_section.entries().len();
    if new_data_segment_index > u32::MAX as usize {
        Err(WError::UsageError("Data section is full"))?;
    }
    let new_data_segment_offset_code = vec![
        Instruction::I32Const(new_data_segment_offset as i32),
        Instruction::End,
    ];
    let new_data = signature.to_bytes();
    let new_data_segment_len = new_data.len() as u32;
    let new_data_segment = DataSegment::new(
        new_data_segment_index as u32,
        InitExpr::new(new_data_segment_offset_code),
        new_data,
    );
    let data_section = module.data_section_mut().unwrap();
    data_section.entries_mut().push(new_data_segment);

    // Add the address of the signature to the data section

    if (i32::MAX as u32 - new_data_segment_offset as u32) < new_data_segment_len {
        Err(WError::UsageError(
            "Data section is full, offset would overflow",
        ))?;
    }
    let new_ref_data_segment_offset = new_data_segment_offset + new_data_segment_len as i32;
    if new_data_segment_index > u32::MAX as usize {
        Err(WError::UsageError("Data section is full"))?;
    }
    let new_ref_data_segment_index = new_data_segment_index + 1;
    let new_ref_data_segment_offset_code = vec![
        Instruction::I32Const(new_ref_data_segment_offset as i32),
        Instruction::End,
    ];
    let mut ref_bytes = vec![];
    ref_bytes
        .write_i32::<LittleEndian>(new_data_segment_offset)
        .unwrap();
    let new_ref_data = ref_bytes;
    let new_ref_data_segment = DataSegment::new(
        new_ref_data_segment_index as u32,
        InitExpr::new(new_ref_data_segment_offset_code),
        new_ref_data,
    );
    let data_section = module.data_section_mut().unwrap();
    data_section.entries_mut().push(new_ref_data_segment);

    // Add a global for the address of the signature

    let global_section = module.global_section().unwrap();
    let new_global_id = global_section.entries().len();
    if new_global_id > u32::MAX as usize {
        Err(WError::UsageError("Global section ID would overflow"))?;
    }
    let new_global_id = new_global_id as u32;
    let new_global_type = GlobalType::new(ValueType::I32, false);
    let new_global_code = vec![
        Instruction::I32Const(new_ref_data_segment_offset as i32),
        Instruction::End,
    ];
    let new_global_entry = GlobalEntry::new(new_global_type, InitExpr::new(new_global_code));
    let global_section = module.global_section_mut().unwrap();
    global_section.entries_mut().push(new_global_entry);

    // Add the global to the export section

    let export_section = module.export_section().unwrap();
    if export_section
        .entries()
        .iter()
        .any(|export_entry| export_entry.field() == signature_symbol)
    {
        Err(WError::ParseError(format!(
            "{} symbol already present",
            signature_symbol
        )))?;
    }
    let new_export_entry =
        ExportEntry::new(signature_symbol.into(), Internal::Global(new_global_id));
    let export_section = module.export_section_mut().unwrap();
    export_section.entries_mut().push(new_export_entry);

    Ok(module)
}
