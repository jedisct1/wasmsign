use super::super::errors::*;
use super::super::signature::*;
use byteorder::{LittleEndian, WriteBytesExt};
use parity_wasm::elements::*;
use std::{i32, u32};

pub fn attach_signature(
    mut module: Module,
    signature_alg: &Box<dyn SignatureAlg>,
    ad: Option<&[u8]>,
    key_pair: &KeyPair,
    signature_symbol: &str,
) -> Result<Module, WError> {
    // Find the offset after the last entry in the data section

    let last_data_segment = {
        let data_section = module.data_section().expect("No data section");
        let last_data_segment = data_section
            .entries()
            .iter()
            .map(|data_segment| {
                let instructions = data_segment
                    .offset()
                    .as_ref()
                    .expect("Invalid offset")
                    .code();
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
        last_data_segment
    };

    // Add the signature to the data section

    let (new_data_segment_offset, new_data_segment_len, new_data_memory_index, new_data_index) = {
        let data_section = module.data_section().expect("No data section");
        if (i32::MAX as u32 - last_data_segment.0 as u32) < last_data_segment.1 {
            Err(WError::UsageError(
                "Data section is full, offset would overflow",
            ))?;
        }
        if data_section.entries().len() > u32::MAX as usize {
            Err(WError::UsageError("Data section is full"))?;
        }
        let new_data_segment_offset = last_data_segment.0 + last_data_segment.1 as i32;
        let new_data_memory_index = 0;
        let new_data_segment_offset_code = vec![
            Instruction::I32Const(new_data_segment_offset as i32),
            Instruction::End,
        ];
        let empty_signature = vec![0; Signature::length(signature_alg)];
        let new_data = empty_signature.clone();
        let new_data_segment_len = new_data.len() as u32;
        let new_data_segment = DataSegment::new(
            new_data_memory_index as u32,
            Some(InitExpr::new(new_data_segment_offset_code)),
            new_data,
            false,
        );
        let data_section = module.data_section_mut().expect("No data section");
        let new_data_index = data_section.entries().len();
        data_section.entries_mut().push(new_data_segment);
        (
            new_data_segment_offset,
            new_data_segment_len,
            new_data_memory_index,
            new_data_index,
        )
    };

    // Add the address of the signature to the data section

    let new_ref_data_segment_offset = {
        let data_section = module.data_section().expect("No data section");
        if (i32::MAX as u32 - new_data_segment_offset as u32) < new_data_segment_len {
            Err(WError::UsageError(
                "Data section is full, offset would overflow",
            ))?;
        }
        if data_section.entries().len() > u32::MAX as usize {
            Err(WError::UsageError("Data section is full"))?;
        }
        let new_ref_data_segment_offset = new_data_segment_offset + new_data_segment_len as i32;
        let new_ref_data_memory_index = new_data_memory_index;
        let new_ref_data_segment_offset_code = vec![
            Instruction::I32Const(new_ref_data_segment_offset as i32),
            Instruction::End,
        ];
        let mut ref_bytes = vec![];
        ref_bytes.write_i32::<LittleEndian>(new_data_segment_offset)?;
        let new_ref_data = ref_bytes;
        let new_ref_data_segment = DataSegment::new(
            new_ref_data_memory_index as u32,
            Some(InitExpr::new(new_ref_data_segment_offset_code)),
            new_ref_data,
            false,
        );
        let data_section = module.data_section_mut().expect("No data section");
        data_section.entries_mut().push(new_ref_data_segment);
        new_ref_data_segment_offset
    };

    // Add a global for the address of the signature

    let new_global_id = {
        let global_section = module.global_section().expect("No global section");
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
        let global_section = module.global_section_mut().expect("No global section");
        global_section.entries_mut().push(new_global_entry);
        new_global_id
    };

    // Add the global to the export section

    {
        let export_section = module.export_section().expect("No export section");
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
        let export_section = module.export_section_mut().expect("No export section");
        export_section.entries_mut().push(new_export_entry);
    }

    // Store the actual signature

    let module = {
        let module_code = parity_wasm::serialize(module)?;
        let signature = signature_alg.sign(&module_code, ad, key_pair)?;
        let mut module: Module = parity_wasm::deserialize_buffer(&module_code)?;
        let data_section = module.data_section_mut().expect("No data section");
        let signature_bytes = data_section.entries_mut()[new_data_index].value_mut();
        let empty_signature = vec![0; Signature::length(signature_alg)];
        assert_eq!(signature_bytes, &empty_signature);
        signature_bytes[..].copy_from_slice(&signature.to_bytes());
        module
    };

    Ok(module)
}
