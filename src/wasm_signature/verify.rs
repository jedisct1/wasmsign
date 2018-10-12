use super::super::errors::*;
use super::super::signature::*;
use byteorder::{ByteOrder, LittleEndian};
use parity_wasm::elements::*;

pub fn verify_signature(
    module: &Module,
    ad: Option<&[u8]>,
    pk: PublicKey,
    signature_symbol: &str,
) -> Result<(), WError> {
    // Get the global ID of the exported name matching the signature symbol
    let global_id = {
        let export_section = module.export_section().expect("No export section");
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
        global_id
    };

    // Get the offset of the data segment with address of the signature

    let ref_data_segment_offset = {
        let global_section = module.global_section().expect("No global section");
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
        ref_data_segment_offset
    };

    // Get the address of the signature

    let data_segment_offset = {
        let data_section = module.data_section().expect("No data section");
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
        data_segment_offset
    };

    // Work on a mutable copy of the module

    let mut module = module.clone();

    // Compute the signature, and also return where it is stored

    let (signature, data_segment_value) = {
        let data_section = module.data_section_mut().expect("No data section");
        let data_segment = match data_section.entries_mut().iter_mut().find(|data_segment| {
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
        let data_segment_value = data_segment.value_mut();
        let signature_bytes = data_segment_value.clone();
        let signature = Signature::from_bytes(&signature_bytes)?;
        (signature, data_segment_value)
    };

    // Check the signature

    let empty_signature = vec![0; data_segment_value.len()];
    data_segment_value.copy_from_slice(&empty_signature);
    let module_bytes = parity_wasm::serialize(module)?;
    let signature_alg = signature.to_alg()?;
    if signature_alg.alg_id() != pk.alg_id() {
        Err(WError::SignatureError(
            "Signature uses a different scheme than the provided public key",
        ))?;
    }
    signature_alg.verify(&module_bytes, ad, pk.raw(), &signature)
}
