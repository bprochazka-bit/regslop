//! Value (vk) operations for the logical layer.
//!
//! A key's values are indexed by a value-list cell: a raw array of u32 vk
//! offsets, sized by the nk "value count" (docs/hive-format.md 3.5). Each vk
//! either stores its data inline (4 bytes or fewer) or points at a plain
//! data cell. Big-data (db) cells for values over 16344 bytes are step 9 and
//! not handled here.
//!
//! These are free functions over the allocator image, given a key's nk
//! offset; `Hive` resolves the path and calls in. Data is opaque to libreg:
//! the caller passes a REG_* type code and raw bytes, and the agent owns the
//! JSON-to-bytes conversion (CONTRACTS value table).

use super::key;
use super::LogicalError;
use crate::alloc::HiveImage;
use crate::format::nk::OFFSET_NONE;
use crate::format::vk::{ValueKey, VALUE_COMP_NAME, VK_INLINE_MAX};

/// Largest value data stored in a single plain data cell. Larger values need
/// a big-data (db) cell, which is step 9.
const MAX_PLAIN_DATA: usize = 16344;

/// Set the value `name` of the key at `key_off` to `data` with type
/// `data_type`, creating it or replacing an existing value of that name.
pub fn set(
    image: &mut HiveImage,
    key_off: u32,
    name: &str,
    data_type: u32,
    data: &[u8],
) -> Result<(), LogicalError> {
    if data.len() > MAX_PLAIN_DATA {
        return Err(LogicalError::Unsupported(
            "value data over 16344 bytes needs a db cell (step 9)",
        ));
    }

    let mut nk = key::read_nk(image, key_off)?;
    let mut offsets = read_value_offsets(image, nk.values_list_offset, nk.value_count)?;

    // Is there already a value of this name?
    let mut existing: Option<(ValueKey, u32)> = None;
    for &vk_off in &offsets {
        let vk = ValueKey::parse(image.content(vk_off))?;
        if name_matches(name, &vk) {
            existing = Some((vk, vk_off));
            break;
        }
    }

    let (flags, name_bytes) = encode_value_name(name);
    let new_vk = build_vk(image, name_bytes, flags, data_type, data);

    match existing {
        Some((old_vk, vk_off)) => {
            // Release the old out-of-line data cell, if any. The name is
            // unchanged, so the vk payload is the same size and rewrites in
            // place; only the data words change.
            if !old_vk.is_inline() && old_vk.data_len() > 0 {
                image.free(old_vk.data_offset);
            }
            write_payload_inplace(image, vk_off, &new_vk.to_payload());
        }
        None => {
            // Allocate the vk and append it to the value list.
            let payload = new_vk.to_payload();
            let vk_off = image.alloc(payload.len());
            write_payload_inplace(image, vk_off, &payload);
            offsets.push(vk_off);

            let old_list = nk.values_list_offset;
            let new_list = write_value_list(image, &offsets);
            if old_list != OFFSET_NONE {
                image.free(old_list);
            }
            nk.values_list_offset = new_list;
            nk.value_count = offsets.len() as u32;
            key::write_nk_inplace(image, key_off, &nk);
        }
    }
    Ok(())
}

/// Get the value `name` of the key at `key_off` as `(type, data)`, or `None`
/// if the key has no such value.
pub fn get(
    image: &HiveImage,
    key_off: u32,
    name: &str,
) -> Result<Option<(u32, Vec<u8>)>, LogicalError> {
    let nk = key::read_nk(image, key_off)?;
    for vk_off in read_value_offsets(image, nk.values_list_offset, nk.value_count)? {
        let vk = ValueKey::parse(image.content(vk_off))?;
        if name_matches(name, &vk) {
            let data = read_data(image, &vk);
            return Ok(Some((vk.data_type, data)));
        }
    }
    Ok(None)
}

/// The names of the key's values, in stored (insertion) order.
pub fn list_names(image: &HiveImage, key_off: u32) -> Result<Vec<String>, LogicalError> {
    let nk = key::read_nk(image, key_off)?;
    let mut out = Vec::new();
    for vk_off in read_value_offsets(image, nk.values_list_offset, nk.value_count)? {
        let vk = ValueKey::parse(image.content(vk_off))?;
        out.push(decode_value_name(&vk));
    }
    Ok(out)
}

/// Build a vk for `data`: inline when it fits in 4 bytes, otherwise a
/// pointer to a freshly allocated data cell.
fn build_vk(
    image: &mut HiveImage,
    name: Vec<u8>,
    flags: u16,
    data_type: u32,
    data: &[u8],
) -> ValueKey {
    if data.len() <= VK_INLINE_MAX {
        ValueKey::new_inline(name, flags, data_type, data)
    } else {
        let data_off = image.alloc(data.len());
        image.content_mut(data_off)[..data.len()].copy_from_slice(data);
        ValueKey::new_pointer(name, flags, data_type, data.len() as u32, data_off)
    }
}

/// Read a value's data, whether inline or in a separate cell.
fn read_data(image: &HiveImage, vk: &ValueKey) -> Vec<u8> {
    if vk.is_inline() {
        vk.inline_data()
    } else {
        let len = vk.data_len() as usize;
        image.content(vk.data_offset)[..len].to_vec()
    }
}

/// Read the value list (array of u32 vk offsets) of a key.
fn read_value_offsets(
    image: &HiveImage,
    list_offset: u32,
    count: u32,
) -> Result<Vec<u32>, LogicalError> {
    if list_offset == OFFSET_NONE || count == 0 {
        return Ok(Vec::new());
    }
    let content = image.content(list_offset);
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let b: [u8; 4] = content[i * 4..i * 4 + 4]
            .try_into()
            .expect("value list slice is 4 bytes");
        out.push(u32::from_le_bytes(b));
    }
    Ok(out)
}

/// Allocate and write a value-list cell holding `offsets`, returning its
/// offset. The value list has no signature; it is a packed u32 array.
fn write_value_list(image: &mut HiveImage, offsets: &[u32]) -> u32 {
    let off = image.alloc(offsets.len() * 4);
    let content = image.content_mut(off);
    for (i, o) in offsets.iter().enumerate() {
        content[i * 4..i * 4 + 4].copy_from_slice(&o.to_le_bytes());
    }
    off
}

fn write_payload_inplace(image: &mut HiveImage, off: u32, payload: &[u8]) {
    image.content_mut(off)[..payload.len()].copy_from_slice(payload);
}

/// Encode a value name: Latin-1 with VALUE_COMP_NAME when every character is
/// at most U+00FF, otherwise UTF-16LE (same threshold as key names). The
/// default value is name "".
fn encode_value_name(name: &str) -> (u16, Vec<u8>) {
    if name.chars().all(|c| (c as u32) <= 0xFF) {
        (VALUE_COMP_NAME, name.chars().map(|c| c as u8).collect())
    } else {
        let mut bytes = Vec::with_capacity(name.len() * 2);
        for unit in name.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        (0, bytes)
    }
}

/// Decode a vk's on-disk name to a string (Latin-1 when compressed, else
/// UTF-16LE). The default value decodes to "".
fn decode_value_name(vk: &ValueKey) -> String {
    if vk.name_is_ascii() {
        vk.name.iter().map(|&b| b as char).collect()
    } else {
        let units: Vec<u16> = vk
            .name
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

/// Case-insensitive match of `name` against a vk's decoded name.
fn name_matches(name: &str, vk: &ValueKey) -> bool {
    key::name_eq(name, &decode_value_name(vk))
}
