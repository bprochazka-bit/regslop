//! Key (nk) helpers for the logical layer.
//!
//! These read and write nk cells through the allocator image and handle the
//! name encoding policy (ASCII/Latin-1 with KEY_COMP_NAME when the name is
//! ASCII, UTF-16LE otherwise). The format layer stays policy-free; the
//! choice of encoding and the case-insensitive ordering live here.

use crate::alloc::HiveImage;
use crate::format::nk::{KeyNode, KEY_COMP_NAME, OFFSET_NONE};
use crate::format::FormatError;
use core::cmp::Ordering;

/// Parse the nk cell at `off`.
pub fn read_nk(image: &HiveImage, off: u32) -> Result<KeyNode, FormatError> {
    KeyNode::parse(image.content(off))
}

/// Rewrite the nk at `off` in place. The cell must already be large enough,
/// which holds when only fixed fields change (the payload length is the
/// same), as on the create path where the name never changes after alloc.
pub fn write_nk_inplace(image: &mut HiveImage, off: u32, nk: &KeyNode) {
    let payload = nk.to_payload();
    image.content_mut(off)[..payload.len()].copy_from_slice(&payload);
}

/// Build a non-root child key node: empty links, no values or subkeys, the
/// given parent and security offsets, and a name encoded per [`encode_name`].
pub fn build_child_nk(name: &str, parent: u32, security_offset: u32, last_written: u64) -> KeyNode {
    let (flags, name_bytes) = encode_name(name);
    KeyNode {
        flags,
        last_written,
        access_bits: 0,
        parent,
        subkey_count: 0,
        volatile_subkey_count: 0,
        subkeys_list_offset: OFFSET_NONE,
        volatile_subkeys_list_offset: OFFSET_NONE,
        value_count: 0,
        values_list_offset: OFFSET_NONE,
        security_offset,
        class_name_offset: OFFSET_NONE,
        largest_subkey_name_len: 0,
        largest_subkey_class_len: 0,
        largest_value_name_len: 0,
        largest_value_data_len: 0,
        work_var: 0,
        class_name_len: 0,
        name: name_bytes,
    }
}

/// Encode a key name: ASCII (Latin-1) with KEY_COMP_NAME set when every
/// character is ASCII, otherwise UTF-16LE with the flag clear. Returns the
/// flag contribution and the on-disk name bytes.
fn encode_name(name: &str) -> (u16, Vec<u8>) {
    if name.is_ascii() {
        (KEY_COMP_NAME, name.as_bytes().to_vec())
    } else {
        let mut bytes = Vec::with_capacity(name.len() * 2);
        for unit in name.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        (0, bytes)
    }
}

/// Decode an nk's on-disk name to a Rust string. Compressed names are
/// Latin-1 (one code point per byte); otherwise UTF-16LE.
pub fn key_name_string(nk: &KeyNode) -> String {
    if nk.name_is_ascii() {
        nk.name.iter().map(|&b| b as char).collect()
    } else {
        let units: Vec<u16> = nk
            .name
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

/// Case-insensitive name ordering, the order subkey lists are kept in
/// (invariant 17). ASCII upcasing only; non-ASCII collation matching the
/// kernel is a future refinement (the lh hash carries the same caveat).
pub fn cmp_name(a: &str, b: &str) -> Ordering {
    a.to_ascii_uppercase().cmp(&b.to_ascii_uppercase())
}

/// Case-insensitive name equality (Windows key-name semantics, ASCII).
pub fn name_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
