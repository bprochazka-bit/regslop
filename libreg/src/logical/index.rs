//! Subkey-list management for the logical layer.
//!
//! A key's subkeys are indexed by a list cell pointed to from the nk
//! "subkeys list offset". Enumeration ([`list_entries`]) reads any of the
//! four on-disk forms (lf, lh, li, and an ri index of those leaves) so libreg
//! can load real hives. Insertion ([`insert_subkey`]) only writes `lh`, the
//! form modern hives use (docs/hive-format.md), name-sorted so the order is
//! canonical (invariant 17); reallocating the list cell to fit each entry.

use super::key;
use super::LogicalError;
use crate::alloc::HiveImage;
use crate::format::lf::FastLeaf;
use crate::format::lh::{HashLeaf, HashLeafEntry};
use crate::format::li::IndexLeaf;
use crate::format::nk::{KeyNode, OFFSET_NONE};
use crate::format::ri::IndexRoot;
use crate::format::FormatError;
use core::cmp::Ordering;

/// Maximum entries in a single lh leaf before a two-level ri index root is
/// required. offreg caps a leaf at 507 entries, which is one hbin of cell
/// space: (4096 - 32 header - 8 cell size field) / 8 bytes per entry = 507
/// (tests/corpus/synthetic/ref_ri.hiv splits its leaves at 507, confirming
/// the boundary that issue #34 / CONTRACTS 0.1.7 pin). The 508th subkey
/// promotes the leaf to an ri index of lh leaves, which is step 8; until then
/// we error rather than emit a leaf offreg would reject.
const LH_MAX_ENTRIES: usize = 507;

/// Insert the subkey at `child_off` (named `child_name`) into `parent`'s
/// subkey list, keeping entries name-sorted. Updates `parent`'s
/// `subkeys_list_offset` and `subkey_count` in place; the caller writes the
/// parent nk back. The parent must not already contain a subkey of this
/// name (the caller checks first).
pub fn insert_subkey(
    image: &mut HiveImage,
    parent: &mut KeyNode,
    child_off: u32,
    child_name: &str,
) -> Result<(), LogicalError> {
    let old_off = parent.subkeys_list_offset;
    let mut leaf = if old_off == OFFSET_NONE {
        HashLeaf::default()
    } else {
        HashLeaf::parse(image.content(old_off))?
    };

    if leaf.entries.len() >= LH_MAX_ENTRIES {
        return Err(LogicalError::Unsupported(
            "subkey list exceeds lh capacity; ri promotion is step 8",
        ));
    }

    // Find the sorted insert position by comparing the new name against the
    // existing children's names (the lh stores hashes, not names, so the
    // names come from the referenced nk cells).
    let mut pos = leaf.entries.len();
    for (i, entry) in leaf.entries.iter().enumerate() {
        let other = key::read_nk(image, entry.key_offset)?;
        if key::cmp_name(child_name, &key::key_name_string(&other)) == Ordering::Less {
            pos = i;
            break;
        }
    }
    leaf.entries
        .insert(pos, HashLeafEntry::new(child_off, child_name));

    // Write the grown list to a fresh cell, then release the old one. Doing
    // it in this order keeps the old contents readable until the new cell is
    // fully written.
    let payload = leaf.to_payload();
    let new_off = image.alloc(payload.len());
    image.content_mut(new_off)[..payload.len()].copy_from_slice(&payload);
    if old_off != OFFSET_NONE {
        image.free(old_off);
    }

    parent.subkeys_list_offset = new_off;
    parent.subkey_count = leaf.entries.len() as u32;
    Ok(())
}

/// Read every subkey of `parent` as `(nk offset, decoded name)`, in stored
/// (name-sorted) order. Handles all four list forms (lf/lh/li/ri). Empty when
/// the key has no subkey list.
pub fn list_entries(
    image: &HiveImage,
    parent: &KeyNode,
) -> Result<Vec<(u32, String)>, LogicalError> {
    if parent.subkeys_list_offset == OFFSET_NONE {
        return Ok(Vec::new());
    }
    let offsets = subkey_offsets(image, parent.subkeys_list_offset)?;
    let mut out = Vec::with_capacity(offsets.len());
    for off in offsets {
        let nk = key::read_nk(image, off)?;
        out.push((off, key::key_name_string(&nk)));
    }
    Ok(out)
}

/// Collect the subkey nk offsets reachable from the list cell at
/// `list_offset`, descending one level through an ri index into its leaves.
fn subkey_offsets(image: &HiveImage, list_offset: u32) -> Result<Vec<u32>, LogicalError> {
    let payload = image.content(list_offset);
    if signature_of(payload) == Some(*b"ri") {
        let ri = IndexRoot::parse(payload)?;
        let mut out = Vec::new();
        for leaf_off in ri.leaf_offsets {
            // An ri points only at leaves (lf/lh/li), never another ri.
            out.extend(leaf_offsets(image.content(leaf_off))?);
        }
        Ok(out)
    } else {
        leaf_offsets(payload)
    }
}

/// Subkey nk offsets from a single leaf cell (lf, lh, or li).
fn leaf_offsets(payload: &[u8]) -> Result<Vec<u32>, LogicalError> {
    match signature_of(payload) {
        Some(s) if s == *b"lh" => Ok(HashLeaf::parse(payload)?
            .entries
            .iter()
            .map(|e| e.key_offset)
            .collect()),
        Some(s) if s == *b"lf" => Ok(FastLeaf::parse(payload)?
            .entries
            .iter()
            .map(|e| e.key_offset)
            .collect()),
        Some(s) if s == *b"li" => Ok(IndexLeaf::parse(payload)?.offsets),
        found => Err(LogicalError::Format(FormatError::BadSignature {
            structure: "subkey leaf",
            found: found.map_or([0, 0, 0, 0], |s| [s[0], s[1], 0, 0]),
        })),
    }
}

fn signature_of(payload: &[u8]) -> Option<[u8; 2]> {
    payload.get(0..2).map(|s| [s[0], s[1]])
}
