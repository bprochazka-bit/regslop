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

/// Maximum entries in a single lh leaf. offreg caps a leaf at 507 entries,
/// which is one hbin of cell space: (4096 - 32 header - 8 cell size field) / 8
/// bytes per entry = 507 (tests/corpus/synthetic/ref_ri.hiv splits its leaves
/// at 507, the boundary issue #34 / CONTRACTS 0.1.7 pin). Beyond 507 the list
/// is promoted to an `ri` index of lh leaves.
const LH_LEAF_MAX: usize = 507;

/// Insert the subkey at `child_off` (named `child_name`) into `parent`'s
/// subkey list, keeping it name-sorted (invariant 17) and promoting to an
/// `ri` index of lh leaves once it would exceed [`LH_LEAF_MAX`]. Updates
/// `parent`'s `subkeys_list_offset` and `subkey_count` in place; the caller
/// writes the parent nk back. The parent must not already contain a subkey of
/// this name (the caller checks first).
///
/// The index is rebuilt from the full, freshly sorted entry set on each
/// insert. This is simpler than incremental leaf splitting and, for keys added
/// in sorted order, partitions the leaves exactly as offreg does (sequential
/// fill, each leaf capped at 507; ref_ri.hiv's [507, 507, 86]). It is O(n) per
/// insert; a future optimization could split incrementally. Allocation order
/// is fixed (leaves in order, then the ri), so the output stays deterministic
/// (Hard Rule 5).
pub fn insert_subkey(
    image: &mut HiveImage,
    parent: &mut KeyNode,
    child_off: u32,
    child_name: &str,
) -> Result<(), LogicalError> {
    // Gather the existing children plus the new one, sorted by name. The
    // names come from the referenced nk cells (the leaves store hashes).
    let mut entries = list_entries(image, parent)?;
    entries.push((child_off, child_name.to_string()));
    entries.sort_by(|a, b| key::cmp_name(&a.1, &b.1));

    // Release the old list structure (an lh leaf, or an ri and its leaves)
    // before laying out the new one in the reclaimed space.
    if parent.subkeys_list_offset != OFFSET_NONE {
        free_subkey_list(image, parent.subkeys_list_offset)?;
    }

    parent.subkeys_list_offset = write_subkey_index(image, &entries);
    parent.subkey_count = entries.len() as u32;
    Ok(())
}

/// Write the subkey index for `entries` (already name-sorted) and return its
/// offset: a single lh leaf when it fits, otherwise an ri of lh leaves each
/// holding at most [`LH_LEAF_MAX`] entries in order.
fn write_subkey_index(image: &mut HiveImage, entries: &[(u32, String)]) -> u32 {
    if entries.len() <= LH_LEAF_MAX {
        return write_lh_leaf(image, entries);
    }
    let leaf_offsets = entries
        .chunks(LH_LEAF_MAX)
        .map(|chunk| write_lh_leaf(image, chunk))
        .collect();
    let payload = IndexRoot { leaf_offsets }.to_payload();
    let off = image.alloc(payload.len());
    image.content_mut(off)[..payload.len()].copy_from_slice(&payload);
    off
}

/// Allocate and write one lh leaf holding `entries`, returning its offset.
fn write_lh_leaf(image: &mut HiveImage, entries: &[(u32, String)]) -> u32 {
    let leaf = HashLeaf {
        entries: entries
            .iter()
            .map(|(off, name)| HashLeafEntry::new(*off, name))
            .collect(),
    };
    let payload = leaf.to_payload();
    let off = image.alloc(payload.len());
    image.content_mut(off)[..payload.len()].copy_from_slice(&payload);
    off
}

/// Remove the subkey at `child_off` from `parent`'s list, rebuilding the
/// index without it (and demoting an ri back to a single lh, or to no list at
/// all, as the count drops). Updates `parent`'s `subkeys_list_offset` and
/// `subkey_count` in place; the caller writes the parent nk back and frees the
/// child's own cells. `child_off`'s nk must still be valid (it is read for its
/// name during the rebuild), so detach before freeing the child.
pub(super) fn remove_subkey(
    image: &mut HiveImage,
    parent: &mut KeyNode,
    child_off: u32,
) -> Result<(), LogicalError> {
    let entries: Vec<(u32, String)> = list_entries(image, parent)?
        .into_iter()
        .filter(|(off, _)| *off != child_off)
        .collect();

    if parent.subkeys_list_offset != OFFSET_NONE {
        free_subkey_list(image, parent.subkeys_list_offset)?;
    }
    parent.subkeys_list_offset = if entries.is_empty() {
        OFFSET_NONE
    } else {
        write_subkey_index(image, &entries)
    };
    parent.subkey_count = entries.len() as u32;
    Ok(())
}

/// Free a subkey list cell and, if it is an ri index, its leaf cells too.
pub(super) fn free_subkey_list(
    image: &mut HiveImage,
    list_offset: u32,
) -> Result<(), LogicalError> {
    let payload = image.try_content(list_offset)?;
    if signature_of(payload) == Some(*b"ri") {
        let ri = IndexRoot::parse(payload)?;
        for leaf_off in ri.leaf_offsets {
            image.free(leaf_off);
        }
    }
    image.free(list_offset);
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
    let payload = image.try_content(list_offset)?;
    if signature_of(payload) == Some(*b"ri") {
        let ri = IndexRoot::parse(payload)?;
        let mut out = Vec::new();
        for leaf_off in ri.leaf_offsets {
            // An ri points only at leaves (lf/lh/li), never another ri.
            out.extend(leaf_offsets(image.try_content(leaf_off)?)?);
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
