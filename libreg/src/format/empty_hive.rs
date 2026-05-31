//! Build a minimal, valid, empty hive in memory (implementation step 3).
//!
//! The result is a complete hive file: a 4096-byte base block followed by
//! a single 4096-byte hive bin holding the root key node, one security
//! cell, and a trailing free cell. Layout within the hive bins data:
//!
//! ```text
//!   0x000  hbin header (32 bytes), declared offset 0, size 4096
//!   0x020  root nk cell  (KEY_COMP_NAME; offreg saves the root with no
//!                         KEY_HIVE_ENTRY/KEY_NO_DELETE, see nk::new_root)
//!   0x078  sk cell       (lone ring, refcount 1, default descriptor)
//!   ...    one free cell filling the rest of the bin
//! ```
//!
//! This is a Layer 0 helper: it emits bytes by composing format structs
//! at fixed offsets, with no allocation policy. Once the allocator
//! (Layer 1) and logical layer exist, hive creation moves up and this
//! becomes a reference/bootstrap.
//!
//! NOTE: the offreg reference hives in tests/corpus/synthetic now confirm
//! the choices here: root key name "ROOT", format version 1.5, and the root
//! security descriptor (byte-identical to the ratified default key
//! descriptor). The empty-hive layout (root nk at 0x20, sk at 0x78, free at
//! 0x120) matches ref_one_ascii.hiv exactly. See libreg/STATE.md.

use super::base_block::{BaseBlock, BASE_BLOCK_SIZE};
use super::cell::{cell_size_for, encode_cell};
use super::hbin::{HBIN_ALIGN, HBIN_HEADER_SIZE, HBIN_SIGNATURE};
use super::nk::KeyNode;
use super::security_descriptor::default_key_security_descriptor_bytes;
use super::sk::SecurityCell;

/// Options for [`build_empty_hive`].
pub struct EmptyHiveOptions {
    /// Root key name (ASCII; stored with KEY_COMP_NAME).
    pub root_name: String,
    /// Last-written FILETIME stamped into the base block and root key.
    pub last_written: u64,
    /// Self-relative security descriptor for the root key.
    pub security_descriptor: Vec<u8>,
}

impl Default for EmptyHiveOptions {
    fn default() -> Self {
        EmptyHiveOptions {
            root_name: "ROOT".to_string(),
            // A fixed, deterministic stamp keeps creation reproducible
            // (Hard Rule 5). Callers that want "now" pass it explicitly.
            // 0x01dc... is an arbitrary valid FILETIME in the 2020s.
            last_written: 0x01dc_0000_0000_0000,
            // offreg gives a freshly created hive's root the same descriptor
            // it gives every created key (the ratified default, issue #11):
            // confirmed byte-identical against the offreg reference hives in
            // tests/corpus/synthetic (ref_one_ascii.hiv root sk). This
            // replaces the earlier NULL-DACL placeholder; spec question 2
            // (root SD) is thereby answered.
            security_descriptor: default_key_security_descriptor_bytes(),
        }
    }
}

/// Build a complete empty hive and return its bytes.
///
/// The hive bins data is a single 4096-byte bin, so the total file is
/// 8192 bytes. Layout is computed from the actual cell sizes rather than
/// hard-coded, so changing the root name or descriptor stays correct.
pub fn build_empty_hive(opts: &EmptyHiveOptions) -> Vec<u8> {
    // Offsets are relative to the start of the hive bins data.
    let root_offset = HBIN_HEADER_SIZE as u32; // 0x20

    let root_payload_len = super::nk::NK_HEADER_SIZE + opts.root_name.len();
    let root_cell_size = cell_size_for(root_payload_len) as u32;
    let sk_offset = root_offset + root_cell_size;

    // Root key references the sk cell that immediately follows it.
    let root = KeyNode::new_root(&opts.root_name, sk_offset, opts.last_written);
    let sk = SecurityCell::lone(sk_offset, 1, opts.security_descriptor.clone());

    let root_cell = encode_cell(&root.to_payload(), true);
    let sk_cell = encode_cell(&sk.to_payload(), true);

    let used = HBIN_HEADER_SIZE + root_cell.len() + sk_cell.len();
    let bin_size = HBIN_ALIGN as usize; // one 4096-byte bin
    assert!(
        used <= bin_size,
        "empty hive cells ({used} bytes) exceed one bin ({bin_size})"
    );

    // Trailing free cell fills the remainder of the bin.
    let free_total = bin_size - used;
    let free_cell = encode_cell(&vec![0u8; free_total - 4], false);
    debug_assert_eq!(free_cell.len(), free_total);

    // Assemble the hive bins data: one bin.
    let mut bins = Vec::with_capacity(bin_size);
    bins.extend_from_slice(&HBIN_SIGNATURE);
    bins.extend_from_slice(&0u32.to_le_bytes()); // declared offset 0
    bins.extend_from_slice(&(bin_size as u32).to_le_bytes()); // size
    bins.extend_from_slice(&[0u8; HBIN_HEADER_SIZE - 12]); // reserved/timestamp/spare
    bins.extend_from_slice(&root_cell);
    bins.extend_from_slice(&sk_cell);
    bins.extend_from_slice(&free_cell);
    debug_assert_eq!(bins.len(), bin_size);

    // Base block points at the root cell and covers the bins data.
    let bb = BaseBlock::create(root_offset, bin_size as u32, opts.last_written);

    let mut file = Vec::with_capacity(BASE_BLOCK_SIZE + bin_size);
    file.extend_from_slice(&bb.to_bytes());
    file.extend_from_slice(&bins);
    file
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::base_block::BaseBlock;
    use crate::format::cell::Cell;
    use crate::format::hbin::{walk, HiveBins};
    use crate::format::nk::{KeyNode, KEY_COMP_NAME};
    use crate::format::sk::SecurityCell;

    fn build() -> Vec<u8> {
        build_empty_hive(&EmptyHiveOptions::default())
    }

    #[test]
    fn base_block_is_valid() {
        let file = build();
        assert_eq!(file.len(), BASE_BLOCK_SIZE + HBIN_ALIGN as usize);
        let bb = BaseBlock::parse(&file).expect("parse base block");
        assert!(bb.checksum_valid(), "checksum must validate");
        assert!(bb.is_clean(), "fresh hive is clean");
        assert_eq!(bb.root_cell_offset, HBIN_HEADER_SIZE as u32);
        assert_eq!(bb.hbins_size, HBIN_ALIGN);
    }

    #[test]
    fn cell_walk_succeeds() {
        let file = build();
        let bb = BaseBlock::parse(&file).expect("base block");
        let data = &file[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + bb.hbins_size as usize];
        let stats = walk(data).expect("walk");
        assert_eq!(stats.hbin_count, 1);
        // root nk, sk, and one trailing free cell.
        assert_eq!(stats.allocated_cells, 2);
        assert_eq!(stats.free_cells, 1);
    }

    #[test]
    fn root_key_is_well_formed() {
        let file = build();
        let bb = BaseBlock::parse(&file).expect("base block");
        let data = &file[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + bb.hbins_size as usize];

        // Frame the root cell at the offset the base block advertises.
        let root_cell = Cell::parse_at(data, bb.root_cell_offset as usize).expect("root cell");
        assert!(root_cell.allocated);
        let root = KeyNode::parse(root_cell.data).expect("root nk");
        // offreg saves a standalone root with KEY_COMP_NAME only.
        assert_eq!(root.flags, KEY_COMP_NAME);
        assert_eq!(root.name, b"ROOT");
        assert_eq!(root.subkey_count, 0);
        assert_eq!(root.value_count, 0);

        // The security offset must point at a valid, lone sk cell with
        // refcount 1 (invariants 13 and 14).
        let sk_cell = Cell::parse_at(data, root.security_offset as usize).expect("sk cell");
        let sk = SecurityCell::parse(sk_cell.data).expect("sk");
        assert_eq!(sk.refcount, 1);
        assert_eq!(sk.flink, root.security_offset, "lone ring points to self");
        assert_eq!(sk.blink, root.security_offset);
    }

    #[test]
    fn deterministic() {
        // Hard Rule 5: same inputs produce identical bytes.
        assert_eq!(build(), build());
    }

    #[test]
    fn base_block_round_trips() {
        let file = build();
        let bb = BaseBlock::parse(&file).expect("parse");
        assert_eq!(&bb.to_bytes()[..], &file[..BASE_BLOCK_SIZE]);
    }

    #[test]
    fn the_single_hbin_declares_offset_zero() {
        let file = build();
        let bb = BaseBlock::parse(&file).expect("base block");
        let data = &file[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + bb.hbins_size as usize];
        let hbin = HiveBins::new(data).hbins().next().unwrap().unwrap();
        assert_eq!(hbin.declared_offset, 0);
        assert_eq!(hbin.size, HBIN_ALIGN);
    }
}
