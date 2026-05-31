//! Step 8: creating more than 507 subkeys under one key promotes its list
//! from a single lh leaf to an ri index of lh leaves. Verified structurally
//! (leaf partition) and against the offreg reference ref_ri.hiv.

use libreg::format::base_block::{BaseBlock, BASE_BLOCK_SIZE};
use libreg::format::cell::Cell;
use libreg::format::hbin::walk;
use libreg::format::lh::HashLeaf;
use libreg::format::nk::KeyNode;
use libreg::format::ri::IndexRoot;
use libreg::logical::Hive;
use std::path::PathBuf;

fn corpus(name: &str) -> Option<Vec<u8>> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../tests/corpus/synthetic");
    p.push(name);
    std::fs::read(p).ok()
}

/// Entry counts of the root's subkey-list leaves: a single element when the
/// list is one lh leaf, or one per leaf when it is an ri index.
fn root_leaf_sizes(file: &[u8]) -> Vec<usize> {
    let bb = BaseBlock::parse(file).expect("base block");
    let bins = &file[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + bb.hbins_size as usize];
    let root_payload = Cell::parse_at(bins, bb.root_cell_offset as usize)
        .expect("root cell")
        .data;
    let root = KeyNode::parse(root_payload).expect("root nk");
    let list = Cell::parse_at(bins, root.subkeys_list_offset as usize)
        .expect("list cell")
        .data;
    if &list[0..2] == b"ri" {
        IndexRoot::parse(list)
            .expect("ri")
            .leaf_offsets
            .iter()
            .map(|&off| {
                let lp = Cell::parse_at(bins, off as usize).expect("leaf cell").data;
                HashLeaf::parse(lp).expect("lh leaf").entries.len()
            })
            .collect()
    } else {
        vec![HashLeaf::parse(list).expect("lh leaf").entries.len()]
    }
}

fn hive_with_keys(n: usize) -> Hive {
    let mut hive = Hive::new_empty();
    for i in 0..n {
        hive.create_key(&format!("k{i:05}")).expect("create");
    }
    hive
}

#[test]
fn stays_one_lh_leaf_at_507() {
    let hive = hive_with_keys(507);
    assert_eq!(root_leaf_sizes(&hive.to_file()), vec![507]);
}

#[test]
fn promotes_to_ri_at_508() {
    let hive = hive_with_keys(508);
    // Sorted append fills the first leaf to 507, the overflow starts a second.
    assert_eq!(root_leaf_sizes(&hive.to_file()), vec![507, 1]);
    assert_eq!(hive.subkeys("").unwrap().len(), 508);
}

#[test]
fn wide_key_matches_ref_ri() {
    let hive = hive_with_keys(1100);
    let file = hive.to_file();

    // Same leaf partition offreg produced for 1100 sorted keys.
    assert_eq!(root_leaf_sizes(&file), vec![507, 507, 86]);

    // The hive validates and reloads with all keys, sorted.
    let bb = BaseBlock::parse(&file).unwrap();
    walk(&file[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + bb.hbins_size as usize]).expect("walk");
    let reloaded = Hive::from_file_bytes(&file).unwrap();
    let expected: Vec<String> = (0..1100).map(|i| format!("k{i:05}")).collect();
    assert_eq!(reloaded.subkeys("").unwrap(), expected);

    // Same logical content as the offreg reference.
    if let Some(ref_bytes) = corpus("ref_ri.hiv") {
        let reference = Hive::from_file_bytes(&ref_bytes).unwrap();
        assert_eq!(hive.subkeys("").unwrap(), reference.subkeys("").unwrap());
    } else {
        eprintln!("SKIP: ref_ri.hiv absent (structural checks above still ran)");
    }
}

#[test]
fn promotion_is_deterministic() {
    assert_eq!(hive_with_keys(600).to_file(), hive_with_keys(600).to_file());
}
