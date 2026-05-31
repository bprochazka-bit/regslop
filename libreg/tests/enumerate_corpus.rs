//! Enumerate subkeys from the offreg reference hives, exercising the read
//! path for every subkey-list form. ref_ri.hiv in particular holds 1100
//! subkeys as an `ri` index of three `lh` leaves, so loading it proves the
//! ri + leaf dispatch in `logical::index`. SKIPs if a fixture is absent.

use libreg::logical::Hive;
use std::path::PathBuf;

fn corpus(name: &str) -> Option<Vec<u8>> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../tests/corpus/synthetic");
    p.push(name);
    std::fs::read(p).ok()
}

#[test]
fn reads_ri_indexed_wide_key() {
    let Some(bytes) = corpus("ref_ri.hiv") else {
        eprintln!("SKIP: ref_ri.hiv absent");
        return;
    };
    let hive = Hive::from_file_bytes(&bytes).expect("load ref_ri.hiv");

    let names = hive.subkeys("").expect("enumerate root subkeys");
    assert_eq!(names.len(), 1100, "ri of lh leaves [507, 507, 86]");

    // offreg names them k00000..k01099; zero padding makes lexical order
    // numeric, and the enumeration must come back in that sorted order.
    let expected: Vec<String> = (0..1100).map(|i| format!("k{i:05}")).collect();
    assert_eq!(names, expected);

    // Spot-check resolution across all three leaves and the boundaries.
    for probe in ["k00000", "k00506", "k00507", "k01013", "k01014", "k01099"] {
        assert!(hive.resolve(probe).unwrap().is_some(), "resolve {probe}");
    }
    assert!(hive.resolve("k01100").unwrap().is_none(), "no k01100");
}

#[test]
fn reads_lh_leaf_hives() {
    // The single-leaf lh hives load through the same path (no ri).
    for (file, count) in [("ref_one_ascii.hiv", 1usize), ("ref_multi.hiv", 6)] {
        let Some(bytes) = corpus(file) else {
            eprintln!("SKIP: {file} absent");
            continue;
        };
        let hive = Hive::from_file_bytes(&bytes).expect("load");
        assert_eq!(hive.subkeys("").unwrap().len(), count, "{file}");
    }
}
