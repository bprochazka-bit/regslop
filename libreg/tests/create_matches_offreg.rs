//! Compare libreg's create path to the offreg reference hives in
//! tests/corpus/synthetic. These hives were produced by real offreg.dll
//! (see their PROVENANCE.md), so matching them is the offline half of
//! "match offreg, not the docs" (libreg/CLAUDE.md Hard Rule 4). We compare
//! the logical form (subkey sets and per-key security), not raw bytes:
//! offreg's exact cell placement is a separate bytewise concern.
//!
//! Each test SKIPs (passes with a note) if the fixture is absent.

use libreg::logical::Hive;
use std::path::PathBuf;

fn corpus(name: &str) -> Option<Vec<u8>> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../tests/corpus/synthetic");
    p.push(name);
    std::fs::read(p).ok()
}

/// Assert every key in `reference` (root plus each subkey) has the same
/// security descriptor in `mine`.
fn assert_same_security(mine: &Hive, reference: &Hive, keys: &[&str]) {
    for &k in keys {
        assert_eq!(
            mine.key_security(k).unwrap(),
            reference.key_security(k).unwrap(),
            "security descriptor for key {k:?}",
        );
    }
}

#[test]
fn one_ascii_subkey_matches_offreg() {
    let Some(bytes) = corpus("ref_one_ascii.hiv") else {
        eprintln!("SKIP: ref_one_ascii.hiv absent");
        return;
    };
    let reference = Hive::from_file_bytes(&bytes).expect("load reference");

    let mut mine = Hive::new_empty();
    mine.create_key("Test").unwrap();

    assert_eq!(mine.subkeys("").unwrap(), vec!["Test"]);
    assert_eq!(mine.subkeys("").unwrap(), reference.subkeys("").unwrap());
    // Root and child carry offreg's descriptor, and the child shares it.
    assert_same_security(&mine, &reference, &["", "Test"]);
    assert_eq!(
        mine.key_security("Test").unwrap(),
        mine.key_security("").unwrap(),
        "child shares the root descriptor",
    );
}

#[test]
fn six_ascii_subkeys_match_offreg() {
    let Some(bytes) = corpus("ref_multi.hiv") else {
        eprintln!("SKIP: ref_multi.hiv absent");
        return;
    };
    let reference = Hive::from_file_bytes(&bytes).expect("load reference");

    let mut mine = Hive::new_empty();
    for name in ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot"] {
        mine.create_key(name).unwrap();
    }

    let subkeys = reference.subkeys("").unwrap();
    assert_eq!(mine.subkeys("").unwrap(), subkeys);
    let mut keys = vec![""];
    keys.extend(subkeys.iter().map(String::as_str));
    assert_same_security(&mine, &reference, &keys);
}

#[test]
fn latin1_name_matches_offreg() {
    let Some(bytes) = corpus("ref_latin1.hiv") else {
        eprintln!("SKIP: ref_latin1.hiv absent");
        return;
    };
    let reference = Hive::from_file_bytes(&bytes).expect("load reference");

    let mut mine = Hive::new_empty();
    // "Café" with e-acute U+00E9: must be stored compressed (Latin-1), the
    // same KEY_COMP_NAME choice offreg makes for chars <= U+00FF.
    mine.create_key("Caf\u{00e9}").unwrap();

    assert_eq!(mine.subkeys("").unwrap(), vec!["Caf\u{00e9}"]);
    assert_eq!(mine.subkeys("").unwrap(), reference.subkeys("").unwrap());
}

#[test]
fn wide_name_matches_offreg() {
    let Some(bytes) = corpus("ref_wide.hiv") else {
        eprintln!("SKIP: ref_wide.hiv absent");
        return;
    };
    let reference = Hive::from_file_bytes(&bytes).expect("load reference");

    let mut mine = Hive::new_empty();
    // Greek capital Omega (U+03A9) > U+00FF, so the name is stored as
    // uncompressed UTF-16LE.
    mine.create_key("\u{03a9}mega").unwrap();

    assert_eq!(mine.subkeys("").unwrap(), vec!["\u{03a9}mega"]);
    assert_eq!(mine.subkeys("").unwrap(), reference.subkeys("").unwrap());
}
