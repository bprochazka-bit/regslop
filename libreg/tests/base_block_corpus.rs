//! Step 1 corpus test: load each reference hive, parse its base block,
//! serialize it back, and assert the leading 4096 bytes are byte-equal.
//!
//! The corpus lives in `tests/corpus/` at the repo root and is gitignored
//! (downloaded separately). When it is absent this test reports how to
//! fetch it and passes, so a fresh checkout is not red for a missing
//! download. Set `LIBREG_REQUIRE_CORPUS=1` in CI to make absence fail.

use std::fs;
use std::path::{Path, PathBuf};

use libreg::format::base_block::{BaseBlock, BASE_BLOCK_SIZE};

/// Locate `tests/corpus` relative to this crate (`libreg/`), i.e. one
/// directory up at the repository root.
fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("corpus")
}

/// Collect candidate hive files. Reference hives use a variety of names
/// (`*.hiv`, `NTUSER.DAT`, `SOFTWARE`, ...), so we accept any regular file
/// whose first four bytes are the `regf` magic.
fn collect_hives(dir: &Path) -> Vec<PathBuf> {
    let mut hives = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return hives;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            if bytes.len() >= 4 && &bytes[0..4] == b"regf" {
                hives.push(path);
            }
        }
    }
    hives.sort();
    hives
}

#[test]
fn base_block_round_trips_for_corpus_hives() {
    let dir = corpus_dir();
    let hives = collect_hives(&dir);

    if hives.is_empty() {
        let require = std::env::var("LIBREG_REQUIRE_CORPUS").is_ok();
        let msg = format!(
            "no corpus hives found in {}; download the reference corpus to \
             exercise step 1's byte-equal round trip",
            dir.display()
        );
        assert!(!require, "{msg}");
        eprintln!("SKIP: {msg}");
        return;
    }

    for hive in &hives {
        let bytes = fs::read(hive).expect("read corpus hive");
        assert!(
            bytes.len() >= BASE_BLOCK_SIZE,
            "{} is shorter than a base block",
            hive.display()
        );

        let bb = BaseBlock::parse(&bytes).unwrap_or_else(|e| {
            panic!("parse base block of {}: {e}", hive.display());
        });
        let out = bb.to_bytes();
        assert_eq!(
            &bytes[..BASE_BLOCK_SIZE],
            &out[..],
            "base block of {} did not round trip byte-for-byte",
            hive.display()
        );

        // A clean reference hive should carry a valid checksum.
        assert!(
            bb.checksum_valid(),
            "{} has a base block checksum that does not validate",
            hive.display()
        );
    }

    eprintln!("checked {} corpus hive(s)", hives.len());
}
