//! Step 2 corpus test: walk the hive bin chain of each reference hive,
//! enumerate every cell, and check the structural invariants.
//!
//! The implementation order asks for "count matches offreg dump". That
//! cross-check belongs to the differential harness (it has offreg on the
//! Windows side); here we do the half we can do offline:
//!
//! - the bin chain tiles exactly `base_block.hbins_size` bytes,
//! - every bin has the `hbin` magic and a 4096-multiple size,
//! - cells tile each bin and none crosses a boundary,
//! - the cell count is recorded, and compared against a checked-in
//!   expectation file (`<hive>.cellcount`) when one exists.
//!
//! Absent a corpus the test passes with a SKIP note (or fails when
//! `LIBREG_REQUIRE_CORPUS=1`).

use std::fs;
use std::path::{Path, PathBuf};

use libreg::format::base_block::{BaseBlock, BASE_BLOCK_SIZE};
use libreg::format::hbin::walk;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("corpus")
}

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
fn cell_walk_for_corpus_hives() {
    let dir = corpus_dir();
    let hives = collect_hives(&dir);

    if hives.is_empty() {
        let require = std::env::var("LIBREG_REQUIRE_CORPUS").is_ok();
        let msg = format!(
            "no corpus hives found in {}; download the reference corpus to \
             exercise the step 2 cell walk",
            dir.display()
        );
        assert!(!require, "{msg}");
        eprintln!("SKIP: {msg}");
        return;
    }

    for hive in &hives {
        let bytes = fs::read(hive).expect("read corpus hive");
        assert!(bytes.len() >= BASE_BLOCK_SIZE, "{} too short", hive.display());

        let bb = BaseBlock::parse(&bytes).expect("parse base block");
        let hbins_size = bb.hbins_size as usize;
        assert!(
            BASE_BLOCK_SIZE + hbins_size <= bytes.len(),
            "{}: base block claims {hbins_size} bytes of hive bins data but \
             the file only has {} after the base block",
            hive.display(),
            bytes.len() - BASE_BLOCK_SIZE
        );

        let data = &bytes[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + hbins_size];
        let stats = walk(data).unwrap_or_else(|e| {
            panic!("{}: hbin walk failed: {e}", hive.display());
        });

        // The bins must tile exactly the hive bins data (no slack, no
        // overrun): walk() already advances bin by bin, so reaching the
        // end without error means the chain covered `data`.
        eprintln!(
            "{}: {} hbins, {} cells ({} allocated, {} free), {} cell bytes",
            hive.file_name().unwrap().to_string_lossy(),
            stats.hbin_count,
            stats.total_cells(),
            stats.allocated_cells,
            stats.free_cells,
            stats.total_cell_bytes,
        );

        // Optional cross-check: a sibling `<hive>.cellcount` file holding
        // the expected total cell count (e.g. produced from an offreg dump)
        // lets the count assertion run offline once recorded.
        let expect_path = hive.with_extension("cellcount");
        if let Ok(text) = fs::read_to_string(&expect_path) {
            let expected: usize = text
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("{}: not an integer", expect_path.display()));
            assert_eq!(
                stats.total_cells(),
                expected,
                "{}: cell count {} != expected {expected}",
                hive.display(),
                stats.total_cells()
            );
        }
    }

    eprintln!("walked {} corpus hive(s)", hives.len());
}
