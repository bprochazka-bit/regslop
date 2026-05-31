//! Corpus loader. Runs the byte-level structural invariants against real hive
//! files (the offreg-generated fixtures under tests/corpus/synthetic), which
//! validates the harness's regf structural checks against known-good offreg
//! output and finally exercises invariants that were Skipped while no real hive
//! bytes existed in the repo.
//!
//! This does NOT run the load-on-both-agents differential roundtrip. That needs
//! the Linux agent to parse a real regf hive, which the in-memory backend
//! cannot do yet (libreg's regf reader is in progress); the synthetic hives are
//! also offreg-side files, not present on the Linux box. When libreg can read
//! regf, the same `differ::regf` parser backs that roundtrip.

use crate::differ::structural::{self, InvariantResult, Status};
use crate::runner::{AspectOutcome, SeqResult, TestResult};
use std::collections::HashMap;
use std::path::Path;

/// Build one `TestResult` per `*.hiv` file under `dir`, each carrying the
/// byte-level `structural` verdict. Returns an empty vec if the directory is
/// absent (the synthetic corpus is checked in, but a custom dir may not exist).
pub fn run_corpus(dir: &Path) -> Vec<TestResult> {
    let mut results = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return results,
    };
    let mut files: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("hiv"))
        .collect();
    files.sort();
    for path in files {
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let structural = match std::fs::read(&path) {
            Ok(bytes) => fold_structural(&structural::check_bytes(&bytes)),
            Err(e) => AspectOutcome::Fail(format!("cannot read {}: {e}", path.display())),
        };
        results.push(TestResult {
            name: format!("corpus:{fname}"),
            tags: vec!["structural".to_string()],
            problems: Vec::new(),
            semantic: AspectOutcome::Na,
            structural,
            bytewise: AspectOutcome::Na,
            roundtrip: AspectOutcome::Na,
            recovery: AspectOutcome::Na,
            fuzz: AspectOutcome::Na,
            linux: empty_seq(),
            windows: None,
        });
    }
    results
}

fn empty_seq() -> SeqResult {
    SeqResult { op_results: Vec::new(), snapshots: HashMap::new(), roundtrip_dumps: HashMap::new() }
}

/// Fold the per-invariant results into one `structural` outcome: any Fail makes
/// the hive fail; Skipped and Pass do not.
fn fold_structural(results: &[InvariantResult]) -> AspectOutcome {
    let failures: Vec<String> = results
        .iter()
        .filter_map(|r| match &r.status {
            Status::Fail(m) => Some(format!("inv{}: {}", r.id, m)),
            _ => None,
        })
        .collect();
    if failures.is_empty() {
        AspectOutcome::Pass
    } else {
        AspectOutcome::Fail(failures.join(" | "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn synthetic_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../corpus/synthetic")
    }

    #[test]
    fn synthetic_hives_pass_byte_invariants() {
        let dir = synthetic_dir();
        let results = run_corpus(&dir);
        assert!(results.len() >= 4, "expected at least 4 synthetic hives in {}", dir.display());
        for r in &results {
            assert!(
                matches!(r.structural, AspectOutcome::Pass),
                "{} structural = {:?}",
                r.name,
                r.structural
            );
        }
    }

    #[test]
    fn corrupting_a_checksummed_byte_fails_invariant_3() {
        let path = synthetic_dir().join("ref_one_ascii.hiv");
        let mut bytes = std::fs::read(&path).expect("read ref_one_ascii.hiv");
        // Offset 300 is in the base block's reserved region, inside the 0..508
        // checksum span but not a field invariants 1, 2, or 4 read. Flipping it
        // changes the computed checksum so invariant 3 must fail.
        bytes[300] ^= 0xFF;
        let results = structural::check_bytes(&bytes);
        let inv3 = results.iter().find(|r| r.id == 3).unwrap();
        assert!(matches!(inv3.status, Status::Fail(_)), "inv3 = {:?}", inv3.status);
        // The magic and sequence invariants are untouched.
        assert!(matches!(results.iter().find(|r| r.id == 1).unwrap().status, Status::Pass));
        assert!(matches!(results.iter().find(|r| r.id == 2).unwrap().status, Status::Pass));
    }

    #[test]
    fn missing_dir_yields_no_results() {
        let results = run_corpus(&PathBuf::from("/nonexistent/corpus/dir"));
        assert!(results.is_empty());
    }
}
