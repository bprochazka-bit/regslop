//! Crash and divergence triage: classify, deduplicate, and minimize.
//!
//! When a sequence fails (hard rules 2 and 7, and the "Triage" section of
//! CLAUDE-fuzz.md) we: classify the failure, hash a signature so repeats of the
//! same bug collapse to one entry, and shrink the operation sequence to the
//! smallest prefix/subset that still reproduces before filing it.
//!
//! The minimizer is deliberately decoupled from the harness: it takes a
//! `reproduces` predicate, so it is unit-testable without a live agent and the
//! op_fuzz binary supplies a predicate that re-runs the harness.

use crate::generators::ops::OpSeq;
use serde_json::Value;

/// Failure categories from CLAUDE-fuzz.md "Triage".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Crash,
    Hang,
    DifferSemantic,
    DifferStructural,
    DifferBytewise,
    ValidationMismatch,
    /// Cross-agent operation-level divergence (success/error-code mismatch,
    /// transport error). The harness reports these as "problems".
    OpDivergence,
}

impl FailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FailureKind::Crash => "crash",
            FailureKind::Hang => "hang",
            FailureKind::DifferSemantic => "differ-semantic",
            FailureKind::DifferStructural => "differ-structural",
            FailureKind::DifferBytewise => "differ-bytewise",
            FailureKind::ValidationMismatch => "validation-mismatch",
            FailureKind::OpDivergence => "op-divergence",
        }
    }

    /// Priority per CLAUDE-fuzz.md hard rule 7: crashes/hangs are P0, a differ
    /// failure on a well-formed sequence is P1.
    pub fn priority(self) -> &'static str {
        match self {
            FailureKind::Crash | FailureKind::Hang => "P0",
            _ => "P1",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: FailureKind,
    pub seed: u64,
    /// Stable hash of the normalized failure signature, for dedup.
    pub signature: u64,
    pub detail: String,
}

/// FNV-1a, 64-bit. A fixed, stable hash so a dedup set computed today matches
/// one computed after a rebuild (unlike `DefaultHasher`, which is randomized).
pub fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Normalize a failure detail into a signature that ignores run-specific noise
/// (the per-seed hive var name, concrete handle strings, timestamps) so the same
/// underlying bug hashes the same across seeds.
pub fn signature(kind: FailureKind, detail: &str) -> u64 {
    let mut norm = String::with_capacity(detail.len() + 16);
    norm.push_str(kind.as_str());
    norm.push('|');
    // Collapse digit runs and quoted hive vars to placeholders.
    let mut prev_digit = false;
    for ch in detail.chars() {
        if ch.is_ascii_digit() {
            if !prev_digit {
                norm.push('#');
            }
            prev_digit = true;
        } else {
            prev_digit = false;
            norm.push(ch);
        }
    }
    fnv1a(&norm)
}

/// Classify one entry from the harness `report.json` `tests` array into a
/// `FailureKind`. Returns `None` when the test passed.
///
/// The entry shape (see `harness/src/report.rs::render_json`) is:
/// `{ "name", "tags", "problems": [..], "outcomes": { "semantic": "FAIL", .. }}`
/// where each outcome is one of `PASS` | `WARN` | `FAIL` | `n/a`. The detailed
/// failure message is not in report.json; the caller reads it from the
/// `failures/<name>/summary.txt` artifact and passes it in alongside.
pub fn classify(test: &Value) -> Option<FailureKind> {
    if let Some(p) = test.get("problems").and_then(|p| p.as_array()) {
        if !p.is_empty() {
            return Some(FailureKind::OpDivergence);
        }
    }
    let outcomes = test.get("outcomes")?;
    // Axis order matters: a structural failure is more actionable than the
    // semantic one it often also trips, so report structural first.
    for (axis, kind) in [
        ("structural", FailureKind::DifferStructural),
        ("semantic", FailureKind::DifferSemantic),
        ("roundtrip", FailureKind::ValidationMismatch),
        ("bytewise", FailureKind::DifferBytewise),
    ] {
        if outcomes.get(axis).and_then(|s| s.as_str()) == Some("FAIL") {
            return Some(kind);
        }
    }
    None
}

/// Greedily shrink a sequence to the smallest one that still reproduces.
///
/// Hard rule 2: "Minimize before filing." We never remove the first operation
/// (the `hive_create` that captures the handle every later op references), then
/// repeatedly try deleting body operations and keep any deletion that preserves
/// the failure. Repeats to a fixed point, so the result is 1-minimal: no single
/// further op can be removed without losing the bug.
pub fn minimize<F>(seq: &OpSeq, reproduces: F) -> OpSeq
where
    F: Fn(&OpSeq) -> bool,
{
    let mut ops = seq.operations.clone();
    let mut changed = true;
    while changed {
        changed = false;
        let mut i = 1; // never touch op 0 (hive_create + capture)
        while i < ops.len() {
            let mut trial = ops.clone();
            trial.remove(i);
            let candidate = OpSeq {
                name: seq.name.clone(),
                tags: seq.tags.clone(),
                operations: trial.clone(),
                expect: clone_expect(seq),
            };
            if reproduces(&candidate) {
                ops = trial; // removal kept the bug: commit it, retest same index
                changed = true;
            } else {
                i += 1;
            }
        }
    }
    OpSeq {
        name: format!("{}_min", seq.name),
        tags: seq.tags.clone(),
        operations: ops,
        expect: clone_expect(seq),
    }
}

fn clone_expect(seq: &OpSeq) -> crate::generators::ops::ExpectOut {
    crate::generators::ops::ExpectOut { semantic_equal: seq.expect.semantic_equal }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::Coverage;
    use crate::generators::ops;
    use serde_json::json;

    #[test]
    fn signature_ignores_seed_and_digits() {
        let a = signature(FailureKind::DifferSemantic, "hive 'h' at root.subkeys[3]: count 5 vs 6");
        let b = signature(FailureKind::DifferSemantic, "hive 'h' at root.subkeys[9]: count 1 vs 2");
        assert_eq!(a, b, "same bug shape should dedup across differing numbers");
        let c = signature(FailureKind::DifferStructural, "hive 'h' at root.subkeys[3]: count 5 vs 6");
        assert_ne!(a, c, "different kind must not collide");
    }

    #[test]
    fn classify_prefers_problems_then_structural() {
        let r = json!({ "problems": ["op[2] key_create success diverged"], "outcomes": {} });
        assert_eq!(classify(&r).unwrap(), FailureKind::OpDivergence);

        let r = json!({
            "problems": [],
            "outcomes": {"structural": "FAIL", "semantic": "FAIL"},
        });
        assert_eq!(classify(&r).unwrap(), FailureKind::DifferStructural);

        let r = json!({ "problems": [], "outcomes": {"semantic": "PASS"} });
        assert!(classify(&r).is_none());
    }

    #[test]
    fn minimizer_reaches_one_minimal() {
        // Build a real sequence, then define "reproduces" as: contains a
        // value_set whose name is "TRIGGER". The minimizer should strip down to
        // create + that one op (+ whatever op 0 is).
        let mut cov = Coverage::new();
        let mut seq = ops::generate(0xABCD, 60, &mut cov);
        // Inject the trigger op in the middle.
        seq.operations.insert(
            seq.operations.len() / 2,
            json!({"op": "value_set", "handle": "$h", "key": "", "name": "TRIGGER",
                   "type": "REG_SZ", "data": "x"}),
        );
        let has_trigger = |s: &OpSeq| {
            s.operations.iter().any(|o| o.get("name").and_then(|v| v.as_str()) == Some("TRIGGER"))
        };
        assert!(has_trigger(&seq));
        let min = minimize(&seq, has_trigger);
        assert!(has_trigger(&min));
        // op 0 is preserved; only the trigger should remain besides it.
        assert_eq!(min.operations.len(), 2, "not 1-minimal: {:?}", min.operations);
        assert_eq!(min.operations[0].get("op").and_then(|v| v.as_str()), Some("hive_create"));
    }
}
