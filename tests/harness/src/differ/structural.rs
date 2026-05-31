//! Structural invariants 1 to 18 from CONTRACTS.md.
//!
//! Two entry points:
//!
//! - `check(canonical, validate)` runs against one agent's output. From the
//!   canonical dump it evaluates invariant 17 (subkey lists sorted) and folds
//!   in the agent's own `/hive/validate` verdict for 18; the byte-level
//!   invariants 1 to 16 stay `Skipped` because the in-memory backend does not
//!   emit a real `regf` file and exposes no raw bytes.
//! - `check_bytes(bytes)` runs against a real hive file's bytes (the corpus).
//!   It evaluates the base-block and hbin/cell invariants 1 to 6, 9, and 10
//!   via `super::regf`. The logical-graph invariants (7, 8, 11 to 16) need a
//!   logical parse and stay `Skipped`; 17 and 18 need the dump/validate and so
//!   belong to `check()`.
//!
//! Everything not evaluated reports `Skipped` with a reason, which the report
//! surfaces honestly rather than silently counting as a pass.

use super::regf;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Pass,
    Fail(String),
    Skipped(String),
}

#[derive(Debug, Clone)]
pub struct InvariantResult {
    pub id: u8,
    pub name: &'static str,
    pub status: Status,
}

const NEEDS_BYTES: &str = "requires raw hive bytes (backend does not yet expose them)";

/// Run all invariant checks against one agent's output for one hive.
/// `canonical` is the `canonical_json` payload from `/hive/dump`; `validate` is
/// the data payload from `/hive/validate`.
pub fn check(canonical: &Value, validate: &Value) -> Vec<InvariantResult> {
    let root = canonical.get("root");
    vec![
        skip(1, "base block magic 'regf'"),
        skip(2, "primary sequence == secondary sequence"),
        skip(3, "base block checksum (XOR of first 127 dwords, 0/0xFFFFFFFF quirks) matches"),
        skip(4, "hive bins data size (base block dword at offset 40) matches hbin total, excluding base block"),
        skip(5, "hbin magic and 4096 alignment"),
        skip(6, "cell size nonzero, sign marks allocation"),
        skip(7, "allocated cells form a tree from root"),
        skip(8, "free cells tracked in free list"),
        skip(9, "sum of cell sizes == hbin size - 32-byte header"),
        skip(10, "no cell crosses an hbin boundary"),
        skip(11, "subkey list cell type promotion lf/lh/ri"),
        skip(12, "big-data cells only above 16344 bytes"),
        skip(13, "security cells doubly linked with refcounts"),
        skip(14, "sk refcounts accurate"),
        skip(15, "class name strings are UTF-16LE"),
        skip(16, "key names UTF-16LE, or Latin-1 when KEY_COMP_NAME (0x0020) is set"),
        inv17_subkeys_sorted(root),
        inv18_logs(validate),
    ]
}

fn skip(id: u8, name: &'static str) -> InvariantResult {
    InvariantResult { id, name, status: Status::Skipped(NEEDS_BYTES.to_string()) }
}

fn result(id: u8, name: &'static str, status: Status) -> InvariantResult {
    InvariantResult { id, name, status }
}

fn from_violations(v: &[String]) -> Status {
    if v.is_empty() {
        Status::Pass
    } else {
        Status::Fail(v.join("; "))
    }
}

/// Run the byte-level structural invariants against a real hive file's bytes
/// (a corpus hive). Implements invariants 1 to 6, 9, and 10 from the base block
/// and the hbin/cell walk. The logical-graph invariants (7, 8, 11 to 16) need a
/// logical parse, and 17/18 need the canonical dump and the agent validate
/// verdict; all of those stay Skipped here. Use `check()` for the agent-output
/// path that evaluates 17 and 18.
pub fn check_bytes(bytes: &[u8]) -> Vec<InvariantResult> {
    let mut out = Vec::new();
    let bb = regf::parse_base_block(bytes);
    let w = regf::walk_hbins(bytes);

    out.push(result(
        1,
        "base block magic 'regf'",
        match &bb {
            Some(b) if b.magic_ok => Status::Pass,
            Some(_) => Status::Fail("base block signature is not 'regf'".into()),
            None => Status::Fail(format!(
                "file is {} bytes, shorter than a 4096-byte base block",
                bytes.len()
            )),
        },
    ));

    if let Some(b) = &bb {
        out.push(result(
            2,
            "primary sequence == secondary sequence",
            if b.primary_seq == b.secondary_seq {
                Status::Pass
            } else {
                Status::Fail(format!(
                    "primary {} != secondary {} (hive awaiting log recovery)",
                    b.primary_seq, b.secondary_seq
                ))
            },
        ));
        out.push(result(
            3,
            "base block checksum matches",
            if b.stored_checksum == b.computed_checksum {
                Status::Pass
            } else {
                Status::Fail(format!(
                    "stored checksum {:#010x} != computed {:#010x}",
                    b.stored_checksum, b.computed_checksum
                ))
            },
        ));
        out.push(result(
            4,
            "hive bins data size matches hbin total",
            if b.hive_bins_data_size as usize == w.total_hbin_bytes {
                Status::Pass
            } else {
                Status::Fail(format!(
                    "base block says {} bytes of bins, hbins total {}",
                    b.hive_bins_data_size, w.total_hbin_bytes
                ))
            },
        ));
    } else {
        for (id, name) in [
            (2, "primary sequence == secondary sequence"),
            (3, "base block checksum matches"),
            (4, "hive bins data size matches hbin total"),
        ] {
            out.push(result(id, name, Status::Skipped("no base block to read".into())));
        }
    }

    out.push(result(5, "hbin magic and 4096 alignment", from_violations(&w.hbin_violations)));
    out.push(result(6, "cell size nonzero and multiple of 8", from_violations(&w.cell_size_violations)));
    out.push(result(9, "sum of cell sizes == hbin size - 32-byte header", from_violations(&w.cell_sum_violations)));
    out.push(result(10, "no cell crosses an hbin boundary", from_violations(&w.boundary_violations)));

    let needs_logical = "requires a logical-tree parse (not implemented for static byte checks)";
    for (id, name) in [
        (7, "allocated cells form a tree from root"),
        (8, "free cells tracked in free list"),
        (11, "subkey list cell type promotion lf/lh/ri"),
        (12, "big-data cells only above 16344 bytes"),
        (13, "security cells doubly linked with refcounts"),
        (14, "sk refcounts accurate"),
        (15, "class name strings are UTF-16LE"),
        (16, "key names UTF-16LE, or Latin-1 when KEY_COMP_NAME (0x0020) is set"),
    ] {
        out.push(result(id, name, Status::Skipped(needs_logical.into())));
    }
    out.push(result(17, "subkey lists sorted", Status::Skipped("needs the canonical dump; use check()".into())));
    out.push(result(18, "transaction logs valid or absent", Status::Skipped("needs the agent validate verdict".into())));
    out
}

/// Invariant 17: subkey lists are sorted (binary search is valid). Observable
/// from the canonical dump: every key's `subkeys` array must be in
/// case-insensitive Unicode ordinal order by name (names compared uppercased,
/// per Windows semantics and the canonical sort rule in CONTRACTS 0.1.2).
fn inv17_subkeys_sorted(root: Option<&Value>) -> InvariantResult {
    let mut violations = Vec::new();
    if let Some(root) = root {
        walk_sorted(root, "", &mut violations);
    } else {
        return InvariantResult {
            id: 17,
            name: "subkey lists sorted",
            status: Status::Skipped("no root in dump".to_string()),
        };
    }
    let status = if violations.is_empty() {
        Status::Pass
    } else {
        Status::Fail(format!("unsorted subkeys at: {}", violations.join(", ")))
    };
    InvariantResult { id: 17, name: "subkey lists sorted", status }
}

fn walk_sorted(key: &Value, path: &str, violations: &mut Vec<String>) {
    if let Some(subkeys) = key.get("subkeys").and_then(|s| s.as_array()) {
        let names: Vec<String> = subkeys
            .iter()
            .filter_map(|k| k.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
            .collect();
        let mut sorted = names.clone();
        sorted.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));
        if names != sorted {
            violations.push(if path.is_empty() { "<root>".to_string() } else { path.to_string() });
        }
        for sk in subkeys {
            let name = sk.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let child = if path.is_empty() { name.to_string() } else { format!("{path}\\{name}") };
            walk_sorted(sk, &child, violations);
        }
    }
}

/// Invariant 18: transaction logs are absent (clean hive) or contain a valid
/// recovery sequence. We cannot inspect log files from here, so we defer to the
/// agent's own validate verdict: if it reports the hive valid with no errors,
/// invariant 18 is considered satisfied; otherwise it fails with those errors.
fn inv18_logs(validate: &Value) -> InvariantResult {
    let valid = validate.get("valid").and_then(|v| v.as_bool());
    let status = match valid {
        Some(true) => Status::Pass,
        Some(false) => {
            let errs = validate
                .get("errors")
                .and_then(|e| e.as_array())
                .map(|a| a.iter().filter_map(|e| e.as_str()).collect::<Vec<_>>().join("; "))
                .unwrap_or_default();
            Status::Fail(format!("agent reports hive invalid: {errs}"))
        }
        None => Status::Skipped("agent did not report a validate verdict".to_string()),
    };
    InvariantResult { id: 18, name: "transaction logs valid or absent", status }
}

/// Convenience: does this set of results contain any hard failure?
#[allow(dead_code)]
pub fn any_failed(results: &[InvariantResult]) -> bool {
    results.iter().any(|r| matches!(r.status, Status::Fail(_)))
}
