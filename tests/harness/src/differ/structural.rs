//! Structural invariants 1 to 18 from CONTRACTS.md.
//!
//! Most invariants are properties of the raw on-disk hive bytes (base block
//! checksum, hbin chaining, cell sign, sk refcounts, and so on). The harness
//! cannot evaluate them from the canonical JSON dump alone, and the current
//! in-memory backend does not emit a real `regf` file. Each invariant is
//! therefore implemented as its own function returning `Status`, so the
//! scaffolding is complete: when a backend that produces real hive bytes lands
//! (and the agent gains a raw-bytes accessor), the byte-level checks fill in
//! without restructuring this module.
//!
//! Today only invariant 17 (subkey lists sorted) is observable from the
//! canonical form, and we additionally fold in the agent's own `/hive/validate`
//! verdict. Everything else reports `Skipped` with the reason, which the report
//! surfaces honestly rather than silently counting as a pass.

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
