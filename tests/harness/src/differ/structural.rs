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
//!   It evaluates the base-block and hbin/cell invariants 1 to 6, 9, 10, plus
//!   the ones reachable from a cell scan: 11 (subkey-list cells), 13 and 14 (sk
//!   doubly linked list and refcounts), and 16 (key-name encoding), via
//!   `super::regf`. The invariants that need a full logical-tree walk (7, 8,
//!   12, 15) stay `Skipped`; 17 and 18 need the dump/validate and so belong to
//!   `check()`.
//!
//! Everything not evaluated reports `Skipped` with a reason, which the report
//! surfaces honestly rather than silently counting as a pass.

use super::regf;
use serde_json::Value;
use std::collections::HashMap;

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

/// Invariant 16: every key node's name is encoded per its KEY_COMP_NAME flag.
/// Found by scanning allocated cells for the `nk` signature; for each, the
/// strong checks are that a non-compressed (UTF-16LE) name has an even byte
/// length and decodes as valid UTF-16, and that the name region stays inside
/// the cell. A compressed name is Latin-1 (one byte per char), which is always
/// well-formed, so only its bounds are checked. nk layout per docs/hive-format.md.
fn check_key_names(bytes: &[u8], w: &regf::Walk) -> Status {
    const KEY_COMP_NAME: u16 = 0x0020;
    let mut viol = Vec::new();
    for c in w.cells.iter().filter(|c| c.allocated) {
        if c.content_len < 2 || &bytes[c.content_start..c.content_start + 2] != b"nk" {
            continue;
        }
        let base = c.content_start;
        if c.content_len < 76 {
            viol.push(format!("nk at {base:#x}: cell too small to hold the name header"));
            continue;
        }
        let flags = regf::u16_at(bytes, base + 2);
        let name_len = regf::u16_at(bytes, base + 72) as usize;
        if 76 + name_len > c.content_len {
            viol.push(format!("nk at {base:#x}: name length {name_len} overruns the cell"));
            continue;
        }
        if flags & KEY_COMP_NAME == 0 {
            if name_len % 2 != 0 {
                viol.push(format!(
                    "nk at {base:#x}: KEY_COMP_NAME clear but name length {name_len} is odd (UTF-16LE needs even)"
                ));
                continue;
            }
            let name = &bytes[base + 76..base + 76 + name_len];
            let units: Vec<u16> = name.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
            if String::from_utf16(&units).is_err() {
                viol.push(format!("nk at {base:#x}: KEY_COMP_NAME clear but name is not valid UTF-16LE"));
            }
        }
    }
    from_violations(&viol)
}

/// Invariant 11: subkey-list cells use a recognized form, the declared entry
/// count fits the cell, and a leaf (lf/lh) stays under the ri promotion
/// threshold (CONTRACTS: lf/lh for fewer than 1015 entries, ri beyond). Found
/// by scanning allocated cells for the lf/lh/li/ri signatures. The exact cell
/// each nk points at is not followed here (that is the logical tree, inv7); a
/// stray or corrupt list cell is still caught.
fn check_subkey_lists(bytes: &[u8], w: &regf::Walk) -> Status {
    let mut viol = Vec::new();
    let mut found = 0;
    for c in w.cells.iter().filter(|c| c.allocated) {
        if c.content_len < 4 {
            continue;
        }
        let sig = &bytes[c.content_start..c.content_start + 2];
        let entry_size = match sig {
            b"lf" | b"lh" => 8, // subkey offset + 4-byte name hint/hash
            b"li" | b"ri" => 4, // bare offset
            _ => continue,
        };
        found += 1;
        let base = c.content_start;
        let count = regf::u16_at(bytes, base + 2) as usize;
        let needed = 4 + count * entry_size;
        if needed > c.content_len {
            viol.push(format!(
                "{} list at {base:#x}: {count} entries need {needed} bytes, cell holds {}",
                String::from_utf8_lossy(sig),
                c.content_len
            ));
        }
        if (sig == b"lf" || sig == b"lh") && count > 1015 {
            viol.push(format!(
                "{} leaf at {base:#x} has {count} entries (> 1015); should promote to ri",
                String::from_utf8_lossy(sig)
            ));
        }
    }
    if found == 0 {
        // A hive with no subkeys (just a root) has no subkey-list cell; nothing
        // to check rather than a vacuous pass.
        return Status::Skipped("no subkey-list cells present".to_string());
    }
    from_violations(&viol)
}

/// Bin-relative offset of a cell (the offset stored in flink/blink/security
/// pointers): the file offset of its 4-byte size field, minus the base block.
fn cell_offset(c: &regf::Cell) -> usize {
    (c.content_start - 4) - regf::BASE_BLOCK_LEN
}

fn cell_sig<'a>(bytes: &'a [u8], c: &regf::Cell) -> &'a [u8] {
    if c.content_len >= 2 {
        &bytes[c.content_start..c.content_start + 2]
    } else {
        &[]
    }
}

/// Invariants 13 and 14: the `sk` (security) cells form a consistent doubly
/// linked list (13), and reference counts are accurate (14). Checkable from a
/// cell scan: locate every `sk` by its bin-relative offset, verify each
/// flink/blink points at an `sk` that links back, verify no refcount is 0, that
/// every `nk`'s security pointer lands on an `sk`, and that the refcounts sum to
/// the number of `nk` cells (each key references exactly one descriptor).
/// `ref_multi.hiv` pins the shared case: 7 nk, one sk, refcount 7.
fn check_security_cells(bytes: &[u8], w: &regf::Walk) -> (Status, Status) {
    let sk_by_off: HashMap<usize, &regf::Cell> = w
        .cells
        .iter()
        .filter(|c| c.allocated && c.content_len >= 20 && cell_sig(bytes, c) == b"sk")
        .map(|c| (cell_offset(c), c))
        .collect();

    let mut inv13 = Vec::new();
    for (&off, c) in &sk_by_off {
        let flink = regf::u32_at(bytes, c.content_start + 4) as usize;
        let blink = regf::u32_at(bytes, c.content_start + 8) as usize;
        match sk_by_off.get(&flink) {
            Some(fc) => {
                let fblink = regf::u32_at(bytes, fc.content_start + 8) as usize;
                if fblink != off {
                    inv13.push(format!(
                        "sk at {off:#x}: flink {flink:#x} does not link back (its blink is {fblink:#x})"
                    ));
                }
            }
            None => inv13.push(format!("sk at {off:#x}: flink {flink:#x} is not an sk cell")),
        }
        if !sk_by_off.contains_key(&blink) {
            inv13.push(format!("sk at {off:#x}: blink {blink:#x} is not an sk cell"));
        }
    }

    let mut inv14 = Vec::new();
    let mut refcount_sum: u64 = 0;
    for (&off, c) in &sk_by_off {
        let rc = regf::u32_at(bytes, c.content_start + 12);
        if rc == 0 {
            inv14.push(format!("sk at {off:#x}: reference count is 0 (orphan)"));
        }
        refcount_sum += rc as u64;
    }
    let mut nk_count: u64 = 0;
    for c in w.cells.iter().filter(|c| c.allocated && c.content_len >= 76 && cell_sig(bytes, c) == b"nk") {
        nk_count += 1;
        let sec = regf::u32_at(bytes, c.content_start + 44) as usize;
        if !sk_by_off.contains_key(&sec) {
            inv14.push(format!(
                "nk at {:#x}: security pointer {sec:#x} is not an sk cell (dangling)",
                cell_offset(c)
            ));
        }
    }
    if refcount_sum != nk_count {
        inv14.push(format!(
            "sk reference counts sum to {refcount_sum}, but there are {nk_count} nk cells"
        ));
    }

    if sk_by_off.is_empty() {
        let s = Status::Skipped("no sk cells present".to_string());
        return (s.clone(), s);
    }
    (from_violations(&inv13), from_violations(&inv14))
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
/// and the hbin/cell walk, plus 11 (subkey-list cells), 13 and 14 (sk list and
/// refcounts), and 16 (key-name encoding) from a cell scan. The invariants that
/// need a full logical-tree walk (7, 8, 12, 15) stay Skipped, and 17/18 need the
/// canonical dump and the agent validate verdict; use `check()` for those.
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

    // inv11 and inv16 are checkable by scanning allocated cells by signature,
    // without building the logical tree.
    out.push(result(11, "subkey list cell type promotion lf/lh/ri", check_subkey_lists(bytes, &w)));
    out.push(result(16, "key names UTF-16LE, or Latin-1 when KEY_COMP_NAME (0x0020) is set", check_key_names(bytes, &w)));
    let (inv13, inv14) = check_security_cells(bytes, &w);
    out.push(result(13, "security cells doubly linked with refcounts", inv13));
    out.push(result(14, "sk refcounts accurate", inv14));

    let needs_logical = "requires a logical-tree parse (not implemented for static byte checks)";
    for (id, name) in [
        (7, "allocated cells form a tree from root"),
        (8, "free cells tracked in free list"),
        (12, "big-data cells only above 16344 bytes"),
        (15, "class name strings are UTF-16LE"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn corpus(name: &str) -> Vec<u8> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../corpus/synthetic")
            .join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    fn inv(results: &[InvariantResult], id: u8) -> &Status {
        &results.iter().find(|r| r.id == id).unwrap().status
    }

    #[test]
    fn latin1_name_passes_invariant_16() {
        // ref_latin1.hiv has a subkey "Cafe<e-acute>" with KEY_COMP_NAME set
        // (Latin-1, byte 0xE9). It must pass invariant 16.
        let r = check_bytes(&corpus("ref_latin1.hiv"));
        assert_eq!(inv(&r, 16), &Status::Pass, "{:?}", inv(&r, 16));
    }

    #[test]
    fn wide_name_passes_invariant_16() {
        // ref_wide.hiv has an uncompressed UTF-16LE subkey name (Omega + mega).
        let r = check_bytes(&corpus("ref_wide.hiv"));
        assert_eq!(inv(&r, 16), &Status::Pass, "{:?}", inv(&r, 16));
    }

    #[test]
    fn security_cells_pass_invariants_13_and_14() {
        // ref_multi shares one sk across 7 nk cells (refcount 7). The doubly
        // linked list (single self-referential sk) and refcount sum must hold.
        let r = check_bytes(&corpus("ref_multi.hiv"));
        assert_eq!(inv(&r, 13), &Status::Pass, "{:?}", inv(&r, 13));
        assert_eq!(inv(&r, 14), &Status::Pass, "{:?}", inv(&r, 14));
    }

    #[test]
    fn bumping_an_sk_refcount_fails_invariant_14() {
        // Inflate the shared sk's refcount so it no longer equals the nk count.
        let mut bytes = corpus("ref_multi.hiv");
        let w = regf::walk_hbins(&bytes);
        let sk = w
            .cells
            .iter()
            .find(|c| c.allocated && c.content_len >= 20 && &bytes[c.content_start..c.content_start + 2] == b"sk")
            .expect("an sk cell");
        let rc_off = sk.content_start + 12;
        let bumped = regf::u32_at(&bytes, rc_off) + 1;
        bytes[rc_off..rc_off + 4].copy_from_slice(&bumped.to_le_bytes());
        let r = check_bytes(&bytes);
        assert!(matches!(inv(&r, 14), Status::Fail(_)), "{:?}", inv(&r, 14));
        // The link structure is untouched, so inv13 still holds.
        assert_eq!(inv(&r, 13), &Status::Pass, "{:?}", inv(&r, 13));
    }

    #[test]
    fn subkey_lists_pass_invariant_11() {
        // Single-subkey (lh, 1 entry) and multi-subkey (lh, 6 entries) hives.
        for f in ["ref_one_ascii.hiv", "ref_multi.hiv"] {
            let r = check_bytes(&corpus(f));
            assert_eq!(inv(&r, 11), &Status::Pass, "{f}: {:?}", inv(&r, 11));
        }
    }

    #[test]
    fn corrupting_a_wide_name_to_odd_length_fails_invariant_16() {
        // ref_multi has odd-length compressed names ("Alpha" is 5 bytes).
        // Flip KEY_COMP_NAME off on one so the name is reinterpreted as
        // UTF-16LE; its odd byte length must fail inv16.
        let mut bytes = corpus("ref_multi.hiv");
        let w = regf::walk_hbins(&bytes);
        // Find the child nk (an allocated nk that is not the hive root).
        let nk = w
            .cells
            .iter()
            .filter(|c| c.allocated && c.content_len >= 76)
            .find(|c| {
                &bytes[c.content_start..c.content_start + 2] == b"nk"
                    && (regf::u16_at(&bytes, c.content_start + 2) & 0x0020) != 0
                    && regf::u16_at(&bytes, c.content_start + 72) % 2 == 1
            })
            .expect("a compressed-name nk with an odd-length name");
        // Clear KEY_COMP_NAME (0x0020) in the flags word.
        let flags_off = nk.content_start + 2;
        let cleared = regf::u16_at(&bytes, flags_off) & !0x0020;
        bytes[flags_off] = cleared.to_le_bytes()[0];
        bytes[flags_off + 1] = cleared.to_le_bytes()[1];
        let r = check_bytes(&bytes);
        assert!(matches!(inv(&r, 16), Status::Fail(_)), "{:?}", inv(&r, 16));
    }
}
