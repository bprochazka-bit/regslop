//! Per-type value payload generator.
//!
//! Each REG_* type has its own edge cases (CLAUDE-fuzz.md, "Data Generator
//! Catalog"). The generator produces a `(type_name, data)` pair where `data` is
//! the JSON representation from the CONTRACTS.md value table, ready to drop into
//! a `value_set` operation. `catalog()` returns the fixed boundary cases used by
//! the data fuzzer and committed as regression entries.

use crate::rng::Rng;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};

/// The db-cell boundary from CONTRACTS.md invariant 12: data above 16344 bytes
/// moves into a big-data (db) cell. We probe just below, at, and just above.
pub const DB_BOUNDARY: usize = 16344;

/// All value types from the CONTRACTS.md table, with the weight each gets in
/// random generation. Common types dominate; the opaque resource types appear
/// rarely but are still exercised.
const TYPE_WEIGHTS: &[(&str, u64)] = &[
    ("REG_SZ", 22),
    ("REG_EXPAND_SZ", 8),
    ("REG_DWORD", 18),
    ("REG_DWORD_BE", 4),
    ("REG_QWORD", 10),
    ("REG_BINARY", 18),
    ("REG_MULTI_SZ", 12),
    ("REG_NONE", 3),
    ("REG_LINK", 2),
    ("REG_RESOURCE_LIST", 3),
];

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// A pseudo-random byte buffer of the given length, filled deterministically.
fn bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        v.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    v.truncate(len);
    v
}

/// A short string drawn from a small pool plus occasional tricky content
/// (embedded null, astral-plane char, long run).
fn text(rng: &mut Rng) -> String {
    match rng.below(100) {
        0..=59 => {
            const POOL: &[&str] = &["hello", "world", "%PATH%", "C:\\Temp", "value", ""];
            rng.choice(POOL).to_string()
        }
        60..=74 => "a\u{0}b".to_string(),          // embedded null
        75..=84 => "\u{1F600}\u{1F4A9}".to_string(), // surrogate pairs
        85..=94 => "x".repeat(rng.range(1, 4000) as usize),
        _ => "líne1\nlíne2\ttab".to_string(),
    }
}

/// Random multi-string array, including the embedded-null and surrogate cases.
fn multi(rng: &mut Rng) -> Vec<String> {
    let n = match rng.below(100) {
        0..=14 => 0,
        15..=64 => rng.range(1, 3) as usize,
        _ => rng.range(4, 12) as usize,
    };
    (0..n).map(|_| text(rng)).collect()
}

/// Produce a `(type_name, data)` for a random value, weighted by `TYPE_WEIGHTS`.
pub fn value(rng: &mut Rng) -> (String, Value) {
    let cum: Vec<u64> = TYPE_WEIGHTS
        .iter()
        .scan(0u64, |acc, (_, w)| {
            *acc += *w;
            Some(*acc)
        })
        .collect();
    let idx = rng.weighted(&cum);
    let ty = TYPE_WEIGHTS[idx].0;
    let data = data_for(rng, ty);
    (ty.to_string(), data)
}

/// A random payload of the JSON shape the given type requires.
pub fn data_for(rng: &mut Rng, ty: &str) -> Value {
    match ty {
        "REG_SZ" | "REG_EXPAND_SZ" | "REG_LINK" => json!(text(rng)),
        "REG_NONE" => Value::Null,
        "REG_DWORD" | "REG_DWORD_BE" => {
            let v = match rng.below(100) {
                0..=9 => 0u32,
                10..=19 => 1,
                20..=29 => 0x7FFF_FFFF,
                30..=39 => 0x8000_0000,
                40..=49 => 0xFFFF_FFFF,
                _ => rng.next_u64() as u32,
            };
            json!(v)
        }
        "REG_QWORD" => {
            // Above 2^53 must be carried as a string (CONTRACTS.md), else JSON
            // number precision is lost.
            match rng.below(100) {
                0..=49 => json!(rng.below(1 << 40)),
                _ => json!(rng.next_u64().to_string()),
            }
        }
        "REG_BINARY" | "REG_RESOURCE_LIST" => {
            let len = match rng.below(100) {
                0..=9 => 0,
                10..=19 => 1,
                20..=39 => rng.range(2, 64) as usize,
                40..=59 => DB_BOUNDARY - 1,
                60..=74 => DB_BOUNDARY,
                75..=89 => DB_BOUNDARY + 1,
                _ => rng.range(16, 4096) as usize,
            };
            json!(b64(&bytes(rng, len)))
        }
        "REG_MULTI_SZ" => json!(multi(rng)),
        // Unknown type name: still emit a plausible shape so misuse generation
        // can deliberately use it.
        _ => json!(b64(&bytes(rng, 4))),
    }
}

/// A deliberately malformed `(type, data)` pair: the type is valid but the data
/// shape does not fit it. The agent must reject this with TYPE_MISMATCH (or
/// BAD_REQUEST), and both agents must agree.
pub fn type_mismatch(rng: &mut Rng) -> (String, Value) {
    let cases: &[(&str, Value)] = &[
        ("REG_DWORD", json!("not a number")),
        ("REG_DWORD", json!(["array"])),
        ("REG_SZ", json!(123)),
        ("REG_MULTI_SZ", json!("not an array")),
        ("REG_BINARY", json!("!!! not base64 !!!")),
        ("REG_QWORD", json!({"obj": 1})),
        ("REG_NONE", json!("should be null")),
    ];
    let (ty, data) = rng.choice(cases);
    (ty.to_string(), data.clone())
}

/// Fixed edge-case catalog, the backbone of the data fuzzer and the committed
/// regression set. Each entry is `(type, case_name, data)`.
pub fn catalog() -> Vec<(&'static str, String, Value)> {
    let mut out: Vec<(&'static str, String, Value)> = Vec::new();

    let mut push = |ty: &'static str, name: &str, data: Value| {
        out.push((ty, name.to_string(), data));
    };

    // REG_BINARY around the db-cell boundary.
    push("REG_BINARY", "empty", json!(""));
    push("REG_BINARY", "one_byte", json!(b64(&[0xAA])));
    push("REG_BINARY", "db_boundary_minus_1", json!(b64(&vec![0x5A; DB_BOUNDARY - 1])));
    push("REG_BINARY", "db_boundary", json!(b64(&vec![0x5A; DB_BOUNDARY])));
    push("REG_BINARY", "db_boundary_plus_1", json!(b64(&vec![0x5A; DB_BOUNDARY + 1])));
    push("REG_BINARY", "big_64k", json!(b64(&vec![0x5A; 65536])));

    // REG_SZ tricky strings.
    push("REG_SZ", "empty", json!(""));
    push("REG_SZ", "embedded_null", json!("a\u{0}b"));
    push("REG_SZ", "surrogate_pair", json!("\u{1F600}"));
    push("REG_SZ", "long_4k", json!("x".repeat(4096)));

    // REG_MULTI_SZ.
    push("REG_MULTI_SZ", "empty", json!([]));
    push("REG_MULTI_SZ", "single", json!(["one"]));
    push("REG_MULTI_SZ", "embedded_null", json!(["a\u{0}b", "c"]));
    push("REG_MULTI_SZ", "surrogate_pair", json!(["\u{1F600}"]));
    push("REG_MULTI_SZ", "many", json!(["a", "b", "c", "d", "e"]));

    // REG_DWORD limits.
    push("REG_DWORD", "zero", json!(0));
    push("REG_DWORD", "max", json!(0xFFFF_FFFFu32));
    push("REG_DWORD", "high_bit", json!(0x8000_0000u32));
    push("REG_DWORD_BE", "max", json!(0xFFFF_FFFFu32));

    // REG_QWORD: small and the >2^53 string form.
    push("REG_QWORD", "small", json!(4294967296u64));
    push("REG_QWORD", "max_as_string", json!(u64::MAX.to_string()));

    push("REG_NONE", "null", Value::Null);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_types_are_known() {
        let known = [
            "REG_SZ", "REG_EXPAND_SZ", "REG_LINK", "REG_NONE", "REG_DWORD",
            "REG_DWORD_BE", "REG_QWORD", "REG_BINARY", "REG_MULTI_SZ",
            "REG_RESOURCE_LIST",
        ];
        let mut r = Rng::new(5);
        for _ in 0..5000 {
            let (ty, _) = value(&mut r);
            assert!(known.contains(&ty.as_str()), "unknown type generated: {ty}");
        }
    }

    #[test]
    fn binary_payloads_are_valid_base64() {
        let mut r = Rng::new(6);
        for _ in 0..500 {
            let d = data_for(&mut r, "REG_BINARY");
            let s = d.as_str().unwrap();
            assert!(STANDARD.decode(s).is_ok(), "not base64: {s:.40}");
        }
    }

    #[test]
    fn catalog_has_db_boundary_triple() {
        let cat = catalog();
        for want in ["db_boundary_minus_1", "db_boundary", "db_boundary_plus_1"] {
            assert!(cat.iter().any(|(_, n, _)| n == want), "missing {want}");
        }
    }

    #[test]
    fn deterministic() {
        let mut a = Rng::new(77);
        let mut b = Rng::new(77);
        for _ in 0..1000 {
            assert_eq!(value(&mut a), value(&mut b));
        }
    }
}
