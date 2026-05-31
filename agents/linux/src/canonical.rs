//! Canonical JSON serialization, per the "Canonical JSON Form" section of
//! CONTRACTS.md. This output is what the harness semantic differ compares, so
//! it must match the Windows agent byte for byte after JSON normalization.
//!
//! serde_json's default `Map` is sorted by key, which satisfies the "use
//! sorted keys" rule for object fields. We additionally sort the `subkeys` and
//! `values` arrays lexicographically by name, case insensitively per Windows
//! semantics, preserving original casing in the emitted `name`.

use crate::model::Key;
use serde_json::{json, Value as J};

/// The format version emitted in the canonical envelope. Pinned to the
/// contract minor version.
pub const FORMAT_VERSION: &str = "0.1.0";

/// Build the canonical envelope: `{ "format_version", "root": <key> }`.
pub fn canonical_hive(root: &Key) -> J {
    json!({
        "format_version": FORMAT_VERSION,
        "root": canonical_key(root),
    })
}

/// Case-insensitive lexicographic ordering used for both subkeys and values.
/// Ties (same name ignoring case) fall back to the original byte order so the
/// result is deterministic.
fn name_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let la = a.to_ascii_lowercase();
    let lb = b.to_ascii_lowercase();
    la.cmp(&lb).then_with(|| a.cmp(b))
}

fn canonical_key(key: &Key) -> J {
    let mut values: Vec<&crate::model::Value> = key.values.iter().collect();
    values.sort_by(|x, y| name_cmp(&x.name, &y.name));
    let values_json: Vec<J> = values
        .iter()
        .map(|v| {
            json!({
                "name": v.name,
                "type": v.vtype,
                "data": v.data,
            })
        })
        .collect();

    let mut subkeys: Vec<&Key> = key.subkeys.iter().collect();
    subkeys.sort_by(|x, y| name_cmp(&x.name, &y.name));
    let subkeys_json: Vec<J> = subkeys.iter().map(|k| canonical_key(k)).collect();

    // class_name is null when absent, never an empty string.
    let class_name = match &key.class_name {
        Some(s) if !s.is_empty() => J::String(s.clone()),
        _ => J::Null,
    };

    json!({
        "name": key.name,
        "last_write": key.last_write,
        "class_name": class_name,
        "security": { "sddl": key.security_sddl },
        "values": values_json,
        "subkeys": subkeys_json,
    })
}
