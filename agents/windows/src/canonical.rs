//! Canonical JSON serialization of a hive, per CONTRACTS "Canonical JSON Form".
//!
//! This output is what semantic diffs compare. It must match the Linux agent
//! byte-for-byte after the harness re-parses, so the rules are exact: subkeys
//! and values sorted by name, class_name null (never ""), timestamps truncated
//! to seconds, binary base64. serde_json's default Map sorts object keys, which
//! gives the stable key ordering the contract asks for.

use serde_json::{json, Value};

use crate::error::AgentError;
use crate::offreg::key::Key;
use crate::offreg::Orhkey;
use crate::sddl::sd_to_sddl;
use crate::time::filetime_to_iso8601;
use crate::valuec;
use crate::winapi::*;

const SEC_ALL: Dword = OWNER_SECURITY_INFORMATION
    | GROUP_SECURITY_INFORMATION
    | DACL_SECURITY_INFORMATION
    | SACL_SECURITY_INFORMATION;
const SEC_NO_SACL: Dword =
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

/// Serialize the whole hive to the canonical form.
pub fn dump_hive(root: Orhkey) -> Result<Value, AgentError> {
    let root_obj = dump_key(root, "", "")?;
    Ok(json!({
        "format_version": "0.1.0",
        "root": root_obj,
    }))
}

fn dump_key(root: Orhkey, path: &str, name: &str) -> Result<Value, AgentError> {
    let key = Key::open(root, path)?;
    let info = key.info()?;

    let mut values: Vec<Value> = key
        .enum_values()?
        .into_iter()
        .map(|(n, ty, bytes)| {
            json!({
                "name": n,
                "type": valuec::type_name(ty),
                "data": valuec::decode(ty, &bytes),
            })
        })
        .collect();
    values.sort_by(|a, b| cmp_by_name(a, b));

    let sddl = read_sddl(&key)?;
    let subnames: Vec<String> = key.enum_subkeys()?.into_iter().map(|(n, _)| n).collect();
    drop(key); // close this handle before descending

    let mut subkeys: Vec<Value> = Vec::with_capacity(subnames.len());
    for subname in subnames {
        let child_path = if path.is_empty() {
            subname.clone()
        } else {
            format!("{path}\\{subname}")
        };
        subkeys.push(dump_key(root, &child_path, &subname)?);
    }
    subkeys.sort_by(|a, b| cmp_by_name(a, b));

    Ok(json!({
        "name": name,
        "last_write": filetime_to_iso8601(info.last_write),
        "class_name": info.class,
        "security": { "sddl": sddl },
        "values": values,
        "subkeys": subkeys,
    }))
}

/// Read the SDDL for a key, falling back to omitting the SACL if the SACL is
/// not readable on this hive (a common offline-hive case).
fn read_sddl(key: &Key) -> Result<String, AgentError> {
    if let Ok(sd) = key.get_security(SEC_ALL) {
        if let Ok(sddl) = sd_to_sddl(&sd, SEC_ALL) {
            return Ok(sddl);
        }
    }
    let sd = key.get_security(SEC_NO_SACL)?;
    sd_to_sddl(&sd, SEC_NO_SACL)
}

/// Compare two `{ "name": ... }` objects case-insensitively (Windows key-name
/// semantics), tie-breaking on the original casing for determinism.
fn cmp_by_name(a: &Value, b: &Value) -> std::cmp::Ordering {
    let an = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let bn = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
    an.to_lowercase()
        .cmp(&bn.to_lowercase())
        .then_with(|| an.cmp(bn))
}
