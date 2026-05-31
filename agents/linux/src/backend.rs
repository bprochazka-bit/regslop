//! Backend abstraction. The handlers call into a `Backend`; the wire protocol
//! never sees backend internals.
//!
//! Today the only implementation is `MemBackend`, an in-memory registry model.
//! It exists so the agent and the differential harness run end to end before
//! libreg is functional (CLAUDE.md implementation order, steps 1 to 4). When
//! libreg's `api/` layer lands, a `LibregBackend` implements this same trait
//! by calling into the library, and `main.rs` selects it. No handler, no
//! canonical serializer, and no wire type changes.
//!
//! The in-memory `save` does NOT produce a real `regf` hive; it writes a JSON
//! envelope to disk so that `load` round-trips and `/hive/checksum` is stable.
//! That means `bytewise` and `structural` (invariants 1 to 18 over real hive
//! bytes) will not pass against this backend; only `semantic` and `roundtrip`
//! are meaningful here. This is expected and is the whole reason those tags are
//! reported separately.

use crate::canonical;
use crate::error::{AgentError, Code, Result};
use crate::model::{Key, KeyInfo, Listing, Validation, Value};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// On-disk envelope written by the in-memory `save`. The magic lets `load`
/// reject foreign files with HIVE_CORRUPT rather than panicking.
#[derive(Serialize, Deserialize)]
struct MemHiveFile {
    magic: String,
    root: Key,
}

const MEM_MAGIC: &str = "libreg-memhive-v0";

struct Hive {
    path: String,
    root: Key,
    /// Bytes of the last successful save, for checksum stability.
    saved_bytes: Option<Vec<u8>>,
}

pub trait Backend: Send + Sync {
    /// e.g. "libreg-0.1.0". Reported in the `/version` handshake.
    fn backend_id(&self) -> String;

    fn hive_create(&self, path: &str) -> Result<String>;
    fn hive_load(&self, path: &str) -> Result<String>;
    fn hive_save(&self, handle: &str) -> Result<u64>;
    fn hive_close(&self, handle: &str) -> Result<()>;

    fn key_create(&self, handle: &str, path: &str) -> Result<()>;
    fn key_delete(&self, handle: &str, path: &str, recursive: bool) -> Result<()>;
    fn key_rename(&self, handle: &str, path: &str, new_name: &str) -> Result<()>;
    fn key_list(&self, handle: &str, path: &str) -> Result<Listing>;
    fn key_info(&self, handle: &str, path: &str) -> Result<KeyInfo>;

    fn value_set(
        &self,
        handle: &str,
        key: &str,
        name: &str,
        vtype: &str,
        data: &serde_json::Value,
    ) -> Result<()>;
    fn value_delete(&self, handle: &str, key: &str, name: &str) -> Result<()>;
    fn value_get(&self, handle: &str, key: &str, name: &str) -> Result<Value>;

    fn security_get(&self, handle: &str, path: &str) -> Result<String>;
    fn security_set(&self, handle: &str, path: &str, sddl: &str) -> Result<()>;

    fn dump(&self, handle: &str) -> Result<serde_json::Value>;
    fn checksum(&self, handle: &str) -> Result<(String, String)>;
    fn validate(&self, handle: &str) -> Result<Validation>;
}

pub struct MemBackend {
    backend_id: String,
    hives: Mutex<HashMap<String, Hive>>,
    next_id: Mutex<u64>,
}

impl MemBackend {
    pub fn new(backend_id: impl Into<String>) -> Self {
        MemBackend {
            backend_id: backend_id.into(),
            hives: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    fn new_handle(&self) -> String {
        let mut n = self.next_id.lock().unwrap();
        let h = format!("h_lin_{:06}", *n);
        *n += 1;
        h
    }

    /// Run a closure with mutable access to the named hive.
    fn with_hive<T>(&self, handle: &str, f: impl FnOnce(&mut Hive) -> Result<T>) -> Result<T> {
        let mut hives = self.hives.lock().unwrap();
        let hive = hives.get_mut(handle).ok_or_else(|| AgentError::handle_invalid(handle))?;
        f(hive)
    }
}

/// Validate that `data` matches the shape implied by the declared type, per the
/// type table in CONTRACTS.md. Returns TYPE_MISMATCH when a known type's data
/// has the wrong shape, and BAD_REQUEST when the type name itself is unknown
/// (an unknown constant, CONTRACTS 0.1.4).
fn validate_value(vtype: &str, data: &serde_json::Value) -> Result<()> {
    use serde_json::Value as J;
    let is_u32 = |n: &serde_json::Number| n.as_u64().map(|v| v <= u32::MAX as u64).unwrap_or(false);
    match vtype {
        "REG_NONE" => match data {
            J::Null => Ok(()),
            _ => Err(AgentError::type_mismatch("REG_NONE data must be null")),
        },
        "REG_SZ" | "REG_EXPAND_SZ" | "REG_LINK" => match data {
            J::String(_) => Ok(()),
            _ => Err(AgentError::type_mismatch(format!("{vtype} data must be a string"))),
        },
        "REG_DWORD" | "REG_DWORD_BE" => match data {
            J::Number(n) if is_u32(n) => Ok(()),
            _ => Err(AgentError::type_mismatch(format!("{vtype} data must be a 32-bit integer"))),
        },
        "REG_QWORD" => match data {
            // integer, or a string when > 2^53 (CONTRACTS.md).
            J::Number(n) if n.as_u64().is_some() || n.as_i64().is_some() => Ok(()),
            J::String(s) if s.parse::<u64>().is_ok() || s.parse::<i64>().is_ok() => Ok(()),
            _ => Err(AgentError::type_mismatch("REG_QWORD data must be an integer or numeric string")),
        },
        "REG_MULTI_SZ" => match data {
            J::Array(items) if items.iter().all(|i| i.is_string()) => Ok(()),
            _ => Err(AgentError::type_mismatch("REG_MULTI_SZ data must be an array of strings")),
        },
        // REG_BINARY and the opaque REG_RESOURCE_* family: base64 string.
        _ if vtype == "REG_BINARY" || vtype.starts_with("REG_RESOURCE") || vtype.starts_with("REG_FULL_RESOURCE") => {
            match data {
                J::String(s) => base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map(|_| ())
                    .map_err(|_| AgentError::type_mismatch(format!("{vtype} data must be base64"))),
                _ => Err(AgentError::type_mismatch(format!("{vtype} data must be a base64 string"))),
            }
        }
        // An unrecognized type name is an unknown constant, i.e. a malformed
        // request (BAD_REQUEST), not a data-shape mismatch (CONTRACTS 0.1.4).
        other => Err(AgentError::bad_request(format!("unknown value type: {other}"))),
    }
}

/// Canonicalize value data into the representation the canonical form requires,
/// so two agents given equivalent input emit byte-identical JSON. Only
/// REG_QWORD needs it today: CONTRACTS encodes a QWORD as an integer and only
/// switches to a string above 2^53 (where f64-based JSON parsers lose
/// precision), regardless of whether the caller sent a number or a numeric
/// string. The threshold mirrors the Windows agent (`v > (1u64 << 53)`).
fn canonicalize_value(vtype: &str, data: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value as J;
    if vtype == "REG_QWORD" {
        let v = match data {
            J::Number(n) => n.as_u64(),
            J::String(s) => s.parse::<u64>().ok(),
            _ => None,
        };
        if let Some(v) = v {
            return if v > (1u64 << 53) {
                J::String(v.to_string())
            } else {
                J::Number(serde_json::Number::from(v))
            };
        }
    }
    data.clone()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

impl Backend for MemBackend {
    fn backend_id(&self) -> String {
        self.backend_id.clone()
    }

    fn hive_create(&self, path: &str) -> Result<String> {
        let handle = self.new_handle();
        let hive = Hive { path: path.to_string(), root: Key::new(""), saved_bytes: None };
        self.hives.lock().unwrap().insert(handle.clone(), hive);
        Ok(handle)
    }

    fn hive_load(&self, path: &str) -> Result<String> {
        let bytes = std::fs::read(path)
            .map_err(|e| AgentError::new(Code::HiveNotFound, format!("cannot read {path}: {e}")))?;
        let parsed: MemHiveFile = serde_json::from_slice(&bytes)
            .map_err(|e| AgentError::new(Code::HiveCorrupt, format!("not a libreg mem hive: {e}")))?;
        if parsed.magic != MEM_MAGIC {
            return Err(AgentError::new(Code::HiveCorrupt, "bad hive magic"));
        }
        let handle = self.new_handle();
        let hive = Hive { path: path.to_string(), root: parsed.root, saved_bytes: Some(bytes) };
        self.hives.lock().unwrap().insert(handle.clone(), hive);
        Ok(handle)
    }

    fn hive_save(&self, handle: &str) -> Result<u64> {
        self.with_hive(handle, |hive| {
            let file = MemHiveFile { magic: MEM_MAGIC.to_string(), root: hive.root.clone() };
            // Deterministic bytes: serde_json with sorted map keys.
            let bytes = serde_json::to_vec(&file)
                .map_err(|e| AgentError::new(Code::Internal, format!("serialize: {e}")))?;
            std::fs::write(&hive.path, &bytes)
                .map_err(|e| AgentError::new(Code::Internal, format!("write {}: {e}", hive.path)))?;
            let n = bytes.len() as u64;
            hive.saved_bytes = Some(bytes);
            Ok(n)
        })
    }

    fn hive_close(&self, handle: &str) -> Result<()> {
        self.hives
            .lock()
            .unwrap()
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| AgentError::handle_invalid(handle))
    }

    fn key_create(&self, handle: &str, path: &str) -> Result<()> {
        self.with_hive(handle, |hive| {
            let comps = Key::split_path(path)?;
            if comps.is_empty() {
                return Err(AgentError::key_exists("")); // root always exists
            }
            let mut cur = &mut hive.root;
            for (i, comp) in comps.iter().enumerate() {
                let last = i + 1 == comps.len();
                if cur.find_subkey(comp).is_some() {
                    if last {
                        return Err(AgentError::key_exists(path));
                    }
                } else {
                    cur.subkeys.push(Key::new(*comp));
                }
                cur = cur.find_subkey_mut(comp).unwrap();
            }
            Ok(())
        })
    }

    fn key_delete(&self, handle: &str, path: &str, recursive: bool) -> Result<()> {
        self.with_hive(handle, |hive| {
            let comps = Key::split_path(path)?;
            if comps.is_empty() {
                return Err(AgentError::new(Code::AccessDenied, "cannot delete the hive root"));
            }
            let (parent_path, leaf) = comps.split_at(comps.len() - 1);
            let leaf = leaf[0];
            let parent = hive.root.get_mut(&parent_path.join("\\"))?;
            let idx = parent
                .subkeys
                .iter()
                .position(|k| k.name.eq_ignore_ascii_case(leaf))
                .ok_or_else(|| AgentError::key_not_found(path))?;
            if !parent.subkeys[idx].subkeys.is_empty() && !recursive {
                // Windows RegDeleteKey refuses a non-empty key. CONTRACTS 0.1.2
                // gives this its own code, KEY_HAS_CHILDREN.
                return Err(AgentError::key_has_children(path));
            }
            parent.subkeys.remove(idx);
            Ok(())
        })
    }

    fn key_rename(&self, handle: &str, path: &str, new_name: &str) -> Result<()> {
        if new_name.is_empty() || new_name.contains('\\') {
            return Err(AgentError::bad_request("new_name must be a single non-empty component"));
        }
        self.with_hive(handle, |hive| {
            let comps = Key::split_path(path)?;
            if comps.is_empty() {
                return Err(AgentError::new(Code::AccessDenied, "cannot rename the hive root"));
            }
            let (parent_path, leaf) = comps.split_at(comps.len() - 1);
            let leaf = leaf[0];
            let parent = hive.root.get_mut(&parent_path.join("\\"))?;
            // Renaming to the same name (case-only change) is allowed.
            if !new_name.eq_ignore_ascii_case(leaf) && parent.find_subkey(new_name).is_some() {
                return Err(AgentError::key_exists(new_name));
            }
            let target = parent
                .find_subkey_mut(leaf)
                .ok_or_else(|| AgentError::key_not_found(path))?;
            target.name = new_name.to_string();
            Ok(())
        })
    }

    fn key_list(&self, handle: &str, path: &str) -> Result<Listing> {
        self.with_hive(handle, |hive| {
            let key = hive.root.get(path)?;
            let mut subkeys: Vec<String> = key.subkeys.iter().map(|k| k.name.clone()).collect();
            let mut values: Vec<String> = key.values.iter().map(|v| v.name.clone()).collect();
            // Case-insensitive Unicode ordinal order, matching the canonical
            // form and the Windows agent (CONTRACTS 0.1.2).
            subkeys.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));
            values.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));
            Ok(Listing { subkeys, values })
        })
    }

    fn key_info(&self, handle: &str, path: &str) -> Result<KeyInfo> {
        self.with_hive(handle, |hive| {
            let key = hive.root.get(path)?;
            Ok(KeyInfo {
                last_write: key.last_write.clone(),
                class_name: key.class_name.clone().filter(|s| !s.is_empty()),
                subkey_count: key.subkeys.len(),
                value_count: key.values.len(),
            })
        })
    }

    fn value_set(
        &self,
        handle: &str,
        key: &str,
        name: &str,
        vtype: &str,
        data: &serde_json::Value,
    ) -> Result<()> {
        validate_value(vtype, data)?;
        let data = canonicalize_value(vtype, data);
        self.with_hive(handle, |hive| {
            let k = hive.root.get_mut(key)?;
            if let Some(existing) = k.find_value_mut(name) {
                existing.vtype = vtype.to_string();
                existing.data = data.clone();
            } else {
                k.values.push(Value {
                    name: name.to_string(),
                    vtype: vtype.to_string(),
                    data: data.clone(),
                });
            }
            Ok(())
        })
    }

    fn value_delete(&self, handle: &str, key: &str, name: &str) -> Result<()> {
        self.with_hive(handle, |hive| {
            let k = hive.root.get_mut(key)?;
            let idx = k
                .values
                .iter()
                .position(|v| v.name.eq_ignore_ascii_case(name))
                .ok_or_else(|| AgentError::value_not_found(name))?;
            k.values.remove(idx);
            Ok(())
        })
    }

    fn value_get(&self, handle: &str, key: &str, name: &str) -> Result<Value> {
        self.with_hive(handle, |hive| {
            let k = hive.root.get(key)?;
            k.find_value(name).cloned().ok_or_else(|| AgentError::value_not_found(name))
        })
    }

    fn security_get(&self, handle: &str, path: &str) -> Result<String> {
        self.with_hive(handle, |hive| Ok(hive.root.get(path)?.security_sddl.clone()))
    }

    fn security_set(&self, handle: &str, path: &str, sddl: &str) -> Result<()> {
        self.with_hive(handle, |hive| {
            hive.root.get_mut(path)?.security_sddl = sddl.to_string();
            Ok(())
        })
    }

    fn dump(&self, handle: &str) -> Result<serde_json::Value> {
        self.with_hive(handle, |hive| Ok(canonical::canonical_hive(&hive.root)))
    }

    fn checksum(&self, handle: &str) -> Result<(String, String)> {
        self.with_hive(handle, |hive| {
            let file_hash = match &hive.saved_bytes {
                Some(b) => sha256_hex(b),
                None => sha256_hex(b""), // not yet saved
            };
            let canon = canonical::canonical_hive(&hive.root);
            let canon_bytes = serde_json::to_vec(&canon)
                .map_err(|e| AgentError::new(Code::Internal, format!("serialize: {e}")))?;
            Ok((file_hash, sha256_hex(&canon_bytes)))
        })
    }

    fn validate(&self, handle: &str) -> Result<Validation> {
        // The in-memory model cannot violate the on-disk invariants 1 to 18
        // because it never produces a real hive. We report valid with a
        // warning that structural checks are not meaningful for this backend.
        self.with_hive(handle, |_hive| {
            Ok(Validation {
                valid: true,
                errors: Vec::new(),
                warnings: vec![
                    "in-memory backend: on-disk hive invariants are not exercised".to_string(),
                ],
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_value_type_is_bad_request() {
        // An unrecognized type name is an unknown constant (BAD_REQUEST),
        // not a data-shape mismatch (CONTRACTS 0.1.4).
        let e = validate_value("REG_NOT_A_TYPE", &json!(1)).unwrap_err();
        assert_eq!(e.code, Code::BadRequest);
    }

    #[test]
    fn wrong_shape_is_type_mismatch_not_bad_request() {
        // A well-formed value whose data does not fit the declared type stays
        // TYPE_MISMATCH, distinct from BAD_REQUEST.
        let e = validate_value("REG_DWORD", &json!("not a number")).unwrap_err();
        assert_eq!(e.code, Code::TypeMismatch);
    }

    #[test]
    fn leading_separator_path_is_bad_request() {
        let e = Key::split_path("\\Software").unwrap_err();
        assert_eq!(e.code, Code::BadRequest);
    }

    #[test]
    fn qword_below_threshold_canonicalizes_to_number() {
        // 2^32 < 2^53, so the canonical form is an integer, not a string
        // (CONTRACTS REG_QWORD rule, matching the Windows agent).
        let v = canonicalize_value("REG_QWORD", &json!("4294967296"));
        assert_eq!(v, json!(4294967296u64));
    }

    #[test]
    fn qword_above_threshold_canonicalizes_to_string() {
        let big = (1u64 << 53) + 1;
        let v = canonicalize_value("REG_QWORD", &json!(big));
        assert_eq!(v, json!(big.to_string()));
    }
}
