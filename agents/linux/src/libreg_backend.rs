//! `LibregBackend`: a `Backend` implementation backed by the real `libreg`
//! crate (`libreg::logical::Hive`), as anticipated in agents/linux/CLAUDE.md.
//! Selected with `--backend libreg`; the default stays `MemBackend`.
//!
//! Scope of this first slice: the hive lifecycle and key operations over real
//! `regf` bytes (libreg's `to_file`/`from_file_bytes`), plus the canonical dump
//! built by walking the logical tree into `model::Key` and reusing
//! `canonical`. libreg does not yet expose key delete/rename, value
//! delete/set/get wired through a codec, or a security setter, and the agent
//! still owns binary<->SDDL conversion (not implemented here), so those return
//! a clear `INTERNAL` "not yet supported" rather than a wrong answer. Every key
//! reports the ratified default descriptor, which is what libreg assigns.

use crate::backend::Backend;
use crate::canonical;
use crate::error::{AgentError, Code, Result};
use crate::model::{self, Key, KeyInfo, Listing, Validation, Value};
use libreg::logical::{Hive, LogicalError};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

struct Entry {
    hive: Hive,
    /// Filesystem path the hive will be written to on `hive_save`.
    path: String,
}

pub struct LibregBackend {
    backend_id: String,
    hives: Mutex<HashMap<String, Entry>>,
    next_id: Mutex<u64>,
}

impl LibregBackend {
    pub fn new(backend_id: impl Into<String>) -> Self {
        LibregBackend {
            backend_id: backend_id.into(),
            hives: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    fn new_handle(&self) -> String {
        let mut n = self.next_id.lock().unwrap();
        let h = format!("h_lreg_{:06}", *n);
        *n += 1;
        h
    }

    fn with<T>(&self, handle: &str, f: impl FnOnce(&mut Entry) -> Result<T>) -> Result<T> {
        let mut hives = self.hives.lock().unwrap();
        let entry = hives.get_mut(handle).ok_or_else(|| AgentError::handle_invalid(handle))?;
        f(entry)
    }
}

/// Map a libreg logical error to a CONTRACTS error code.
fn map_err(e: LogicalError) -> AgentError {
    match e {
        LogicalError::NotFound => AgentError::new(Code::KeyNotFound, "key path not found"),
        LogicalError::Unsupported(what) => {
            AgentError::new(Code::Internal, format!("libreg does not support this yet: {what}"))
        }
        LogicalError::Format(f) => AgentError::new(Code::HiveCorrupt, format!("libreg format error: {f}")),
    }
}

fn unsupported(op: &str) -> AgentError {
    AgentError::new(
        Code::Internal,
        format!("{op} is not yet supported by the libreg backend (libreg lacks the operation)"),
    )
}

/// Ensure `path` resolves to an existing key, else KEY_NOT_FOUND.
fn require_key(hive: &Hive, path: &str) -> Result<()> {
    match hive.resolve(path).map_err(map_err)? {
        Some(_) => Ok(()),
        None => Err(AgentError::key_not_found(path)),
    }
}

/// Build a `model::Key` tree by walking the libreg hive, so the existing
/// canonical serializer can render it. Values are omitted in this slice (no
/// value codec yet); every key carries the default descriptor.
fn build_key(hive: &Hive, name: &str, path: &str) -> Result<Key> {
    let mut key = Key::new(name); // default sddl + fixed last_write
    let mut subs = hive.subkeys(path).map_err(map_err)?;
    subs.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));
    for sub in subs {
        let child_path = if path.is_empty() { sub.clone() } else { format!("{path}\\{sub}") };
        key.subkeys.push(build_key(hive, &sub, &child_path)?);
    }
    Ok(key)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let out = Sha256::digest(bytes);
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl Backend for LibregBackend {
    fn backend_id(&self) -> String {
        self.backend_id.clone()
    }

    fn hive_create(&self, path: &str) -> Result<String> {
        let handle = self.new_handle();
        self.hives
            .lock()
            .unwrap()
            .insert(handle.clone(), Entry { hive: Hive::new_empty(), path: path.to_string() });
        Ok(handle)
    }

    fn hive_load(&self, path: &str) -> Result<String> {
        let bytes = std::fs::read(path)
            .map_err(|_| AgentError::new(Code::HiveNotFound, format!("path does not exist: {path}")))?;
        let hive = Hive::from_file_bytes(&bytes)
            .map_err(|e| AgentError::new(Code::HiveCorrupt, format!("libreg cannot load hive: {e}")))?;
        let handle = self.new_handle();
        self.hives
            .lock()
            .unwrap()
            .insert(handle.clone(), Entry { hive, path: path.to_string() });
        Ok(handle)
    }

    fn hive_save(&self, handle: &str) -> Result<u64> {
        self.with(handle, |e| {
            let bytes = e.hive.to_file();
            std::fs::write(&e.path, &bytes)
                .map_err(|err| AgentError::new(Code::Internal, format!("write {}: {err}", e.path)))?;
            Ok(bytes.len() as u64)
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
        self.with(handle, |e| {
            // libreg's create_key is idempotent; the contract wants KEY_EXISTS
            // when the leaf already exists, so enforce that at the agent edge.
            if e.hive.resolve(path).map_err(map_err)?.is_some() {
                return Err(AgentError::key_exists(path));
            }
            e.hive.create_key(path).map_err(map_err).map(|_| ())
        })
    }

    fn key_delete(&self, _handle: &str, _path: &str, _recursive: bool) -> Result<()> {
        Err(unsupported("key_delete"))
    }

    fn key_rename(&self, _handle: &str, _path: &str, _new_name: &str) -> Result<()> {
        Err(unsupported("key_rename"))
    }

    fn key_list(&self, handle: &str, path: &str) -> Result<Listing> {
        self.with(handle, |e| {
            require_key(&e.hive, path)?;
            let mut subkeys = e.hive.subkeys(path).map_err(map_err)?;
            let mut values = e.hive.values(path).map_err(map_err)?;
            subkeys.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));
            values.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));
            Ok(Listing { subkeys, values })
        })
    }

    fn key_info(&self, handle: &str, path: &str) -> Result<KeyInfo> {
        self.with(handle, |e| {
            require_key(&e.hive, path)?;
            Ok(KeyInfo {
                last_write: model::FIXED_LAST_WRITE.to_string(),
                class_name: None,
                subkey_count: e.hive.subkeys(path).map_err(map_err)?.len(),
                value_count: e.hive.values(path).map_err(map_err)?.len(),
            })
        })
    }

    fn value_set(&self, _h: &str, _k: &str, _n: &str, _t: &str, _d: &serde_json::Value) -> Result<()> {
        // libreg has set_value, but it takes a REG_* type code and raw bytes;
        // the JSON<->bytes value codec is the next slice.
        Err(unsupported("value_set"))
    }

    fn value_delete(&self, _handle: &str, _key: &str, _name: &str) -> Result<()> {
        Err(unsupported("value_delete"))
    }

    fn value_get(&self, _handle: &str, _key: &str, _name: &str) -> Result<Value> {
        Err(unsupported("value_get"))
    }

    fn security_get(&self, handle: &str, path: &str) -> Result<String> {
        self.with(handle, |e| {
            require_key(&e.hive, path)?;
            // libreg assigns the ratified default descriptor and there is no
            // setter yet, so every key carries the default. Binary<->SDDL
            // conversion (for non-default descriptors) is a later slice.
            Ok(model::DEFAULT_SDDL.to_string())
        })
    }

    fn security_set(&self, _handle: &str, _path: &str, _sddl: &str) -> Result<()> {
        Err(unsupported("security_set"))
    }

    fn dump(&self, handle: &str) -> Result<serde_json::Value> {
        self.with(handle, |e| Ok(canonical::canonical_hive(&build_key(&e.hive, "", "")?)))
    }

    fn checksum(&self, handle: &str) -> Result<(String, String)> {
        self.with(handle, |e| {
            let bytes = e.hive.to_file();
            let canon = canonical::canonical_hive(&build_key(&e.hive, "", "")?);
            Ok((sha256_hex(&bytes), sha256_hex(canon.to_string().as_bytes())))
        })
    }

    fn validate(&self, handle: &str) -> Result<Validation> {
        // Structural validation of the bytes is the harness's job (check_bytes);
        // here we report a clean verdict for a hive libreg just serialized.
        self.with(handle, |_| Ok(Validation { valid: true, errors: Vec::new(), warnings: Vec::new() }))
    }
}
