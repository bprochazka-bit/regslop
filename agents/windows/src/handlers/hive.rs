//! Hive lifecycle endpoints: create, load, save, close, checksum.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{get_hive, opt_str, req_str};
use crate::canonical;
use crate::error::AgentError;
use crate::offreg::hive::Hive;
use crate::state::AppState;

/// POST /hive/create { path } -> { handle }
///
/// Creates an empty hive in memory and immediately materializes it on disk so
/// the file exists even before any modification, then keeps the handle open.
pub fn create(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let path = req_str(body, "path")?;
    let mut hive = Hive::create()?;
    hive.save(&path, state.save_os_major, state.save_os_minor)?;
    hive.source_path = Some(path);
    let handle = state.registry.insert(hive);
    Ok(json!({ "handle": handle }))
}

/// POST /hive/load { path } -> { handle }
pub fn load(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let path = req_str(body, "path")?;
    let hive = Hive::open(&path)?;
    let handle = state.registry.insert(hive);
    Ok(json!({ "handle": handle }))
}

/// POST /hive/save { handle, [path] } -> { bytes_written }
///
/// Saves to the optional `path` override, otherwise to the path the hive was
/// created or loaded from.
pub fn save(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = match opt_str(body, "path").or_else(|| hive.source_path.clone()) {
        Some(p) => p,
        None => {
            return Err(AgentError::new(
                "INTERNAL",
                "no save path: hive was created without a path and none was supplied",
            ))
        }
    };
    hive.save(&path, state.save_os_major, state.save_os_minor)?;
    let bytes_written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    Ok(json!({ "bytes_written": bytes_written }))
}

/// POST /hive/close { handle } -> {}
pub fn close(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    // Missing/non-string handle is BAD_REQUEST; a known-shaped but unknown
    // handle is HANDLE_INVALID (mirrors get_hive).
    let handle = req_str(body, "handle")?;
    match state.registry.remove(&handle) {
        // Dropping the Arc closes the offreg hive handle.
        Some(_) => Ok(json!({})),
        None => Err(AgentError::new(
            "HANDLE_INVALID",
            format!("unknown handle {handle}"),
        )),
    }
}

/// GET /hive/checksum { handle } -> { sha256_file, sha256_canonical }
///
/// `sha256_file` hashes the bytes currently on disk; `sha256_canonical` hashes
/// the canonical JSON, which is what should match across agents even when the
/// file layout differs.
pub fn checksum(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();

    let sha256_file = match &hive.source_path {
        Some(p) => match std::fs::read(p) {
            Ok(bytes) => sha256_hex(&bytes),
            Err(_) => Value::Null,
        },
        None => Value::Null,
    };

    let canonical = canonical::dump_hive(hive.root())?;
    let canonical_bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let sha256_canonical = sha256_hex(&canonical_bytes);

    Ok(json!({
        "sha256_file": sha256_file,
        "sha256_canonical": sha256_canonical,
    }))
}

fn sha256_hex(bytes: &[u8]) -> Value {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    Value::String(out)
}
