//! In-memory registry model. This is the data the backend operates on.
//!
//! Name matching is case insensitive (Windows semantics) but the original
//! casing is preserved, exactly as CONTRACTS.md requires for canonical output.

use crate::error::{AgentError, Result};
use serde::{Deserialize, Serialize};

/// Default security descriptor applied to a freshly created key. This matches
/// the default that the offreg oracle produces for a fresh offline hive,
/// observed live on the Windows VM (2026-05-31): owner/group BA, and a DACL of
/// SYSTEM (full), Administrators (full), Everyone (read), and Restricted Code
/// (read), all container-inheritable. The harness differ confirmed an
/// identical descriptor on both sides once this matched. The canonical default
/// is not yet specified in CONTRACTS.md; pending a spec decision this mirrors
/// the oracle. Tracked in agents/linux/spec-questions.md.
pub const DEFAULT_SDDL: &str =
    "O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)";

/// Deterministic last-write timestamp for the in-memory backend. A real
/// backend stamps wall-clock time; the harness differ ignores `last_write` by
/// default precisely because two implementations cannot agree on it to the
/// second. See spec-questions.md.
pub const FIXED_LAST_WRITE: &str = "2026-01-01T00:00:00Z";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Value {
    pub name: String,
    #[serde(rename = "type")]
    pub vtype: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    pub name: String,
    pub class_name: Option<String>,
    pub last_write: String,
    pub security_sddl: String,
    pub values: Vec<Value>,
    pub subkeys: Vec<Key>,
}

impl Key {
    pub fn new(name: impl Into<String>) -> Self {
        Key {
            name: name.into(),
            class_name: None,
            last_write: FIXED_LAST_WRITE.to_string(),
            security_sddl: DEFAULT_SDDL.to_string(),
            values: Vec::new(),
            subkeys: Vec::new(),
        }
    }

    /// Split a registry path into components. Empty string is the root (no
    /// components). Paths never start with a separator per CONTRACTS.md.
    pub fn split_path(path: &str) -> Result<Vec<&str>> {
        if path.is_empty() {
            return Ok(Vec::new());
        }
        if path.starts_with('\\') {
            return Err(AgentError::bad_request(format!(
                "path must not start with a separator: {path}"
            )));
        }
        let parts: Vec<&str> = path.split('\\').collect();
        if parts.iter().any(|p| p.is_empty()) {
            return Err(AgentError::bad_request(format!(
                "path has an empty component: {path}"
            )));
        }
        Ok(parts)
    }

    pub fn find_subkey(&self, name: &str) -> Option<&Key> {
        self.subkeys.iter().find(|k| k.name.eq_ignore_ascii_case(name))
    }

    pub fn find_subkey_mut(&mut self, name: &str) -> Option<&mut Key> {
        self.subkeys.iter_mut().find(|k| k.name.eq_ignore_ascii_case(name))
    }

    /// Navigate to the key at `path` relative to this key.
    pub fn get(&self, path: &str) -> Result<&Key> {
        let mut cur = self;
        for comp in Key::split_path(path)? {
            cur = cur.find_subkey(comp).ok_or_else(|| AgentError::key_not_found(path))?;
        }
        Ok(cur)
    }

    pub fn get_mut(&mut self, path: &str) -> Result<&mut Key> {
        let comps = Key::split_path(path)?;
        let mut cur = self;
        for comp in comps {
            cur = cur
                .find_subkey_mut(comp)
                .ok_or_else(|| AgentError::key_not_found(path))?;
        }
        Ok(cur)
    }

    pub fn find_value(&self, name: &str) -> Option<&Value> {
        self.values.iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }

    pub fn find_value_mut(&mut self, name: &str) -> Option<&mut Value> {
        self.values.iter_mut().find(|v| v.name.eq_ignore_ascii_case(name))
    }
}

/// Result of `/key/list`.
#[derive(Debug, Clone)]
pub struct Listing {
    pub subkeys: Vec<String>,
    pub values: Vec<String>,
}

/// Result of `/key/info`.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub last_write: String,
    pub class_name: Option<String>,
    pub subkey_count: usize,
    pub value_count: usize,
}

/// Result of `/hive/validate`.
#[derive(Debug, Clone)]
pub struct Validation {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}
