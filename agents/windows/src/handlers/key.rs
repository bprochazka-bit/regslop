//! Key endpoints: create, delete, rename, list, info.

use serde_json::{json, Value};

use super::{get_hive, opt_bool, req_path, req_str};
use crate::error::AgentError;
use crate::offreg::key::{self, Key};
use crate::time::filetime_to_iso8601;
use crate::state::AppState;

/// The hive root (empty path) is structurally protected: it cannot be deleted
/// or renamed. CONTRACTS 0.1.13 pins this to ACCESS_DENIED (not INTERNAL, which
/// is reserved for agent bugs, and not KEY_NOT_FOUND, since the root exists).
/// offreg itself returns ERROR_BADKEY/INTERNAL on root delete and a stale
/// KEY_NOT_FOUND on root rename, so we reject before reaching offreg.
fn reject_root(path: &str, op: &str) -> Result<(), AgentError> {
    if path.is_empty() {
        return Err(AgentError::new(
            "ACCESS_DENIED",
            format!("cannot {op} the hive root: it is structurally protected"),
        ));
    }
    Ok(())
}

/// POST /key/create { handle, path } -> {}
pub fn create(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_path(body, "path")?;
    let (_key, created) = Key::create(hive.root(), &path)?;
    if !created {
        return Err(AgentError::new(
            "KEY_EXISTS",
            format!("key already exists: {path}"),
        ));
    }
    Ok(json!({}))
}

/// POST /key/delete { handle, path, [recursive] } -> {}
///
/// Non-recursive deletion of a key that still has subkeys is refused, mirroring
/// offreg's own behavior, and returns KEY_HAS_CHILDREN (CONTRACTS 0.1.2).
pub fn delete(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_path(body, "path")?;
    reject_root(&path, "delete")?;
    let recursive = opt_bool(body, "recursive", false);

    if !recursive {
        let target = Key::open(hive.root(), &path)?;
        if target.info()?.subkey_count > 0 {
            return Err(AgentError::new(
                "KEY_HAS_CHILDREN",
                format!("key has subkeys, pass recursive=true to delete: {path}"),
            ));
        }
    }
    key::delete_key(hive.root(), &path, recursive)?;
    Ok(json!({}))
}

/// POST /key/rename { handle, path, new_name } -> {}
///
/// offreg has no native rename, so this is emulated: create the destination key
/// under the same parent and deep-copy the subtree (class, security, values,
/// and all descendants), then delete the source. Per CONTRACTS 0.1.2 this MUST
/// preserve class/security/values/subtree; descendant `last_write` cannot be
/// preserved by a copy, and the harness excludes `last_write` under a renamed
/// path from semantic comparison for that reason.
pub fn rename(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_path(body, "path")?;
    reject_root(&path, "rename")?;
    let new_name = req_str(body, "new_name")?;

    let parent = path.rsplit_once('\\').map(|(p, _)| p).unwrap_or("");
    let new_path = if parent.is_empty() {
        new_name.clone()
    } else {
        format!("{parent}\\{new_name}")
    };

    // Reject if the target already exists (offreg create would just open it).
    if Key::open(hive.root(), &new_path).is_ok() {
        return Err(AgentError::new(
            "KEY_EXISTS",
            format!("rename target already exists: {new_path}"),
        ));
    }
    key::copy_subtree(hive.root(), &path, &new_path)?;
    key::delete_key(hive.root(), &path, true)?;
    Ok(json!({}))
}

/// GET /key/list { handle, path } -> { subkeys: [...], values: [...] }
pub fn list(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_path(body, "path")?;
    let key = Key::open(hive.root(), &path)?;

    let mut subkeys: Vec<String> = key.enum_subkeys()?.into_iter().map(|(n, _)| n).collect();
    let mut values: Vec<String> = key.enum_values()?.into_iter().map(|(n, _, _)| n).collect();
    // CONTRACTS 0.1.2: case-insensitive Unicode ordinal order, names uppercased.
    subkeys.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));
    values.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));

    Ok(json!({ "subkeys": subkeys, "values": values }))
}

/// GET /key/info { handle, path }
/// -> { last_write, class_name, subkey_count, value_count }
pub fn info(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_path(body, "path")?;
    let key = Key::open(hive.root(), &path)?;
    let info = key.info()?;
    Ok(json!({
        "last_write": filetime_to_iso8601(info.last_write),
        "class_name": info.class,
        "subkey_count": info.subkey_count,
        "value_count": info.value_count,
    }))
}

#[cfg(test)]
mod tests {
    use super::reject_root;

    #[test]
    fn root_delete_and_rename_are_access_denied() {
        // CONTRACTS 0.1.13: the empty path is the hive root and is structurally
        // protected. Both operations must report ACCESS_DENIED, never INTERNAL
        // or KEY_NOT_FOUND.
        let del = reject_root("", "delete").unwrap_err();
        assert_eq!(del.code, "ACCESS_DENIED");
        let ren = reject_root("", "rename").unwrap_err();
        assert_eq!(ren.code, "ACCESS_DENIED");
    }

    #[test]
    fn non_root_paths_pass_the_guard() {
        assert!(reject_root("Software", "delete").is_ok());
        assert!(reject_root("Software\\Acme", "rename").is_ok());
    }
}
