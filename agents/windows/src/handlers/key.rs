//! Key endpoints: create, delete, rename, list, info.

use serde_json::{json, Value};

use super::{get_hive, opt_bool, req_str};
use crate::error::AgentError;
use crate::offreg::key::{self, Key};
use crate::offreg::Orhkey;
use crate::time::filetime_to_iso8601;
use crate::state::AppState;

/// POST /key/create { handle, path } -> {}
pub fn create(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_str(body, "path")?;
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
/// offreg's own behavior. (CONTRACTS has no dedicated "has children" code, so
/// this surfaces as INTERNAL with a descriptive message; flagged as a spec gap
/// in STATE.md.)
pub fn delete(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_str(body, "path")?;
    let recursive = opt_bool(body, "recursive", false);

    if !recursive {
        let target = Key::open(hive.root(), &path)?;
        if target.info()?.subkey_count > 0 {
            return Err(AgentError::new(
                "INTERNAL",
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
/// under the same parent, deep-copy the subtree, then delete the source. This
/// cannot preserve original last_write timestamps (the copies are new), which
/// may diverge from libreg's native rename. Flagged as a spec item in STATE.md.
pub fn rename(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_str(body, "path")?;
    let new_name = req_str(body, "new_name")?;

    let parent = path.rsplit_once('\\').map(|(p, _)| p).unwrap_or("");
    let new_path = if parent.is_empty() {
        new_name.clone()
    } else {
        format!("{parent}\\{new_name}")
    };

    let (_dst, created) = Key::create(hive.root(), &new_path)?;
    if !created {
        return Err(AgentError::new(
            "KEY_EXISTS",
            format!("rename target already exists: {new_path}"),
        ));
    }
    copy_tree(hive.root(), &path, &new_path)?;
    key::delete_key(hive.root(), &path, true)?;
    Ok(json!({}))
}

/// Recursively copy values and subkeys from `src` to an already-created `dst`.
fn copy_tree(root: Orhkey, src: &str, dst: &str) -> Result<(), AgentError> {
    let src_key = Key::open(root, src)?;
    let dst_key = Key::open(root, dst)?;
    for (name, ty, bytes) in src_key.enum_values()? {
        dst_key.set_value(&name, ty, &bytes)?;
    }
    let subnames: Vec<String> = src_key.enum_subkeys()?.into_iter().map(|(n, _)| n).collect();
    drop(src_key);
    drop(dst_key);
    for subname in subnames {
        let s = format!("{src}\\{subname}");
        let d = format!("{dst}\\{subname}");
        Key::create(root, &d)?;
        copy_tree(root, &s, &d)?;
    }
    Ok(())
}

/// GET /key/list { handle, path } -> { subkeys: [...], values: [...] }
pub fn list(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_str(body, "path")?;
    let key = Key::open(hive.root(), &path)?;

    let mut subkeys: Vec<String> = key.enum_subkeys()?.into_iter().map(|(n, _)| n).collect();
    let mut values: Vec<String> = key.enum_values()?.into_iter().map(|(n, _, _)| n).collect();
    subkeys.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()).then_with(|| a.cmp(b)));
    values.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()).then_with(|| a.cmp(b)));

    Ok(json!({ "subkeys": subkeys, "values": values }))
}

/// GET /key/info { handle, path }
/// -> { last_write, class_name, subkey_count, value_count }
pub fn info(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_str(body, "path")?;
    let key = Key::open(hive.root(), &path)?;
    let info = key.info()?;
    Ok(json!({
        "last_write": filetime_to_iso8601(info.last_write),
        "class_name": info.class,
        "subkey_count": info.subkey_count,
        "value_count": info.value_count,
    }))
}
