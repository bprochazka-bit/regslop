//! Key endpoints: create, delete, rename, list, info.

use super::{opt_bool, req_str, req_str_allow_empty, Backend};
use crate::error::Result;
use serde_json::{json, Value as J};

pub fn create(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let path = req_str(body, "path")?;
    backend.key_create(handle, path)?;
    Ok(json!({}))
}

pub fn delete(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let path = req_str(body, "path")?;
    let recursive = opt_bool(body, "recursive", false);
    backend.key_delete(handle, path, recursive)?;
    Ok(json!({}))
}

pub fn rename(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let path = req_str(body, "path")?;
    let new_name = req_str(body, "new_name")?;
    backend.key_rename(handle, path, new_name)?;
    Ok(json!({}))
}

pub fn list(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let path = req_str_allow_empty(body, "path")?;
    let listing = backend.key_list(handle, path)?;
    Ok(json!({ "subkeys": listing.subkeys, "values": listing.values }))
}

pub fn info(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let path = req_str_allow_empty(body, "path")?;
    let info = backend.key_info(handle, path)?;
    Ok(json!({
        "last_write": info.last_write,
        "class_name": info.class_name,
        "subkey_count": info.subkey_count,
        "value_count": info.value_count,
    }))
}
