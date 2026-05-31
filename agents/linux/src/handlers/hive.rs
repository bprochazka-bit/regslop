//! Hive lifecycle endpoints: create, load, save, close.

use super::{req_str, Backend};
use crate::error::Result;
use serde_json::{json, Value as J};

pub fn create(backend: &dyn Backend, body: &J) -> Result<J> {
    let path = req_str(body, "path")?;
    let handle = backend.hive_create(path)?;
    Ok(json!({ "handle": handle }))
}

pub fn load(backend: &dyn Backend, body: &J) -> Result<J> {
    let path = req_str(body, "path")?;
    let handle = backend.hive_load(path)?;
    Ok(json!({ "handle": handle }))
}

pub fn save(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let bytes = backend.hive_save(handle)?;
    Ok(json!({ "bytes_written": bytes }))
}

pub fn close(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    backend.hive_close(handle)?;
    Ok(json!({}))
}
