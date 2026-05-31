//! Diagnostics endpoints: dump, checksum, validate.

use super::{req_str, Backend};
use crate::error::Result;
use serde_json::{json, Value as J};

pub fn dump(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let canonical = backend.dump(handle)?;
    Ok(json!({ "canonical_json": canonical }))
}

pub fn checksum(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let (file, canonical) = backend.checksum(handle)?;
    Ok(json!({ "sha256_file": file, "sha256_canonical": canonical }))
}

pub fn validate(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let v = backend.validate(handle)?;
    Ok(json!({ "valid": v.valid, "errors": v.errors, "warnings": v.warnings }))
}
