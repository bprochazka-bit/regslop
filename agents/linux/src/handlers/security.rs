//! Security endpoints. CONTRACTS.md uses one path `/key/security` for both
//! GET (read SDDL) and POST (write SDDL). Since the agent routes on path only,
//! we distinguish the two by the presence of an `sddl` field in the body.

use super::{req_str_allow_empty, Backend};
use crate::error::Result;
use serde_json::{json, Value as J};

pub fn dispatch(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str_allow_empty(body, "handle")?;
    let path = req_str_allow_empty(body, "path")?;
    match body.get("sddl").and_then(|v| v.as_str()) {
        Some(sddl) => {
            backend.security_set(handle, path, sddl)?;
            Ok(json!({}))
        }
        None => {
            let sddl = backend.security_get(handle, path)?;
            Ok(json!({ "sddl": sddl }))
        }
    }
}
