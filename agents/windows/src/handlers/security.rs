//! Security endpoint: GET and POST /key/security.
//!
//! The protocol uses the same path for read and write. We distinguish by
//! presence of the `sddl` field in the request body (a write supplies it).

use serde_json::{json, Value};

use super::{get_hive, opt_str, req_str};
use crate::error::AgentError;
use crate::offreg::key::Key;
use crate::sddl::{sd_to_sddl, sddl_to_sd};
use crate::state::AppState;
use crate::winapi::*;

const SEC_ALL: Dword = OWNER_SECURITY_INFORMATION
    | GROUP_SECURITY_INFORMATION
    | DACL_SECURITY_INFORMATION
    | SACL_SECURITY_INFORMATION;
const SEC_NO_SACL: Dword =
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

pub fn dispatch(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    if opt_str(body, "sddl").is_some() {
        set(state, body)
    } else {
        get(state, body)
    }
}

/// GET /key/security { handle, path } -> { sddl }
fn get(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_str(body, "path")?;
    let key = Key::open(hive.root(), &path)?;

    // Prefer the full descriptor; fall back without the SACL if it is not
    // readable on this offline hive.
    let sddl = if let Ok(sd) = key.get_security(SEC_ALL) {
        sd_to_sddl(&sd, SEC_ALL).or_else(|_| read_no_sacl(&key))?
    } else {
        read_no_sacl(&key)?
    };
    Ok(json!({ "sddl": sddl }))
}

fn read_no_sacl(key: &Key) -> Result<String, AgentError> {
    let sd = key.get_security(SEC_NO_SACL)?;
    sd_to_sddl(&sd, SEC_NO_SACL)
}

/// POST /key/security { handle, path, sddl } -> {}
fn set(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let path = req_str(body, "path")?;
    let sddl = req_str(body, "sddl")?;

    let sd = sddl_to_sd(&sddl)?;
    let sec_info = sec_info_from_sddl(&sddl);
    let key = Key::open(hive.root(), &path)?;
    key.set_security(sec_info, &sd)?;
    Ok(json!({}))
}

/// Derive which SECURITY_INFORMATION components an SDDL string carries so we
/// only set the parts the caller supplied. SDDL components are introduced by
/// the tokens O:, G:, D:, S: (owner, group, DACL, SACL).
fn sec_info_from_sddl(sddl: &str) -> Dword {
    let mut info = 0;
    if sddl.contains("O:") {
        info |= OWNER_SECURITY_INFORMATION;
    }
    if sddl.contains("G:") {
        info |= GROUP_SECURITY_INFORMATION;
    }
    if sddl.contains("D:") {
        info |= DACL_SECURITY_INFORMATION;
    }
    if sddl.contains("S:") {
        info |= SACL_SECURITY_INFORMATION;
    }
    info
}
