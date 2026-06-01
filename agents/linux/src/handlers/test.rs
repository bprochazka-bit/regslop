//! Test-only endpoints (`/test/...`) for the recovery harness, Linux/libreg
//! only. Not part of the production protocol: this is the crash-injection hook
//! from ADR 0004 part B / issue #61. The Windows agent does not implement it.

use super::{req_str, Backend};
use crate::error::Result;
use serde_json::{json, Value as J};

/// POST /test/crash_save { handle, point } -> { bytes_written, crashed_at }
///
/// Execute a recoverable save truncated at `point`, leaving the on-disk primary
/// and logs in a mid-save state so the next `/hive/load` exercises recovery.
pub fn crash_save(backend: &dyn Backend, body: &J) -> Result<J> {
    let handle = req_str(body, "handle")?;
    let point = req_str(body, "point")?;
    let bytes = backend.crash_save(handle, point)?;
    Ok(json!({ "bytes_written": bytes, "crashed_at": point }))
}
