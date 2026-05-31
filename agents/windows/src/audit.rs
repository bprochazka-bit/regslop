//! Append-only operation audit log.
//!
//! Each request appends one JSON line with a timestamp, endpoint, the request
//! body, and the response status. The harness may collect this for post-mortem
//! debugging. Logging failures never block a request; they are swallowed.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::time::now_iso8601;

static LOG_PATH: Mutex<Option<String>> = Mutex::new(None);

/// Set the audit log path (defaults to "audit.log" in the working directory).
pub fn init(path: String) {
    *LOG_PATH.lock().unwrap() = Some(path);
}

/// Append one audit record. `ok` is the response status; `code` is the error
/// code when the request failed, otherwise None.
pub fn record(endpoint: &str, request: &Value, ok: bool, code: Option<&str>) {
    let path = {
        let guard = LOG_PATH.lock().unwrap();
        guard.clone().unwrap_or_else(|| "audit.log".to_string())
    };
    let line = json!({
        "ts": now_iso8601(),
        "endpoint": endpoint,
        "request": request,
        "ok": ok,
        "code": code,
    });
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
}
