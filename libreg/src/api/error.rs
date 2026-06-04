//! C ABI error model.
//!
//! The boundary reports outcomes as a stable integer enum that mirrors the
//! CONTRACTS.md "Error Codes" table 1:1 (see `docs/ffi-abi.md`, ratified in
//! issue #107). The names are owned by CONTRACTS.md; this layer only assigns
//! each a stable integer and maps the library's internal errors onto them. It
//! invents no code the spec has not ratified.
//!
//! The integer is the contract. The human-readable detail is diagnostic only
//! and is exposed through a thread-local last-error getter
//! ([`super::libreg_last_error`]); callers must not parse it.

use crate::logical::LogicalError;
use std::cell::RefCell;
use std::ffi::CString;

/// Outcome of a C ABI call. Integer values are the stable contract and are
/// recorded in `libreg/include/libreg.h`; they map 1:1 to the CONTRACTS.md
/// error-code table, in that table's order, with success as 0.
///
/// The `BAD_REQUEST` (caller error) vs `INTERNAL` (library bug) split is
/// preserved exactly as CONTRACTS.md defines it. A caught panic is `INTERNAL`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibregStatus {
    /// The call succeeded.
    Ok = 0,
    /// A hive path does not exist on the filesystem.
    HiveNotFound = 1,
    /// The base block or hbin chain is invalid.
    HiveCorrupt = 2,
    /// The handle is not known (never created, or already closed).
    HandleInvalid = 3,
    /// Path resolution failed: a key on the path does not exist.
    KeyNotFound = 4,
    /// Create was asked for a leaf key that already exists.
    KeyExists = 5,
    /// The named value does not exist on the key.
    ValueNotFound = 6,
    /// The data shape does not match the declared type.
    TypeMismatch = 7,
    /// A security descriptor blocks the operation.
    AccessDenied = 8,
    /// Transaction-log replay failed.
    LogCorrupt = 9,
    /// A non-recursive delete hit a key that still has subkeys.
    KeyHasChildren = 10,
    /// The request is malformed: a caller error, not a library bug.
    BadRequest = 11,
    /// A library bug. The detail string carries context.
    Internal = 12,
}

/// An internal error carrying both the boundary status and a detail string.
/// The detail is stored thread-locally and surfaced by `libreg_last_error`.
pub(crate) struct ApiError {
    pub status: LibregStatus,
    pub detail: String,
}

impl ApiError {
    pub(crate) fn new(status: LibregStatus, detail: impl Into<String>) -> ApiError {
        ApiError {
            status,
            detail: detail.into(),
        }
    }

    /// A malformed argument from the caller (null pointer, bad UTF-8, an
    /// unknown constant). The caller's error, never a library bug.
    pub(crate) fn bad_request(detail: impl Into<String>) -> ApiError {
        ApiError::new(LibregStatus::BadRequest, detail)
    }

    /// The handle was never created or has already been closed.
    pub(crate) fn handle_invalid() -> ApiError {
        ApiError::new(LibregStatus::HandleInvalid, "handle not known to libreg")
    }
}

/// Map a logical-layer error onto a boundary status. Format errors are
/// corruption; a missing key or value is the matching not-found code; an
/// over-eager non-recursive delete is `KEY_HAS_CHILDREN`. `Unsupported`
/// covers well-formed but rejected requests (for example deleting the root),
/// which are caller errors, so they map to `BAD_REQUEST`, never `INTERNAL`.
impl From<LogicalError> for ApiError {
    fn from(e: LogicalError) -> ApiError {
        let status = match &e {
            LogicalError::Format(_) => LibregStatus::HiveCorrupt,
            LogicalError::NotFound => LibregStatus::KeyNotFound,
            LogicalError::HasSubkeys => LibregStatus::KeyHasChildren,
            LogicalError::Unsupported(_) => LibregStatus::BadRequest,
        };
        ApiError::new(status, e.to_string())
    }
}

thread_local! {
    /// The last error detail for the calling thread. Holds a valid C string at
    /// all times so `libreg_last_error` never returns a dangling pointer.
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

/// Record `detail` as this thread's last error. Interior NUL bytes (which
/// cannot occur in a C string) are dropped so the message is always storable.
pub(crate) fn set_last_error(detail: &str) {
    let cleaned: String = detail.chars().filter(|&c| c != '\0').collect();
    let cstring = CString::new(cleaned).unwrap_or_default();
    LAST_ERROR.with(|slot| *slot.borrow_mut() = cstring);
}

/// Borrow this thread's last error and run `f` on the raw pointer. The pointer
/// is valid only for the duration of `f`; the caller returns it onward knowing
/// the backing `CString` lives in thread-local storage until the next call
/// that sets the error on this thread.
pub(crate) fn with_last_error_ptr<R>(f: impl FnOnce(*const std::ffi::c_char) -> R) -> R {
    LAST_ERROR.with(|slot| f(slot.borrow().as_ptr()))
}
