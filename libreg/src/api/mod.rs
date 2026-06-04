//! Layer 4: the stable C ABI (`cdylib`).
//!
//! This is the thin in-process surface native bindings link against (for
//! example the Python `ctypes` binding, issue #108). It is governed by
//! `docs/ffi-abi.md` (ratified in issue #107) and implemented here under issue
//! #106. The rules it conforms to:
//!
//! - **Error model** ([`error`]): a stable integer enum that mirrors the
//!   CONTRACTS.md error-code table 1:1, with the `BAD_REQUEST` (caller error)
//!   vs `INTERNAL` (library bug) split preserved. The detail string is
//!   diagnostic only, read through [`libreg_last_error`].
//! - **Binary-native representation**: value data and security descriptors
//!   cross as `(pointer, length)`, value types as native `u32`. The HTTP
//!   protocol's base64 and "QWORD as a string" rules are JSON wire artifacts
//!   and do not apply here. The canonical form remains the acceptance oracle;
//!   a consumer (the harness FFI backend, a binding) builds it from the
//!   enumeration primitives below, exactly as the HTTP agent builds it from
//!   `logical::Hive`.
//! - **Opaque handles** ([`handle`]): a `uint64_t` token, never a Rust
//!   pointer. An unknown or closed token is `HANDLE_INVALID`, not UB.
//! - **Panic safety**: every entry point wraps its body in [`guard`], so a
//!   panic is caught and reported as `INTERNAL` instead of unwinding across
//!   the boundary.
//! - **Buffer ownership**: every buffer the library hands out is released by
//!   [`libreg_free`]; callers do not free it with their own allocator.
//!
//! Security is exposed as the **binary self-relative descriptor**, mirroring
//! [`crate::logical::Hive::key_security`]. libreg does not parse or emit SDDL
//! (ADR 0003 makes the SDDL/binary conversion the consumer's job, the same as
//! on the HTTP side); the binding or harness converts. See `STATE.md` for the
//! note raised to the spec about the `docs/ffi-abi.md` "get/set SDDL" wording.

pub mod error;
pub mod handle;

pub use error::LibregStatus;

use crate::logical::Hive;
use error::{set_last_error, with_last_error_ptr, ApiError};
use std::ffi::{c_char, c_int, CStr};

/// Run an entry-point body, catching panics and mapping the result to a status
/// code. A returned error records its detail as the thread's last error; a
/// caught panic becomes `INTERNAL` so it never unwinds across the FFI boundary
/// (`docs/ffi-abi.md` rule 4).
fn guard(body: impl FnOnce() -> Result<(), ApiError>) -> LibregStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(Ok(())) => LibregStatus::Ok,
        Ok(Err(e)) => {
            set_last_error(&e.detail);
            e.status
        }
        Err(_) => {
            set_last_error("internal panic caught at the FFI boundary");
            LibregStatus::Internal
        }
    }
}

/// Borrow a caller-provided C string as `&str` for the duration of the call.
///
/// # Safety
/// `ptr`, when non-null, must point at a NUL-terminated string that stays
/// valid and unmodified for the lifetime of the returned reference (the whole
/// call). A null pointer or non-UTF-8 contents is a `BAD_REQUEST`.
unsafe fn cstr<'a>(ptr: *const c_char, what: &str) -> Result<&'a str, ApiError> {
    if ptr.is_null() {
        return Err(ApiError::bad_request(format!("{what} pointer is null")));
    }
    // SAFETY: caller guarantees a NUL-terminated string valid for the call.
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| ApiError::bad_request(format!("{what} is not valid UTF-8")))
}

/// Borrow a caller-provided byte buffer as `&[u8]`.
///
/// # Safety
/// When `len` is non-zero, `ptr` must point at `len` readable bytes that stay
/// valid for the lifetime of the returned slice. A zero length yields an empty
/// slice and `ptr` is ignored.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], ApiError> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(ApiError::bad_request(
            "data pointer is null but length is non-zero",
        ));
    }
    // SAFETY: caller guarantees `len` readable bytes valid for the call.
    Ok(std::slice::from_raw_parts(ptr, len))
}

/// Hand a freshly allocated copy of `data` to the caller through `out_ptr` /
/// `out_len`. The caller releases it with [`libreg_free`].
///
/// # Safety
/// `out_ptr` and `out_len` must be non-null and writable.
unsafe fn emit_bytes(
    data: &[u8],
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> Result<(), ApiError> {
    if out_ptr.is_null() || out_len.is_null() {
        return Err(ApiError::bad_request("output buffer pointer is null"));
    }
    let boxed: Box<[u8]> = data.to_vec().into_boxed_slice();
    let len = boxed.len();
    // SAFETY: out pointers checked non-null just above; Box::into_raw yields a
    // pointer libreg_free reconstructs with the same length.
    *out_len = len;
    *out_ptr = Box::into_raw(boxed) as *mut u8;
    Ok(())
}

/// Hand a list of names to the caller as a single buffer of NUL-terminated
/// UTF-8 strings (`name0\0name1\0...`), with the count written to `out_count`.
/// Registry names never contain an interior NUL, so the caller splits on NUL.
/// The buffer is released with [`libreg_free`].
///
/// # Safety
/// `out_ptr`, `out_len`, and `out_count` must be non-null and writable.
unsafe fn emit_names(
    names: &[String],
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
    out_count: *mut usize,
) -> Result<(), ApiError> {
    if out_count.is_null() {
        return Err(ApiError::bad_request("output count pointer is null"));
    }
    let mut buf = Vec::new();
    for name in names {
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
    }
    // SAFETY: out_count checked above; emit_bytes checks the buffer pointers.
    *out_count = names.len();
    emit_bytes(&buf, out_ptr, out_len)
}

/// Translate a filesystem error from load/save onto a boundary status: a
/// missing file is `HIVE_NOT_FOUND`, anything else is `INTERNAL`.
fn map_io(e: std::io::Error, path: &str) -> ApiError {
    if e.kind() == std::io::ErrorKind::NotFound {
        ApiError::new(
            LibregStatus::HiveNotFound,
            format!("hive not found: {path}"),
        )
    } else {
        ApiError::new(LibregStatus::Internal, format!("io error on {path}: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Library-wide entry points
// ---------------------------------------------------------------------------

/// The backend id string, identical to the agent handshake `backend` field, so
/// a binding and the harness check the C ABI's version the same way they check
/// `/version` over HTTP (`docs/ffi-abi.md` rule 3). The returned pointer is
/// static and must not be freed.
#[no_mangle]
pub extern "C" fn libreg_version() -> *const c_char {
    b"libreg-0.1.0\0".as_ptr() as *const c_char
}

/// The detail string for this thread's most recent failing call. The pointer
/// is valid until the next libreg call on the same thread. It is never null;
/// it is the empty string before any error. Diagnostic only: the integer
/// status is the contract.
#[no_mangle]
pub extern "C" fn libreg_last_error() -> *const c_char {
    with_last_error_ptr(|p| p)
}

/// Release a buffer the library handed out through an `out_ptr` / `out_len`
/// pair (value data, security descriptors, name lists, validate problems).
/// `len` must be the exact length the library reported. A null pointer is a
/// no-op. Do not call on `libreg_version` or `libreg_last_error` results.
///
/// # Safety
/// `ptr`/`len` must be a pair the library produced and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn libreg_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: ptr/len came from emit_bytes' Box::into_raw with this same len,
    // so reconstructing the boxed slice and dropping it frees exactly it.
    drop(Box::from_raw(std::slice::from_raw_parts_mut(ptr, len)));
}

// ---------------------------------------------------------------------------
// Hive lifecycle
// ---------------------------------------------------------------------------

/// Create an empty in-memory hive bound to `path` (nothing is written until
/// `libreg_hive_save`). On success `out_handle` receives a non-zero handle.
///
/// # Safety
/// `path` is a C string (see [`cstr`]); `out_handle` must be non-null/writable.
#[no_mangle]
pub unsafe extern "C" fn libreg_hive_create(
    path: *const c_char,
    out_handle: *mut u64,
) -> LibregStatus {
    guard(|| {
        if out_handle.is_null() {
            return Err(ApiError::bad_request("out_handle is null"));
        }
        let path = cstr(path, "path")?.to_owned();
        let handle = handle::insert(Hive::new_empty(), path);
        // SAFETY: out_handle checked non-null above.
        *out_handle = handle;
        Ok(())
    })
}

/// Load the hive file at `path`, binding the handle to that path for later
/// saves. On success `out_handle` receives a non-zero handle.
///
/// # Safety
/// `path` is a C string; `out_handle` must be non-null/writable.
#[no_mangle]
pub unsafe extern "C" fn libreg_hive_load(
    path: *const c_char,
    out_handle: *mut u64,
) -> LibregStatus {
    guard(|| {
        if out_handle.is_null() {
            return Err(ApiError::bad_request("out_handle is null"));
        }
        let path = cstr(path, "path")?.to_owned();
        let raw = std::fs::read(&path).map_err(|e| map_io(e, &path))?;
        let hive = Hive::from_file_bytes(&raw).map_err(ApiError::from)?;
        let handle = handle::insert(hive, path);
        // SAFETY: out_handle checked non-null above.
        *out_handle = handle;
        Ok(())
    })
}

/// Write the hive behind `handle` back to the path it is bound to.
#[no_mangle]
pub extern "C" fn libreg_hive_save(handle: u64) -> LibregStatus {
    guard(|| {
        handle::with_entry(handle, |entry| {
            if entry.path.is_empty() {
                return Err(ApiError::bad_request("hive has no path to save to"));
            }
            let bytes = entry.hive.to_file();
            std::fs::write(&entry.path, &bytes).map_err(|e| {
                ApiError::new(LibregStatus::Internal, format!("write {}: {e}", entry.path))
            })
        })
    })
}

/// Close `handle`, freeing the hive it owns. Using the handle afterward is
/// `HANDLE_INVALID`. Closing an unknown or already-closed handle is
/// `HANDLE_INVALID`.
#[no_mangle]
pub extern "C" fn libreg_hive_close(handle: u64) -> LibregStatus {
    guard(|| {
        if handle::remove(handle) {
            Ok(())
        } else {
            Err(ApiError::handle_invalid())
        }
    })
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// Create the key at `path`, creating intermediates (RegCreateKeyEx
/// semantics). Returns `KEY_EXISTS` when the leaf already exists, matching the
/// HTTP `/key/create` contract.
///
/// # Safety
/// `path` is a C string.
#[no_mangle]
pub unsafe extern "C" fn libreg_key_create(handle: u64, path: *const c_char) -> LibregStatus {
    guard(|| {
        let path = cstr(path, "path")?;
        handle::with_entry(handle, |entry| {
            if entry.hive.resolve(path)?.is_some() {
                return Err(ApiError::new(
                    LibregStatus::KeyExists,
                    format!("key already exists: {path}"),
                ));
            }
            entry.hive.create_key(path)?;
            Ok(())
        })
    })
}

/// Delete the key at `path`. With `recursive` zero, a key that still has
/// subkeys is rejected with `KEY_HAS_CHILDREN`; non-zero removes the subtree.
/// The root key cannot be deleted.
///
/// # Safety
/// `path` is a C string.
#[no_mangle]
pub unsafe extern "C" fn libreg_key_delete(
    handle: u64,
    path: *const c_char,
    recursive: c_int,
) -> LibregStatus {
    guard(|| {
        let path = cstr(path, "path")?;
        handle::with_entry(handle, |entry| {
            entry
                .hive
                .delete_key(path, recursive != 0)
                .map_err(ApiError::from)
        })
    })
}

/// List the subkey names of the key at `path` into a NUL-separated buffer (see
/// [`emit_names`]); `out_count` receives the number of names. Release the
/// buffer with [`libreg_free`].
///
/// # Safety
/// `path` is a C string; the out pointers must be non-null/writable.
#[no_mangle]
pub unsafe extern "C" fn libreg_key_list_subkeys(
    handle: u64,
    path: *const c_char,
    out_names: *mut *mut u8,
    out_len: *mut usize,
    out_count: *mut usize,
) -> LibregStatus {
    guard(|| {
        let path = cstr(path, "path")?;
        handle::with_entry(handle, |entry| {
            let names = entry.hive.subkeys(path)?;
            emit_names(&names, out_names, out_len, out_count)
        })
    })
}

/// List the value names of the key at `path`, like [`libreg_key_list_subkeys`].
///
/// # Safety
/// `path` is a C string; the out pointers must be non-null/writable.
#[no_mangle]
pub unsafe extern "C" fn libreg_key_list_values(
    handle: u64,
    path: *const c_char,
    out_names: *mut *mut u8,
    out_len: *mut usize,
    out_count: *mut usize,
) -> LibregStatus {
    guard(|| {
        let path = cstr(path, "path")?;
        handle::with_entry(handle, |entry| {
            let names = entry.hive.values(path)?;
            emit_names(&names, out_names, out_len, out_count)
        })
    })
}

/// Report the subkey and value counts of the key at `path`. Either out pointer
/// may be null to skip that count.
///
/// # Safety
/// `path` is a C string; non-null out pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn libreg_key_info(
    handle: u64,
    path: *const c_char,
    out_subkeys: *mut u64,
    out_values: *mut u64,
) -> LibregStatus {
    guard(|| {
        let path = cstr(path, "path")?;
        handle::with_entry(handle, |entry| {
            let subkeys = entry.hive.subkeys(path)?.len() as u64;
            let values = entry.hive.values(path)?.len() as u64;
            // SAFETY: each out pointer is written only after a null check.
            if !out_subkeys.is_null() {
                *out_subkeys = subkeys;
            }
            if !out_values.is_null() {
                *out_values = values;
            }
            Ok(())
        })
    })
}

/// Get the class name of the key at `path` as UTF-8 into `out_class`/`out_len`
/// (release with [`libreg_free`]). A length of 0 means the key has no class
/// (equivalently an empty class), so a consumer treats empty as absent, the
/// way the canonical form's `class_name` is null when absent. libreg's create
/// path never sets a class, so this is empty for created keys; it is meaningful
/// for keys read from a loaded hive.
///
/// # Safety
/// `path` is a C string; the out pointers must be non-null/writable.
#[no_mangle]
pub unsafe extern "C" fn libreg_key_class(
    handle: u64,
    path: *const c_char,
    out_class: *mut *mut u8,
    out_len: *mut usize,
) -> LibregStatus {
    guard(|| {
        let path = cstr(path, "path")?;
        handle::with_entry(handle, |entry| {
            let class = entry.hive.key_class(path)?.unwrap_or_default();
            emit_bytes(class.as_bytes(), out_class, out_len)
        })
    })
}

/// Deep-copy the key subtree at `src` to `dst` (both full paths) using public
/// operations: create `dst`, copy its security descriptor and its values, then
/// recurse into each subkey. This is how rename is emulated; libreg's logical
/// layer has no native rename, the same situation the HTTP agent emulates
/// around. Security is carried (CONTRACTS rename preserves the descriptor).
fn copy_subtree(hive: &mut Hive, src: &str, dst: &str) -> Result<(), ApiError> {
    hive.create_key(dst)?;
    hive.set_key_security(dst, hive.key_security(src)?)?;
    for vname in hive.values(src)? {
        if let Some((value_type, data)) = hive.get_value(src, &vname)? {
            hive.set_value(dst, &vname, value_type, &data)?;
        }
    }
    for sub in hive.subkeys(src)? {
        copy_subtree(hive, &format!("{src}\\{sub}"), &format!("{dst}\\{sub}"))?;
    }
    Ok(())
}

/// Rename the key at `path` to `new_name` (a single component, kept under the
/// same parent), preserving its values, security, and subtree. Emulated as
/// create + deep copy + delete, matching the oracle (libreg has no native
/// rename; CONTRACTS rename semantics). The renamed key's `last_write` is reset
/// by the copy, which the harness excludes from comparison for a renamed
/// subtree. Errors: `BAD_REQUEST` (empty `new_name`, a separator in it, or a
/// case-only rename, which a copy cannot emulate), `ACCESS_DENIED` (renaming
/// the root), `KEY_NOT_FOUND` (source missing), `KEY_EXISTS` (target taken).
///
/// NOTE: a source key's class name is not carried, since libreg cannot write a
/// class; created keys have none, so this only matters for a classed key read
/// from a loaded hive.
///
/// # Safety
/// `path` and `new_name` are C strings.
#[no_mangle]
pub unsafe extern "C" fn libreg_key_rename(
    handle: u64,
    path: *const c_char,
    new_name: *const c_char,
) -> LibregStatus {
    guard(|| {
        let path = cstr(path, "path")?;
        let new_name = cstr(new_name, "new_name")?;
        if new_name.is_empty() || new_name.contains('\\') {
            return Err(ApiError::bad_request(
                "new_name must be a single non-empty component",
            ));
        }
        if path.is_empty() {
            return Err(ApiError::new(
                LibregStatus::AccessDenied,
                "cannot rename the root key",
            ));
        }
        handle::with_entry(handle, |entry| {
            let hive = &mut entry.hive;
            if hive.resolve(path)?.is_none() {
                return Err(ApiError::new(
                    LibregStatus::KeyNotFound,
                    format!("key not found: {path}"),
                ));
            }
            // Same parent, new leaf; reject a case-only rename (libreg is
            // case-insensitive and has no in-place name update).
            let (parent, leaf) = match path.rfind('\\') {
                Some(i) => (&path[..i], &path[i + 1..]),
                None => ("", path),
            };
            if new_name.eq_ignore_ascii_case(leaf) {
                return Err(ApiError::bad_request("case-only rename is not supported"));
            }
            let new_path = if parent.is_empty() {
                new_name.to_string()
            } else {
                format!("{parent}\\{new_name}")
            };
            if hive.resolve(&new_path)?.is_some() {
                return Err(ApiError::new(
                    LibregStatus::KeyExists,
                    format!("key already exists: {new_path}"),
                ));
            }
            copy_subtree(hive, path, &new_path)?;
            hive.delete_key(path, true)?;
            Ok(())
        })
    })
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Set value `name` on the key at `key_path` to `data` of type `value_type` (a
/// REG_* code). `data`/`data_len` is raw binary, not base64. Creates or
/// replaces the value. The default value is the empty name `""`.
///
/// # Safety
/// `key_path` and `name` are C strings; `data`/`data_len` is a byte buffer.
#[no_mangle]
pub unsafe extern "C" fn libreg_value_set(
    handle: u64,
    key_path: *const c_char,
    name: *const c_char,
    value_type: u32,
    data: *const u8,
    data_len: usize,
) -> LibregStatus {
    guard(|| {
        let key_path = cstr(key_path, "key_path")?;
        let name = cstr(name, "name")?;
        let data = bytes(data, data_len)?;
        handle::with_entry(handle, |entry| {
            entry
                .hive
                .set_value(key_path, name, value_type, data)
                .map_err(ApiError::from)
        })
    })
}

/// Get value `name` from the key at `key_path`. `out_type` receives the REG_*
/// code; `out_data`/`out_len` receive a freshly allocated copy of the raw data
/// (release with [`libreg_free`]). A missing value is `VALUE_NOT_FOUND`.
///
/// # Safety
/// `key_path` and `name` are C strings; the out pointers must be
/// non-null/writable (`out_type` may be null to skip the type).
#[no_mangle]
pub unsafe extern "C" fn libreg_value_get(
    handle: u64,
    key_path: *const c_char,
    name: *const c_char,
    out_type: *mut u32,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> LibregStatus {
    guard(|| {
        let key_path = cstr(key_path, "key_path")?;
        let name = cstr(name, "name")?;
        handle::with_entry(handle, |entry| {
            match entry.hive.get_value(key_path, name)? {
                Some((value_type, data)) => {
                    // SAFETY: out_type written only after a null check; emit_bytes
                    // checks its own out pointers.
                    if !out_type.is_null() {
                        *out_type = value_type;
                    }
                    emit_bytes(&data, out_data, out_len)
                }
                None => Err(ApiError::new(
                    LibregStatus::ValueNotFound,
                    format!("value not found: {name}"),
                )),
            }
        })
    })
}

/// Delete value `name` from the key at `key_path`. A missing value is
/// `VALUE_NOT_FOUND`.
///
/// # Safety
/// `key_path` and `name` are C strings.
#[no_mangle]
pub unsafe extern "C" fn libreg_value_delete(
    handle: u64,
    key_path: *const c_char,
    name: *const c_char,
) -> LibregStatus {
    guard(|| {
        let key_path = cstr(key_path, "key_path")?;
        let name = cstr(name, "name")?;
        handle::with_entry(handle, |entry| {
            if entry.hive.delete_value(key_path, name)? {
                Ok(())
            } else {
                Err(ApiError::new(
                    LibregStatus::ValueNotFound,
                    format!("value not found: {name}"),
                ))
            }
        })
    })
}

// ---------------------------------------------------------------------------
// Security (binary self-relative descriptor; the consumer converts SDDL)
// ---------------------------------------------------------------------------

/// Get the binary self-relative security descriptor of the key at `path` into
/// `out_desc`/`out_len` (release with [`libreg_free`]). This is binary, not
/// SDDL: the binding or harness converts to/from SDDL (ADR 0003).
///
/// # Safety
/// `path` is a C string; the out pointers must be non-null/writable.
#[no_mangle]
pub unsafe extern "C" fn libreg_key_security_get(
    handle: u64,
    path: *const c_char,
    out_desc: *mut *mut u8,
    out_len: *mut usize,
) -> LibregStatus {
    guard(|| {
        let path = cstr(path, "path")?;
        handle::with_entry(handle, |entry| {
            let desc = entry.hive.key_security(path)?;
            emit_bytes(&desc, out_desc, out_len)
        })
    })
}

/// Set the security descriptor of the key at `path` to the binary
/// self-relative bytes `desc`/`desc_len`. Shares an existing identical
/// descriptor or allocates a new one (ref-counted), like the HTTP path.
///
/// # Safety
/// `path` is a C string; `desc`/`desc_len` is a byte buffer.
#[no_mangle]
pub unsafe extern "C" fn libreg_key_security_set(
    handle: u64,
    path: *const c_char,
    desc: *const u8,
    desc_len: usize,
) -> LibregStatus {
    guard(|| {
        let path = cstr(path, "path")?;
        let desc = bytes(desc, desc_len)?.to_vec();
        handle::with_entry(handle, |entry| {
            entry
                .hive
                .set_key_security(path, desc)
                .map_err(ApiError::from)
        })
    })
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Run structural validation of the hive behind `handle`. The problems are
/// returned as a NUL-separated name buffer (see [`emit_names`]); `out_count`
/// is the number of problems, so a count of 0 means the hive validates.
/// Release the buffer with [`libreg_free`].
///
/// # Safety
/// The out pointers must be non-null/writable.
#[no_mangle]
pub unsafe extern "C" fn libreg_validate(
    handle: u64,
    out_problems: *mut *mut u8,
    out_len: *mut usize,
    out_count: *mut usize,
) -> LibregStatus {
    guard(|| {
        handle::with_entry(handle, |entry| {
            let problems = entry.hive.validate();
            emit_names(&problems, out_problems, out_len, out_count)
        })
    })
}

#[cfg(test)]
mod tests;
