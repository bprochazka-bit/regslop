//! `FfiBackend`: a `Backend` implemented over libreg's Layer 4 C ABI (the
//! `libreg::api::*` entry points the cdylib exports, issue #106). It exists so
//! the harness can validate the C ABI by differential: run a shared operation
//! sequence through this backend and through the rlib-backed `LibregBackend`,
//! then compare canonical forms (issue #112). Because it reuses the agent's
//! existing `valuec` / `sddl` / `canonical` code to build the dump, the two
//! canonical forms match by construction, so any divergence is a real bug in the
//! C ABI surface (its enumeration or mutation primitives), not a codec artifact.
//!
//! The library agents link libreg by path, so these `extern "C"` functions are
//! called directly from Rust. That exercises the same boundary code the cdylib
//! exports (the panic guard, the process-global handle registry, the
//! status/error mapping); `docs/ffi-abi.md` allows driving the C ABI either way.
//! Every `unsafe` block is a documented FFI call into that boundary.

use crate::backend::Backend;
use crate::canonical;
use crate::error::{AgentError, Code, Result};
use crate::model::{self, Key, KeyInfo, Listing, Validation, Value};
use crate::valuec;
use libreg::api;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::ptr;
use std::sync::Mutex;

pub struct FfiBackend {
    backend_id: String,
    /// handle -> bound on-disk path, recorded at create/load so `hive_save`'s
    /// byte count and `checksum`'s file hash can read the saved file (the C ABI
    /// keeps the path internally and does not expose it).
    paths: Mutex<HashMap<u64, String>>,
}

impl FfiBackend {
    pub fn new(backend_id: impl Into<String>) -> Self {
        FfiBackend { backend_id: backend_id.into(), paths: Mutex::new(HashMap::new()) }
    }

    fn path_of(&self, handle: u64) -> Option<String> {
        self.paths.lock().unwrap().get(&handle).cloned()
    }
}

// --- status / error mapping ---

/// Map a C ABI status integer onto the agent's `Code`. The values are 1:1 with
/// the CONTRACTS error table (`libreg/include/libreg.h`), so this is positional.
fn code_from_status(status: i32) -> Code {
    match status {
        1 => Code::HiveNotFound,
        2 => Code::HiveCorrupt,
        3 => Code::HandleInvalid,
        4 => Code::KeyNotFound,
        5 => Code::KeyExists,
        6 => Code::ValueNotFound,
        7 => Code::TypeMismatch,
        8 => Code::AccessDenied,
        9 => Code::LogCorrupt,
        10 => Code::KeyHasChildren,
        11 => Code::BadRequest,
        _ => Code::Internal,
    }
}

/// This thread's last C ABI error detail (diagnostic only; the integer is the
/// contract). Empty when there was none.
fn last_error() -> String {
    // SAFETY: libreg_last_error returns a static-for-now thread-local C string,
    // valid until the next libreg call on this thread; we copy it immediately.
    unsafe {
        let p = api::libreg_last_error();
        if p.is_null() {
            String::new()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

/// Turn a returned status into a `Result`, attaching the last-error detail.
fn check(status: i32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(AgentError::new(code_from_status(status), last_error()))
    }
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| AgentError::bad_request("string contains an interior NUL"))
}

fn parse_handle(handle: &str) -> Result<u64> {
    handle.parse::<u64>().map_err(|_| AgentError::handle_invalid(handle))
}

/// Copy a `(ptr, len)` buffer the C ABI handed out, then free it with the exact
/// length, as the ownership rule requires.
///
/// # Safety
/// `ptr` is either null or a buffer of `len` bytes returned by a libreg call.
unsafe fn take_bytes(ptr: *mut u8, len: usize) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    let v = std::slice::from_raw_parts(ptr, len).to_vec();
    api::libreg_free(ptr, len);
    v
}

/// Copy and free a NUL-separated name buffer, returning exactly `count` names.
/// Registry names never contain an interior NUL, and the default value's empty
/// name is preserved (a leading or doubled NUL yields an empty entry).
///
/// # Safety
/// As `take_bytes`.
unsafe fn take_names(ptr: *mut u8, len: usize, count: usize) -> Vec<String> {
    let bytes = take_bytes(ptr, len);
    if count == 0 {
        return Vec::new();
    }
    let mut names: Vec<String> = bytes
        .split(|&b| b == 0)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    names.truncate(count); // drop the trailing empty from a terminating NUL
    names
}

fn sha256_hex(bytes: &[u8]) -> String {
    let out = Sha256::digest(bytes);
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// --- enumeration helpers (used by build_key) ---

fn list_subkeys(handle: u64, path: &str) -> Result<Vec<String>> {
    let cpath = cstr(path)?;
    let (mut ptr, mut len, mut count) = (ptr::null_mut(), 0usize, 0usize);
    // SAFETY: documented C ABI call; out pointers are writable; buffer is freed
    // by take_names.
    let st = unsafe {
        api::libreg_key_list_subkeys(handle, cpath.as_ptr(), &mut ptr, &mut len, &mut count) as i32
    };
    check(st)?;
    Ok(unsafe { take_names(ptr, len, count) })
}

fn list_values(handle: u64, path: &str) -> Result<Vec<String>> {
    let cpath = cstr(path)?;
    let (mut ptr, mut len, mut count) = (ptr::null_mut(), 0usize, 0usize);
    // SAFETY: as list_subkeys.
    let st = unsafe {
        api::libreg_key_list_values(handle, cpath.as_ptr(), &mut ptr, &mut len, &mut count) as i32
    };
    check(st)?;
    Ok(unsafe { take_names(ptr, len, count) })
}

/// Build a `model::Key` tree by walking the hive through the C ABI enumeration
/// primitives, so the agent's canonical serializer renders it exactly as it does
/// for `LibregBackend`. Mirrors `libreg_backend::build_key` but over the C ABI:
/// fixed `last_write`, null `class_name` (matching the rlib backend's dump),
/// values via `valuec`, security via `sddl`.
fn build_key(handle: u64, name: &str, path: &str) -> Result<Key> {
    let mut key = Key::new(name);
    let cpath = cstr(path)?;

    // Security: binary self-relative descriptor -> SDDL (the agent's converter).
    let (mut dptr, mut dlen) = (ptr::null_mut(), 0usize);
    // SAFETY: documented C ABI call; out pointers writable; buffer freed below.
    let st = unsafe { api::libreg_key_security_get(handle, cpath.as_ptr(), &mut dptr, &mut dlen) as i32 };
    check(st)?;
    let desc = unsafe { take_bytes(dptr, dlen) };
    key.security_sddl = crate::sddl::to_sddl(&desc)?;

    // Values: each (type, raw bytes) decoded via valuec, exactly as the rlib path.
    for vname in list_values(handle, path)? {
        let cname = cstr(&vname)?;
        let mut ty: u32 = 0;
        let (mut vptr, mut vlen) = (ptr::null_mut(), 0usize);
        // SAFETY: documented C ABI call; out pointers writable; buffer freed below.
        let st = unsafe {
            api::libreg_value_get(handle, cpath.as_ptr(), cname.as_ptr(), &mut ty, &mut vptr, &mut vlen) as i32
        };
        check(st)?;
        let bytes = unsafe { take_bytes(vptr, vlen) };
        key.values.push(Value {
            name: vname,
            vtype: valuec::type_name(ty).to_string(),
            data: valuec::decode(ty, &bytes),
        });
    }

    // Subkeys: recurse. The canonical serializer sorts, so order here is free.
    for sub in list_subkeys(handle, path)? {
        let child = if path.is_empty() { sub.clone() } else { format!("{path}\\{sub}") };
        key.subkeys.push(build_key(handle, &sub, &child)?);
    }
    Ok(key)
}

impl Backend for FfiBackend {
    fn backend_id(&self) -> String {
        self.backend_id.clone()
    }

    fn hive_create(&self, path: &str) -> Result<String> {
        let cpath = cstr(path)?;
        let mut h: u64 = 0;
        // SAFETY: documented C ABI call; out_handle is writable.
        let st = unsafe { api::libreg_hive_create(cpath.as_ptr(), &mut h) as i32 };
        check(st)?;
        self.paths.lock().unwrap().insert(h, path.to_string());
        Ok(h.to_string())
    }

    fn hive_load(&self, path: &str) -> Result<String> {
        let cpath = cstr(path)?;
        let mut h: u64 = 0;
        // SAFETY: documented C ABI call; out_handle is writable.
        let st = unsafe { api::libreg_hive_load(cpath.as_ptr(), &mut h) as i32 };
        check(st)?;
        self.paths.lock().unwrap().insert(h, path.to_string());
        Ok(h.to_string())
    }

    fn hive_save(&self, handle: &str) -> Result<u64> {
        let h = parse_handle(handle)?;
        let st = api::libreg_hive_save(h) as i32;
        check(st)?;
        // The C ABI save reports no byte count; read the file it wrote (the
        // differential does not compare this number, but keep it faithful).
        Ok(self.path_of(h).and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len()).unwrap_or(0))
    }

    fn crash_save(&self, _handle: &str, _point: &str) -> Result<u64> {
        // The C ABI save writes a clean primary only; mid-save crash injection is
        // not on the boundary. Recovery is exercised against the libreg backend.
        Err(AgentError::new(Code::Internal, "crash_save is only supported by the libreg backend"))
    }

    fn hive_close(&self, handle: &str) -> Result<()> {
        let h = parse_handle(handle)?;
        let st = api::libreg_hive_close(h) as i32;
        check(st)?;
        self.paths.lock().unwrap().remove(&h);
        Ok(())
    }

    fn key_create(&self, handle: &str, path: &str) -> Result<()> {
        // Agent-edge path validation, exactly as the other backends do it: a
        // malformed path (e.g. a leading separator) is BAD_REQUEST (CONTRACTS
        // 0.1.4). The C ABI's libreg_key_create is lenient here (it would create
        // a spurious key), so without this the FFI hive diverges from the agent's.
        // Note: a direct C ABI consumer (the Python binding) must validate paths
        // itself; flagged for the binding/spec.
        crate::model::Key::split_path(path)?;
        let h = parse_handle(handle)?;
        let cpath = cstr(path)?;
        // SAFETY: documented C ABI call.
        check(unsafe { api::libreg_key_create(h, cpath.as_ptr()) as i32 })
    }

    fn key_delete(&self, handle: &str, path: &str, recursive: bool) -> Result<()> {
        let h = parse_handle(handle)?;
        let cpath = cstr(path)?;
        // SAFETY: documented C ABI call.
        check(unsafe { api::libreg_key_delete(h, cpath.as_ptr(), recursive as c_int) as i32 })
    }

    fn key_rename(&self, handle: &str, path: &str, new_name: &str) -> Result<()> {
        let h = parse_handle(handle)?;
        let cpath = cstr(path)?;
        let cnew = cstr(new_name)?;
        // SAFETY: documented C ABI call.
        check(unsafe { api::libreg_key_rename(h, cpath.as_ptr(), cnew.as_ptr()) as i32 })
    }

    fn key_list(&self, handle: &str, path: &str) -> Result<Listing> {
        let h = parse_handle(handle)?;
        let mut subkeys = list_subkeys(h, path)?;
        let mut values = list_values(h, path)?;
        // Case-insensitive Unicode ordinal order, matching the libreg backend.
        subkeys.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));
        values.sort_by(|a, b| a.to_uppercase().cmp(&b.to_uppercase()));
        Ok(Listing { subkeys, values })
    }

    fn key_info(&self, handle: &str, path: &str) -> Result<KeyInfo> {
        let h = parse_handle(handle)?;
        let cpath = cstr(path)?;
        let (mut subkeys, mut values): (u64, u64) = (0, 0);
        // SAFETY: documented C ABI call; both out pointers writable.
        let st = unsafe { api::libreg_key_info(h, cpath.as_ptr(), &mut subkeys, &mut values) as i32 };
        check(st)?;
        Ok(KeyInfo {
            // last_write and class_name are not on the C ABI; emit the same fixed
            // / null values the libreg backend's dump uses (the differ ignores
            // last_write, and the rlib backend reports class_name null too).
            last_write: model::FIXED_LAST_WRITE.to_string(),
            class_name: None,
            subkey_count: subkeys as usize,
            value_count: values as usize,
        })
    }

    fn value_set(&self, handle: &str, key: &str, name: &str, vtype: &str, data: &serde_json::Value) -> Result<()> {
        let h = parse_handle(handle)?;
        let (type_code, bytes) = valuec::encode(vtype, data)?;
        let ckey = cstr(key)?;
        let cname = cstr(name)?;
        // SAFETY: documented C ABI call; data/len describe `bytes`.
        check(unsafe {
            api::libreg_value_set(h, ckey.as_ptr(), cname.as_ptr(), type_code, bytes.as_ptr(), bytes.len()) as i32
        })
    }

    fn value_delete(&self, handle: &str, key: &str, name: &str) -> Result<()> {
        let h = parse_handle(handle)?;
        let ckey = cstr(key)?;
        let cname = cstr(name)?;
        // SAFETY: documented C ABI call.
        check(unsafe { api::libreg_value_delete(h, ckey.as_ptr(), cname.as_ptr()) as i32 })
    }

    fn value_get(&self, handle: &str, key: &str, name: &str) -> Result<Value> {
        let h = parse_handle(handle)?;
        let ckey = cstr(key)?;
        let cname = cstr(name)?;
        let mut ty: u32 = 0;
        let (mut vptr, mut vlen) = (ptr::null_mut(), 0usize);
        // SAFETY: documented C ABI call; out pointers writable; buffer freed below.
        let st = unsafe {
            api::libreg_value_get(h, ckey.as_ptr(), cname.as_ptr(), &mut ty, &mut vptr, &mut vlen) as i32
        };
        check(st)?;
        let bytes = unsafe { take_bytes(vptr, vlen) };
        Ok(Value { name: name.to_string(), vtype: valuec::type_name(ty).to_string(), data: valuec::decode(ty, &bytes) })
    }

    fn security_get(&self, handle: &str, path: &str) -> Result<String> {
        let h = parse_handle(handle)?;
        let cpath = cstr(path)?;
        let (mut dptr, mut dlen) = (ptr::null_mut(), 0usize);
        // SAFETY: documented C ABI call; out pointers writable; buffer freed below.
        let st = unsafe { api::libreg_key_security_get(h, cpath.as_ptr(), &mut dptr, &mut dlen) as i32 };
        check(st)?;
        let desc = unsafe { take_bytes(dptr, dlen) };
        crate::sddl::to_sddl(&desc)
    }

    fn security_set(&self, handle: &str, path: &str, sddl: &str) -> Result<()> {
        let h = parse_handle(handle)?;
        let desc = crate::sddl::from_sddl(sddl)?;
        let cpath = cstr(path)?;
        // SAFETY: documented C ABI call; desc/len describe `desc`.
        check(unsafe { api::libreg_key_security_set(h, cpath.as_ptr(), desc.as_ptr(), desc.len()) as i32 })
    }

    fn dump(&self, handle: &str) -> Result<serde_json::Value> {
        let h = parse_handle(handle)?;
        Ok(canonical::canonical_hive(&build_key(h, "", "")?))
    }

    fn checksum(&self, handle: &str) -> Result<(String, String)> {
        let h = parse_handle(handle)?;
        let canon = canonical::canonical_hive(&build_key(h, "", "")?);
        let file_hash = match self.path_of(h).and_then(|p| std::fs::read(p).ok()) {
            Some(bytes) => sha256_hex(&bytes),
            None => sha256_hex(b""),
        };
        Ok((file_hash, sha256_hex(canon.to_string().as_bytes())))
    }

    fn validate(&self, handle: &str) -> Result<Validation> {
        let h = parse_handle(handle)?;
        let (mut ptr, mut len, mut count) = (ptr::null_mut(), 0usize, 0usize);
        // SAFETY: documented C ABI call; out pointers writable; buffer freed below.
        let st = unsafe { api::libreg_validate(h, &mut ptr, &mut len, &mut count) as i32 };
        check(st)?;
        let problems = unsafe { take_names(ptr, len, count) };
        Ok(Validation { valid: problems.is_empty(), errors: problems, warnings: Vec::new() })
    }
}
