//! C ABI smoke test.
//!
//! Drives the exported `extern "C"` functions the way a C or `ctypes` caller
//! would: create a hive, write several REG_* types, read a security
//! descriptor, save, reload, and read back. This is the library-side half of
//! the issue #106 acceptance bar (the harness wires an FFI-driven backend for
//! the cross-agent semantic comparison; here we prove the surface itself).

use super::*;
use std::ffi::{CStr, CString};

// REG_* type codes (CONTRACTS values). libreg stores value data opaquely; the
// codes are passed through, so the test just round-trips them.
const REG_SZ: u32 = 1;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Drain a `(ptr, len)` buffer the library handed out into an owned vector and
/// free it through the library's allocator.
unsafe fn take_bytes(ptr: *mut u8, len: usize) -> Vec<u8> {
    let owned = std::slice::from_raw_parts(ptr, len).to_vec();
    libreg_free(ptr, len);
    owned
}

/// Split a NUL-separated name buffer into strings and free it, checking the
/// reported count matches.
unsafe fn take_names(ptr: *mut u8, len: usize, count: usize) -> Vec<String> {
    let raw = std::slice::from_raw_parts(ptr, len);
    let mut names = Vec::new();
    let mut start = 0;
    for (i, &b) in raw.iter().enumerate() {
        if b == 0 {
            names.push(String::from_utf8(raw[start..i].to_vec()).unwrap());
            start = i + 1;
        }
    }
    libreg_free(ptr, len);
    assert_eq!(
        names.len(),
        count,
        "reported count must match emitted names"
    );
    names
}

#[test]
fn c_abi_round_trips_a_hive() {
    unsafe {
        // The backend id matches the agent handshake string.
        let version = CStr::from_ptr(libreg_version()).to_str().unwrap();
        assert_eq!(version, "libreg-0.1.0");

        // A unique path so parallel test runs do not collide.
        let path = std::env::temp_dir().join(format!("libreg_c_abi_{}.hive", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cpath = cs(path.to_str().unwrap());

        // Create the hive and a nested key.
        let mut handle: u64 = 0;
        assert_eq!(
            libreg_hive_create(cpath.as_ptr(), &mut handle),
            LibregStatus::Ok
        );
        assert_ne!(handle, 0);

        let key = cs("Software\\Example");
        assert_eq!(libreg_key_create(handle, key.as_ptr()), LibregStatus::Ok);
        // Re-creating the leaf is KEY_EXISTS, matching the HTTP contract.
        assert_eq!(
            libreg_key_create(handle, key.as_ptr()),
            LibregStatus::KeyExists
        );

        // Write one value of each of several REG_* types.
        let values: &[(&str, u32, Vec<u8>)] = &[
            ("", REG_SZ, b"d\0e\0f\0a\0u\0l\0t\0\0\0".to_vec()),
            ("Dword", REG_DWORD, 0x1234_5678u32.to_le_bytes().to_vec()),
            (
                "Qword",
                REG_QWORD,
                0x1122_3344_5566_7788u64.to_le_bytes().to_vec(),
            ),
            ("Binary", REG_BINARY, vec![0, 1, 2, 0xfe, 0xff]),
            ("Multi", REG_MULTI_SZ, b"a\0\0b\0\0\0\0".to_vec()),
        ];
        for (name, ty, data) in values {
            let cname = cs(name);
            assert_eq!(
                libreg_value_set(
                    handle,
                    key.as_ptr(),
                    cname.as_ptr(),
                    *ty,
                    data.as_ptr(),
                    data.len()
                ),
                LibregStatus::Ok,
                "set {name}"
            );
        }

        // Read each back: type and raw bytes survive unchanged.
        for (name, ty, data) in values {
            let cname = cs(name);
            let mut got_type: u32 = 0;
            let mut out: *mut u8 = std::ptr::null_mut();
            let mut out_len: usize = 0;
            assert_eq!(
                libreg_value_get(
                    handle,
                    key.as_ptr(),
                    cname.as_ptr(),
                    &mut got_type,
                    &mut out,
                    &mut out_len
                ),
                LibregStatus::Ok,
                "get {name}"
            );
            assert_eq!(got_type, *ty, "type of {name}");
            assert_eq!(&take_bytes(out, out_len), data, "data of {name}");
        }

        // A missing value is VALUE_NOT_FOUND.
        let missing = cs("Nope");
        let mut t = 0u32;
        let mut p: *mut u8 = std::ptr::null_mut();
        let mut l = 0usize;
        assert_eq!(
            libreg_value_get(
                handle,
                key.as_ptr(),
                missing.as_ptr(),
                &mut t,
                &mut p,
                &mut l
            ),
            LibregStatus::ValueNotFound
        );

        // Value enumeration reports all five names.
        let mut np: *mut u8 = std::ptr::null_mut();
        let (mut nl, mut nc) = (0usize, 0usize);
        assert_eq!(
            libreg_key_list_values(handle, key.as_ptr(), &mut np, &mut nl, &mut nc),
            LibregStatus::Ok
        );
        let names = take_names(np, nl, nc);
        assert_eq!(names.len(), 5);
        for (name, _, _) in values {
            assert!(names.iter().any(|n| n == name), "missing value name {name}");
        }

        // Subkey enumeration and info counts.
        let software = cs("Software");
        let (mut sp, mut sl, mut sc) = (std::ptr::null_mut(), 0usize, 0usize);
        assert_eq!(
            libreg_key_list_subkeys(handle, software.as_ptr(), &mut sp, &mut sl, &mut sc),
            LibregStatus::Ok
        );
        assert_eq!(take_names(sp, sl, sc), vec!["Example".to_string()]);

        let (mut sub_n, mut val_n) = (0u64, 0u64);
        assert_eq!(
            libreg_key_info(handle, key.as_ptr(), &mut sub_n, &mut val_n),
            LibregStatus::Ok
        );
        assert_eq!((sub_n, val_n), (0, 5));

        // Security: read the root's binary descriptor, set it on the subkey,
        // read it back unchanged. (Binary, not SDDL: the consumer converts.)
        let root = cs("");
        let (mut dp, mut dl) = (std::ptr::null_mut(), 0usize);
        assert_eq!(
            libreg_key_security_get(handle, root.as_ptr(), &mut dp, &mut dl),
            LibregStatus::Ok
        );
        let descriptor = take_bytes(dp, dl);
        assert!(!descriptor.is_empty());
        assert_eq!(
            libreg_key_security_set(handle, key.as_ptr(), descriptor.as_ptr(), descriptor.len()),
            LibregStatus::Ok
        );
        let (mut gp, mut gl) = (std::ptr::null_mut(), 0usize);
        assert_eq!(
            libreg_key_security_get(handle, key.as_ptr(), &mut gp, &mut gl),
            LibregStatus::Ok
        );
        assert_eq!(take_bytes(gp, gl), descriptor);

        // The hive validates clean.
        let (mut vp, mut vl, mut vc) = (std::ptr::null_mut(), 0usize, 0usize);
        assert_eq!(
            libreg_validate(handle, &mut vp, &mut vl, &mut vc),
            LibregStatus::Ok
        );
        let problems = take_names(vp, vl, vc);
        assert!(
            problems.is_empty(),
            "unexpected validation problems: {problems:?}"
        );

        // Save, close, reload from disk, and confirm a value survived.
        assert_eq!(libreg_hive_save(handle), LibregStatus::Ok);
        assert_eq!(libreg_hive_close(handle), LibregStatus::Ok);
        // The handle is now invalid.
        assert_eq!(libreg_hive_save(handle), LibregStatus::HandleInvalid);

        let mut reloaded: u64 = 0;
        assert_eq!(
            libreg_hive_load(cpath.as_ptr(), &mut reloaded),
            LibregStatus::Ok
        );
        let dword = cs("Dword");
        let (mut rt, mut rp, mut rl) = (0u32, std::ptr::null_mut(), 0usize);
        assert_eq!(
            libreg_value_get(
                reloaded,
                key.as_ptr(),
                dword.as_ptr(),
                &mut rt,
                &mut rp,
                &mut rl
            ),
            LibregStatus::Ok
        );
        assert_eq!(rt, REG_DWORD);
        assert_eq!(take_bytes(rp, rl), 0x1234_5678u32.to_le_bytes());
        assert_eq!(libreg_hive_close(reloaded), LibregStatus::Ok);

        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn c_abi_reports_caller_errors() {
    unsafe {
        // An unknown handle is HANDLE_INVALID, not a panic.
        let key = cs("Any");
        assert_eq!(
            libreg_key_create(999_999, key.as_ptr()),
            LibregStatus::HandleInvalid
        );

        // A null path is BAD_REQUEST, and the last-error string is populated.
        let mut handle: u64 = 0;
        let path =
            std::env::temp_dir().join(format!("libreg_c_abi_err_{}.hive", std::process::id()));
        let cpath = cs(path.to_str().unwrap());
        assert_eq!(
            libreg_hive_create(cpath.as_ptr(), &mut handle),
            LibregStatus::Ok
        );
        assert_eq!(
            libreg_key_create(handle, std::ptr::null()),
            LibregStatus::BadRequest
        );
        let detail = CStr::from_ptr(libreg_last_error()).to_str().unwrap();
        assert!(
            detail.contains("null"),
            "last error should explain: {detail}"
        );

        // Loading a path that does not exist is HIVE_NOT_FOUND.
        let absent = cs("/nonexistent/libreg/path.hive");
        let mut h2: u64 = 0;
        assert_eq!(
            libreg_hive_load(absent.as_ptr(), &mut h2),
            LibregStatus::HiveNotFound
        );

        // Non-recursive delete of a key with children is KEY_HAS_CHILDREN.
        let parent = cs("A\\B");
        assert_eq!(libreg_key_create(handle, parent.as_ptr()), LibregStatus::Ok);
        let a = cs("A");
        assert_eq!(
            libreg_key_delete(handle, a.as_ptr(), 0),
            LibregStatus::KeyHasChildren
        );
        assert_eq!(libreg_key_delete(handle, a.as_ptr(), 1), LibregStatus::Ok);

        assert_eq!(libreg_hive_close(handle), LibregStatus::Ok);
    }
}
