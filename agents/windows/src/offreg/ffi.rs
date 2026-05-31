//! Raw FFI surface for offreg.dll.
//!
//! offreg.dll ships with the Windows ADK Deployment Tools, not the base OS, and
//! no import library is available on our Linux build host. So we load it
//! dynamically with LoadLibraryW/GetProcAddress at startup and keep the
//! resolved function pointers in [`Offreg`].
//!
//! All offreg functions return a Win32 error DWORD (ERROR_SUCCESS on success).

use std::os::raw::c_void;

use crate::util::to_wide;
use crate::winapi::{Dword, GetProcAddress, LoadLibraryW};

/// Opaque offline-registry key handle. The root handle returned by
/// OROpenHive/ORCreateHive doubles as the hive handle.
pub type Orhkey = *mut c_void;
pub type Porhkey = *mut Orhkey;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Filetime {
    pub low: u32,
    pub high: u32,
}

// Registry value type constants (winnt.h).
pub const REG_NONE: Dword = 0;
pub const REG_SZ: Dword = 1;
pub const REG_EXPAND_SZ: Dword = 2;
pub const REG_BINARY: Dword = 3;
pub const REG_DWORD: Dword = 4; // little-endian
pub const REG_DWORD_BIG_ENDIAN: Dword = 5;
pub const REG_LINK: Dword = 6;
pub const REG_MULTI_SZ: Dword = 7;
pub const REG_RESOURCE_LIST: Dword = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: Dword = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: Dword = 10;
pub const REG_QWORD: Dword = 11;

type FnOpenHive = unsafe extern "system" fn(*const u16, Porhkey) -> Dword;
type FnCreateHive = unsafe extern "system" fn(Porhkey) -> Dword;
type FnCloseHive = unsafe extern "system" fn(Orhkey) -> Dword;
type FnSaveHive = unsafe extern "system" fn(Orhkey, *const u16, Dword, Dword) -> Dword;
type FnOpenKey = unsafe extern "system" fn(Orhkey, *const u16, Porhkey) -> Dword;
type FnCreateKey = unsafe extern "system" fn(
    Orhkey,
    *const u16,        // subkey
    *const u16,        // class (may be null)
    Dword,             // options
    *const c_void,     // security descriptor (may be null)
    Porhkey,           // out key
    *mut Dword,        // disposition out
) -> Dword;
type FnCloseKey = unsafe extern "system" fn(Orhkey) -> Dword;
type FnDeleteKey = unsafe extern "system" fn(Orhkey, *const u16) -> Dword;
type FnDeleteValue = unsafe extern "system" fn(Orhkey, *const u16) -> Dword;
type FnSetValue =
    unsafe extern "system" fn(Orhkey, *const u16, Dword, *const u8, Dword) -> Dword;
type FnGetValue = unsafe extern "system" fn(
    Orhkey,
    *const u16, // subkey (may be null = this key)
    *const u16, // value name
    *mut Dword, // type out
    *mut c_void, // data out
    *mut Dword,  // data size in/out
) -> Dword;
type FnEnumKey = unsafe extern "system" fn(
    Orhkey,
    Dword,         // index
    *mut u16,      // name out
    *mut Dword,    // name len in/out
    *mut u16,      // class out (may be null)
    *mut Dword,    // class len in/out (may be null)
    *mut Filetime, // last write out (may be null)
) -> Dword;
type FnEnumValue = unsafe extern "system" fn(
    Orhkey,
    Dword,      // index
    *mut u16,   // value name out
    *mut Dword, // value name len in/out
    *mut Dword, // type out (may be null)
    *mut u8,    // data out (may be null)
    *mut Dword, // data size in/out (may be null)
) -> Dword;
type FnQueryInfoKey = unsafe extern "system" fn(
    Orhkey,
    *mut u16,      // class out
    *mut Dword,    // class len in/out
    *mut Dword,    // subkey count
    *mut Dword,    // max subkey name len
    *mut Dword,    // max class len
    *mut Dword,    // value count
    *mut Dword,    // max value name len
    *mut Dword,    // max value data len
    *mut Dword,    // security descriptor len
    *mut Filetime, // last write
) -> Dword;
type FnGetKeySecurity =
    unsafe extern "system" fn(Orhkey, Dword, *mut c_void, *mut Dword) -> Dword;
type FnSetKeySecurity = unsafe extern "system" fn(Orhkey, Dword, *const c_void) -> Dword;

/// Resolved offreg.dll entry points. Built once at startup via [`Offreg::load`].
///
/// All fields are plain function pointers, which are `Send + Sync`, so the
/// struct can live in a global and be shared across request threads. offreg
/// itself is not thread-safe, but the handle registry serializes calls per
/// hive handle.
pub struct Offreg {
    pub open_hive: FnOpenHive,
    pub create_hive: FnCreateHive,
    pub close_hive: FnCloseHive,
    pub save_hive: FnSaveHive,
    pub open_key: FnOpenKey,
    pub create_key: FnCreateKey,
    pub close_key: FnCloseKey,
    pub delete_key: FnDeleteKey,
    pub delete_value: FnDeleteValue,
    pub set_value: FnSetValue,
    pub get_value: FnGetValue,
    pub enum_key: FnEnumKey,
    pub enum_value: FnEnumValue,
    // offreg names this ORQueryInfoKey (mirrors RegQueryInfoKey), not GetKeyInfo.
    pub query_info_key: FnQueryInfoKey,
    pub get_key_security: FnGetKeySecurity,
    pub set_key_security: FnSetKeySecurity,
}

macro_rules! resolve {
    ($module:expr, $name:literal) => {{
        // GetProcAddress takes an ANSI, null-terminated symbol name.
        let cname = concat!($name, "\0");
        let proc = GetProcAddress($module, cname.as_ptr());
        if proc.is_null() {
            return Err(format!("offreg.dll is missing export {}", $name));
        }
        std::mem::transmute(proc)
    }};
}

impl Offreg {
    /// Load offreg.dll and resolve every entry point. Returns a human-readable
    /// error if the DLL or any export is missing (for example when the ADK
    /// Deployment Tools are not installed on the VM).
    pub fn load() -> Result<Offreg, String> {
        let name = to_wide("offreg.dll");
        unsafe {
            let module = LoadLibraryW(name.as_ptr());
            if module.is_null() {
                return Err(
                    "could not load offreg.dll (install the Windows ADK Deployment Tools)"
                        .to_string(),
                );
            }
            Ok(Offreg {
                open_hive: resolve!(module, "OROpenHive"),
                create_hive: resolve!(module, "ORCreateHive"),
                close_hive: resolve!(module, "ORCloseHive"),
                save_hive: resolve!(module, "ORSaveHive"),
                open_key: resolve!(module, "OROpenKey"),
                create_key: resolve!(module, "ORCreateKey"),
                close_key: resolve!(module, "ORCloseKey"),
                delete_key: resolve!(module, "ORDeleteKey"),
                delete_value: resolve!(module, "ORDeleteValue"),
                set_value: resolve!(module, "ORSetValue"),
                get_value: resolve!(module, "ORGetValue"),
                enum_key: resolve!(module, "OREnumKey"),
                enum_value: resolve!(module, "OREnumValue"),
                query_info_key: resolve!(module, "ORQueryInfoKey"),
                get_key_security: resolve!(module, "ORGetKeySecurity"),
                set_key_security: resolve!(module, "ORSetKeySecurity"),
            })
        }
    }
}
