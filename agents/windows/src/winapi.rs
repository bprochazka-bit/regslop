//! Minimal raw FFI to kernel32 and advapi32.
//!
//! These two DLLs ship with every Windows install and are linked through the
//! mingw import libraries at build time, so unlike offreg they need no dynamic
//! loading. We only declare the handful of symbols the agent actually calls.

use std::os::raw::c_void;

pub type Dword = u32;
pub type Bool = i32;
pub type Hmodule = *mut c_void;
pub type Farproc = *mut c_void;

// SDDL revision passed to the security descriptor conversion helpers.
pub const SDDL_REVISION_1: Dword = 1;

// SECURITY_INFORMATION bits.
pub const OWNER_SECURITY_INFORMATION: Dword = 0x0000_0001;
pub const GROUP_SECURITY_INFORMATION: Dword = 0x0000_0002;
pub const DACL_SECURITY_INFORMATION: Dword = 0x0000_0004;
pub const SACL_SECURITY_INFORMATION: Dword = 0x0000_0008;

// Win32 error codes we map onto CONTRACTS error codes.
pub const ERROR_SUCCESS: Dword = 0;
pub const ERROR_FILE_NOT_FOUND: Dword = 2;
pub const ERROR_PATH_NOT_FOUND: Dword = 3;
pub const ERROR_ACCESS_DENIED: Dword = 5;
pub const ERROR_INVALID_HANDLE: Dword = 6;
pub const ERROR_INSUFFICIENT_BUFFER: Dword = 122;
pub const ERROR_INVALID_PARAMETER: Dword = 87;
pub const ERROR_ALREADY_EXISTS: Dword = 183;
pub const ERROR_MORE_DATA: Dword = 234;
pub const ERROR_NO_MORE_ITEMS: Dword = 259;

#[link(name = "kernel32")]
extern "system" {
    pub fn LoadLibraryW(name: *const u16) -> Hmodule;
    pub fn GetProcAddress(module: Hmodule, name: *const u8) -> Farproc;
    pub fn GetLastError() -> Dword;
}

#[link(name = "advapi32")]
extern "system" {
    /// Self-relative security descriptor -> SDDL string (LocalFree the result).
    pub fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        security_descriptor: *const c_void,
        request_revision: Dword,
        security_information: Dword,
        string_out: *mut *mut u16,
        string_len_out: *mut Dword,
    ) -> Bool;

    /// SDDL string -> self-relative security descriptor (LocalFree the result).
    pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        revision: Dword,
        security_descriptor_out: *mut *mut c_void,
        security_descriptor_size_out: *mut Dword,
    ) -> Bool;

    pub fn LocalFree(mem: *mut c_void) -> *mut c_void;
}
