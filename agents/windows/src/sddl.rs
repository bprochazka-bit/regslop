//! Security descriptor <-> SDDL string conversion via advapi32.
//!
//! Security descriptors transit the protocol as SDDL strings (CONTRACTS). The
//! agent holds them as offreg's self-relative binary form, so we convert at the
//! boundary.

use std::os::raw::c_void;
use std::ptr;

use crate::error::AgentError;
use crate::util::to_wide;
use crate::winapi::*;

/// Convert a self-relative security descriptor to an SDDL string covering the
/// given SECURITY_INFORMATION mask.
pub fn sd_to_sddl(sd: &[u8], sec_info: Dword) -> Result<String, AgentError> {
    let mut out_ptr: *mut u16 = ptr::null_mut();
    let mut out_len: Dword = 0;
    let rc = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd.as_ptr() as *const c_void,
            SDDL_REVISION_1,
            sec_info,
            &mut out_ptr,
            &mut out_len,
        )
    };
    if rc == 0 || out_ptr.is_null() {
        let err = unsafe { GetLastError() };
        return Err(AgentError::new(
            "INTERNAL",
            format!("ConvertSecurityDescriptorToStringSecurityDescriptorW failed (win32 {err})"),
        ));
    }
    // out_len can include trailing null padding beyond the actual string, so
    // cut at the first null rather than trusting the reported length.
    let raw = unsafe { std::slice::from_raw_parts(out_ptr, out_len as usize) };
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    let sddl = String::from_utf16_lossy(&raw[..end]);
    unsafe {
        LocalFree(out_ptr as *mut c_void);
    }
    Ok(sddl)
}

/// Convert an SDDL string to a self-relative security descriptor (owned bytes).
pub fn sddl_to_sd(sddl: &str) -> Result<Vec<u8>, AgentError> {
    let wsddl = to_wide(sddl);
    let mut sd_ptr: *mut c_void = ptr::null_mut();
    let mut sd_size: Dword = 0;
    let rc = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wsddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr,
            &mut sd_size,
        )
    };
    if rc == 0 || sd_ptr.is_null() {
        let err = unsafe { GetLastError() };
        return Err(AgentError::new(
            "INTERNAL",
            format!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed (win32 {err})"),
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(sd_ptr as *const u8, sd_size as usize) }.to_vec();
    unsafe {
        LocalFree(sd_ptr);
    }
    Ok(bytes)
}
