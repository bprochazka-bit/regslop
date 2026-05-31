//! RAII wrapper around an offline registry key handle plus the value and
//! enumeration operations layered on top of it.
//!
//! A [`Key`] is either *owned* (obtained from OROpenKey/ORCreateKey and closed
//! on drop) or a non-owning reference to a hive root (closed by the owning
//! `Hive`, never here). Path resolution always starts from a hive root handle.

use std::os::raw::c_void;
use std::ptr;

use crate::error::{map_win32, AgentError, Ctx};
use crate::offreg::{offreg, Filetime, Orhkey};
use crate::util::{from_wide_exact, to_wide};
use crate::winapi::*;

// Disposition values returned by ORCreateKey.
const REG_CREATED_NEW_KEY: Dword = 1;

/// Aggregate facts about a key from ORGetKeyInfo.
pub struct KeyInfo {
    pub subkey_count: u32,
    pub value_count: u32,
    pub last_write: Filetime,
    pub class: Option<String>,
    pub max_subkey_name: u32,
    pub max_value_name: u32,
    pub max_value_data: u32,
}

pub struct Key {
    handle: Orhkey,
    owned: bool,
}

unsafe impl Send for Key {}

impl Key {
    /// Borrow a hive root handle as a key without taking ownership of it.
    pub fn root_ref(root: Orhkey) -> Key {
        Key {
            handle: root,
            owned: false,
        }
    }

    /// Open a key by path relative to `root`. An empty path resolves to the
    /// root itself (returned as a non-owning reference).
    pub fn open(root: Orhkey, path: &str) -> Result<Key, AgentError> {
        if path.is_empty() {
            return Ok(Key::root_ref(root));
        }
        let wpath = to_wide(path);
        let mut out: Orhkey = ptr::null_mut();
        let rc = unsafe { (offreg().open_key)(root, wpath.as_ptr(), &mut out) };
        if rc != ERROR_SUCCESS {
            return Err(map_win32(rc, Ctx::Key));
        }
        Ok(Key {
            handle: out,
            owned: true,
        })
    }

    /// Create (or open) a key by path relative to `root`. Returns the key and
    /// whether the leaf was newly created (false means it already existed).
    ///
    /// Unlike RegCreateKeyEx, offreg's ORCreateKey does not create intermediate
    /// keys (a multi-level path with a missing parent fails with error 2), so we
    /// create each level in turn. Each cumulative path is created from `root`;
    /// its immediate parent exists because the prior iteration made it.
    pub fn create(root: Orhkey, path: &str) -> Result<(Key, bool), AgentError> {
        let components: Vec<&str> = path.split('\\').filter(|c| !c.is_empty()).collect();
        if components.is_empty() {
            return Ok((Key::root_ref(root), false));
        }

        let mut accum = String::new();
        for (i, comp) in components.iter().enumerate() {
            if !accum.is_empty() {
                accum.push('\\');
            }
            accum.push_str(comp);

            let wpath = to_wide(&accum);
            let mut out: Orhkey = ptr::null_mut();
            let mut disposition: Dword = 0;
            let rc = unsafe {
                (offreg().create_key)(
                    root,
                    wpath.as_ptr(),
                    ptr::null(), // no class
                    0,           // REG_OPTION_NON_VOLATILE
                    ptr::null(), // default security
                    &mut out,
                    &mut disposition,
                )
            };
            if rc != ERROR_SUCCESS {
                return Err(map_win32(rc, Ctx::Key));
            }

            if i == components.len() - 1 {
                return Ok((
                    Key {
                        handle: out,
                        owned: true,
                    },
                    disposition == REG_CREATED_NEW_KEY,
                ));
            }
            // Intermediate level: close its handle and continue.
            unsafe {
                (offreg().close_key)(out);
            }
        }
        unreachable!("loop returns on the final component")
    }

    pub fn info(&self) -> Result<KeyInfo, AgentError> {
        let mut class_len: Dword = 0;
        let mut subkeys: Dword = 0;
        let mut max_subkey: Dword = 0;
        let mut max_class: Dword = 0;
        let mut values: Dword = 0;
        let mut max_vname: Dword = 0;
        let mut max_vdata: Dword = 0;
        let mut sd_len: Dword = 0;
        let mut ft = Filetime::default();

        // First pass: counts and the class string length (with a null class
        // buffer ORGetKeyInfo reports the required length without copying).
        let rc = unsafe {
            (offreg().query_info_key)(
                self.handle,
                ptr::null_mut(),
                &mut class_len,
                &mut subkeys,
                &mut max_subkey,
                &mut max_class,
                &mut values,
                &mut max_vname,
                &mut max_vdata,
                &mut sd_len,
                &mut ft,
            )
        };
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA && rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(map_win32(rc, Ctx::Key));
        }

        let class = if class_len > 0 {
            let cap = class_len as usize + 1;
            let mut buf = vec![0u16; cap];
            let mut cl = cap as Dword;
            let rc2 = unsafe {
                (offreg().query_info_key)(
                    self.handle,
                    buf.as_mut_ptr(),
                    &mut cl,
                    &mut subkeys,
                    &mut max_subkey,
                    &mut max_class,
                    &mut values,
                    &mut max_vname,
                    &mut max_vdata,
                    &mut sd_len,
                    &mut ft,
                )
            };
            if rc2 != ERROR_SUCCESS {
                return Err(map_win32(rc2, Ctx::Key));
            }
            Some(from_wide_exact(&buf, cl as usize))
        } else {
            None
        };

        Ok(KeyInfo {
            subkey_count: subkeys,
            value_count: values,
            last_write: ft,
            class,
            max_subkey_name: max_subkey,
            max_value_name: max_vname,
            max_value_data: max_vdata,
        })
    }

    /// Enumerate immediate subkeys as (name, last_write), in offreg's order.
    pub fn enum_subkeys(&self) -> Result<Vec<(String, Filetime)>, AgentError> {
        let info = self.info()?;
        let cap = (info.max_subkey_name as usize).max(256) + 1;
        let mut out = Vec::with_capacity(info.subkey_count as usize);
        let mut idx: Dword = 0;
        loop {
            let mut name = vec![0u16; cap];
            let mut name_len = cap as Dword;
            let mut ft = Filetime::default();
            let rc = unsafe {
                (offreg().enum_key)(
                    self.handle,
                    idx,
                    name.as_mut_ptr(),
                    &mut name_len,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut ft,
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                return Err(map_win32(rc, Ctx::Key));
            }
            out.push((from_wide_exact(&name, name_len as usize), ft));
            idx += 1;
        }
        Ok(out)
    }

    /// Enumerate values as (name, type, raw bytes), in offreg's order.
    pub fn enum_values(&self) -> Result<Vec<(String, u32, Vec<u8>)>, AgentError> {
        let info = self.info()?;
        let ncap = (info.max_value_name as usize).max(256) + 1;
        let dcap = (info.max_value_data as usize).max(1);
        let mut out = Vec::with_capacity(info.value_count as usize);
        let mut idx: Dword = 0;
        loop {
            let mut name = vec![0u16; ncap];
            let mut name_len = ncap as Dword;
            let mut ty: Dword = 0;
            let mut data = vec![0u8; dcap];
            let mut data_len = dcap as Dword;
            let rc = unsafe {
                (offreg().enum_value)(
                    self.handle,
                    idx,
                    name.as_mut_ptr(),
                    &mut name_len,
                    &mut ty,
                    data.as_mut_ptr(),
                    &mut data_len,
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc != ERROR_SUCCESS {
                return Err(map_win32(rc, Ctx::Value));
            }
            data.truncate(data_len as usize);
            out.push((from_wide_exact(&name, name_len as usize), ty, data));
            idx += 1;
        }
        Ok(out)
    }

    /// Read a single value by name. The default value is name "".
    pub fn get_value(&self, name: &str) -> Result<(u32, Vec<u8>), AgentError> {
        let wname = to_wide(name);
        let mut ty: Dword = 0;
        let mut size: Dword = 0;
        let rc = unsafe {
            (offreg().get_value)(
                self.handle,
                ptr::null(),
                wname.as_ptr(),
                &mut ty,
                ptr::null_mut(),
                &mut size,
            )
        };
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA && rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(map_win32(rc, Ctx::Value));
        }
        let mut buf = vec![0u8; size as usize];
        if size > 0 {
            let rc2 = unsafe {
                (offreg().get_value)(
                    self.handle,
                    ptr::null(),
                    wname.as_ptr(),
                    &mut ty,
                    buf.as_mut_ptr() as *mut c_void,
                    &mut size,
                )
            };
            if rc2 != ERROR_SUCCESS {
                return Err(map_win32(rc2, Ctx::Value));
            }
            buf.truncate(size as usize);
        }
        Ok((ty, buf))
    }

    /// Set a value. An empty payload passes a null data pointer, which offreg
    /// accepts (used for REG_NONE).
    pub fn set_value(&self, name: &str, ty: u32, data: &[u8]) -> Result<(), AgentError> {
        let wname = to_wide(name);
        let data_ptr = if data.is_empty() {
            ptr::null()
        } else {
            data.as_ptr()
        };
        let rc = unsafe {
            (offreg().set_value)(self.handle, wname.as_ptr(), ty, data_ptr, data.len() as Dword)
        };
        if rc != ERROR_SUCCESS {
            return Err(map_win32(rc, Ctx::Value));
        }
        Ok(())
    }

    pub fn delete_value(&self, name: &str) -> Result<(), AgentError> {
        let wname = to_wide(name);
        let rc = unsafe { (offreg().delete_value)(self.handle, wname.as_ptr()) };
        if rc != ERROR_SUCCESS {
            return Err(map_win32(rc, Ctx::Value));
        }
        Ok(())
    }

    /// Read the self-relative security descriptor bytes for the requested
    /// SECURITY_INFORMATION mask.
    pub fn get_security(&self, sec_info: Dword) -> Result<Vec<u8>, AgentError> {
        let mut size: Dword = 0;
        let rc = unsafe {
            (offreg().get_key_security)(self.handle, sec_info, ptr::null_mut(), &mut size)
        };
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA && rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(map_win32(rc, Ctx::Security));
        }
        let mut buf = vec![0u8; size as usize];
        let rc2 = unsafe {
            (offreg().get_key_security)(
                self.handle,
                sec_info,
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
            )
        };
        if rc2 != ERROR_SUCCESS {
            return Err(map_win32(rc2, Ctx::Security));
        }
        buf.truncate(size as usize);
        Ok(buf)
    }

    /// Apply a self-relative security descriptor for the requested mask.
    pub fn set_security(&self, sec_info: Dword, sd: &[u8]) -> Result<(), AgentError> {
        let rc = unsafe {
            (offreg().set_key_security)(self.handle, sec_info, sd.as_ptr() as *const c_void)
        };
        if rc != ERROR_SUCCESS {
            return Err(map_win32(rc, Ctx::Security));
        }
        Ok(())
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        if self.owned {
            unsafe {
                (offreg().close_key)(self.handle);
            }
        }
    }
}

/// Delete `path` (relative to `root`). offreg's ORDeleteKey will not remove a
/// key that still has subkeys, so recursive deletion is done depth-first here.
/// Non-recursive deletion of a key with children is refused with KEY_EXISTS-
/// style semantics surfaced as an error by the caller.
pub fn delete_key(root: Orhkey, path: &str, recursive: bool) -> Result<(), AgentError> {
    if recursive {
        // Enumerate and delete children depth-first before the key itself.
        let key = Key::open(root, path)?;
        let children: Vec<String> = key.enum_subkeys()?.into_iter().map(|(n, _)| n).collect();
        drop(key); // release the handle before mutating the subtree
        for child in children {
            let child_path = if path.is_empty() {
                child
            } else {
                format!("{path}\\{child}")
            };
            delete_key(root, &child_path, true)?;
        }
    }
    let wpath = to_wide(path);
    let rc = unsafe { (offreg().delete_key)(root, wpath.as_ptr()) };
    if rc != ERROR_SUCCESS {
        return Err(map_win32(rc, Ctx::Key));
    }
    Ok(())
}
