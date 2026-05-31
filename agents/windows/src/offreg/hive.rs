//! RAII wrapper around an offline hive (its root ORHKEY).
//!
//! ORCreateHive / OROpenHive return the root key handle, which doubles as the
//! hive handle. The handle is closed with ORCloseHive on drop. The registry
//! owns one [`Hive`] per opaque handle string for the hive's lifetime.

use std::ptr;

use crate::error::{map_win32, AgentError, Ctx};
use crate::offreg::{offreg, Orhkey};
use crate::util::to_wide;
use crate::winapi::ERROR_SUCCESS;

pub struct Hive {
    root: Orhkey,
    /// The on-disk path the hive was loaded from, if any. `None` for a hive
    /// created fresh in memory until its first save.
    pub source_path: Option<String>,
}

// offreg is not thread-safe; the registry serializes calls per handle with a
// Mutex, so it is sound to move a Hive across threads.
unsafe impl Send for Hive {}

impl Hive {
    /// Create a brand new empty hive in memory.
    pub fn create() -> Result<Hive, AgentError> {
        let mut root: Orhkey = ptr::null_mut();
        let rc = unsafe { (offreg().create_hive)(&mut root) };
        if rc != ERROR_SUCCESS {
            return Err(map_win32(rc, Ctx::Hive));
        }
        Ok(Hive {
            root,
            source_path: None,
        })
    }

    /// Load an existing hive file from disk.
    pub fn open(path: &str) -> Result<Hive, AgentError> {
        let wpath = to_wide(path);
        let mut root: Orhkey = ptr::null_mut();
        let rc = unsafe { (offreg().open_hive)(wpath.as_ptr(), &mut root) };
        if rc != ERROR_SUCCESS {
            return Err(map_win32(rc, Ctx::Hive));
        }
        Ok(Hive {
            root,
            source_path: Some(path.to_string()),
        })
    }

    /// Serialize the hive to `path`. The OS version arguments select the hive
    /// format generation offreg writes (6.3 = Windows 8.1, giving v1.5 hives,
    /// which is what the harness expects by default).
    pub fn save(&self, path: &str, os_major: u32, os_minor: u32) -> Result<(), AgentError> {
        // ORSaveHive refuses to overwrite an existing file (it returns
        // ERROR_FILE_EXISTS), so clear the target first. offreg does not write
        // transaction log files, so the .hiv is the only artifact to remove.
        let _ = std::fs::remove_file(path);
        let wpath = to_wide(path);
        let rc = unsafe { (offreg().save_hive)(self.root, wpath.as_ptr(), os_major, os_minor) };
        if rc != ERROR_SUCCESS {
            return Err(map_win32(rc, Ctx::Hive));
        }
        Ok(())
    }

    /// The root key handle, used as the starting point for path resolution.
    pub fn root(&self) -> Orhkey {
        self.root
    }
}

impl Drop for Hive {
    fn drop(&mut self) {
        unsafe {
            (offreg().close_hive)(self.root);
        }
    }
}
