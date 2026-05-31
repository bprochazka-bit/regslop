//! Advisory lock for the shared Windows VM (harness CLAUDE.md hard rule 6).
//!
//! Multiple harness runs may execute in parallel from separate worktrees, but
//! the Windows agent backs onto a single VM. We take an exclusive `flock` on a
//! known path before driving the Windows agent and hold it for the run. The
//! lock is advisory and released automatically when the process exits (the file
//! descriptor closes), so a crashed run does not wedge the queue.

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;

pub struct WinVmLock {
    _file: File,
}

impl WinVmLock {
    /// Block until the lock is acquired. Other harness runs queue here.
    pub fn acquire(path: &Path) -> Result<WinVmLock, String> {
        let file = File::create(path)
            .map_err(|e| format!("cannot open VM lock {}: {e}", path.display()))?;
        eprintln!("Waiting for Windows VM lock at {} ...", path.display());
        // SAFETY: a valid open fd from `file`, held for the duration of the
        // lock. LOCK_EX blocks until the exclusive lock is granted.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(format!(
                "flock failed on {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        eprintln!("Acquired Windows VM lock.");
        Ok(WinVmLock { _file: file })
    }
}
