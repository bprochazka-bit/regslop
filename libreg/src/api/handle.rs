//! Opaque hive handles.
//!
//! A handle is an opaque 64-bit token the API hands out, never a Rust pointer
//! (`docs/ffi-abi.md` rule 4: Rust structs are never exposed across the
//! boundary). Each token keys into a process-global registry that owns the
//! live [`Hive`] and the filesystem path it loads from and saves to. Looking a
//! token up that was never issued, or was closed, yields `HANDLE_INVALID`
//! rather than undefined behavior, so a stale handle is a clean error.

use super::error::ApiError;
use crate::logical::Hive;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// A live hive plus the path it is bound to on disk.
pub(crate) struct HiveEntry {
    pub hive: Hive,
    /// Where `libreg_hive_save` writes and where load read from. Empty for a
    /// hive created in memory that has not been given a path yet.
    pub path: String,
}

/// The process-global handle table. Tokens are assigned from a monotonic
/// counter that starts at 1, so 0 is never a valid handle and can serve as the
/// caller-visible "no handle" sentinel.
struct Registry {
    map: HashMap<u64, HiveEntry>,
    next: u64,
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

/// Lock the registry, recovering from a poisoned mutex. Poisoning means a
/// previous call panicked while holding the lock; that panic was already
/// reported as `INTERNAL`, and the registry itself (a plain map) stays usable,
/// so taking the inner guard is safe and keeps later calls working.
fn lock() -> MutexGuard<'static, Registry> {
    REGISTRY
        .get_or_init(|| {
            Mutex::new(Registry {
                map: HashMap::new(),
                next: 1,
            })
        })
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Insert a hive bound to `path` and return its fresh handle token.
pub(crate) fn insert(hive: Hive, path: String) -> u64 {
    let mut reg = lock();
    let handle = reg.next;
    reg.next += 1;
    reg.map.insert(handle, HiveEntry { hive, path });
    handle
}

/// Run `f` against the entry behind `handle`, or fail with `HANDLE_INVALID`
/// when the token is unknown. The registry lock is held for the duration, so
/// operations on a single hive are serialized; concurrent calls on different
/// handles do not race the map.
pub(crate) fn with_entry<R>(
    handle: u64,
    f: impl FnOnce(&mut HiveEntry) -> Result<R, ApiError>,
) -> Result<R, ApiError> {
    let mut reg = lock();
    let entry = reg
        .map
        .get_mut(&handle)
        .ok_or_else(ApiError::handle_invalid)?;
    f(entry)
}

/// Remove and drop the entry behind `handle`. Returns whether it existed;
/// closing an unknown or already-closed handle is reported as `HANDLE_INVALID`
/// by the caller rather than silently succeeding.
pub(crate) fn remove(handle: u64) -> bool {
    lock().map.remove(&handle).is_some()
}
