//! Server-wide state: the hive handle registry and run configuration.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::offreg::hive::Hive;
use crate::util::next_handle_id;

/// Per-handle hive storage. The outer Mutex guards the map; each hive sits
/// behind its own Mutex so requests on different handles run concurrently while
/// requests on the same handle serialize (offreg is not thread-safe).
pub struct Registry {
    hives: Mutex<HashMap<String, Arc<Mutex<Hive>>>>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry {
            hives: Mutex::new(HashMap::new()),
        }
    }

    /// Store a hive, returning the opaque handle the agents exchange.
    pub fn insert(&self, hive: Hive) -> String {
        let handle = next_handle_id();
        self.hives
            .lock()
            .unwrap()
            .insert(handle.clone(), Arc::new(Mutex::new(hive)));
        handle
    }

    pub fn get(&self, handle: &str) -> Option<Arc<Mutex<Hive>>> {
        self.hives.lock().unwrap().get(handle).cloned()
    }

    /// Remove a handle, returning the hive so the caller can drop it (closing
    /// the offreg handle). Returns None if the handle was unknown.
    pub fn remove(&self, handle: &str) -> Option<Arc<Mutex<Hive>>> {
        self.hives.lock().unwrap().remove(handle)
    }
}

/// Immutable run configuration shared with every handler.
pub struct AppState {
    pub registry: Registry,
    /// OS version offreg stamps into saved hives (defaults to 6.3 = Win 8.1,
    /// producing v1.5 hives, the harness default).
    pub save_os_major: u32,
    pub save_os_minor: u32,
    /// offreg backend version string reported in the handshake.
    pub backend: String,
}

impl AppState {
    pub fn new(backend: String, save_os_major: u32, save_os_minor: u32) -> AppState {
        AppState {
            registry: Registry::new(),
            save_os_major,
            save_os_minor,
            backend,
        }
    }
}
