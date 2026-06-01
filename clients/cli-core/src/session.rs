//! Open a hive file, operate on it through libreg, and save it back.
//!
//! A [`Session`] owns a `libreg::logical::Hive` plus the file path it came
//! from. Clients resolve a registry path to a file (via the mount map), open a
//! session on that file, perform their operation against the in-hive subpath,
//! and call [`Session::save`] when they mutated it.

use crate::error::{CliError, CliResult};
use crate::value;
use libreg::logical::Hive;
use std::path::{Path, PathBuf};

/// One open hive file.
pub struct Session {
    hive: Hive,
    path: PathBuf,
}

/// A fully enumerated key: its values and child keys (raw, type-tagged).
#[derive(Debug, Clone)]
pub struct KeyDump {
    /// In-hive path of this key (`""` is the hive root).
    pub path: String,
    pub values: Vec<ValueDump>,
    pub subkeys: Vec<String>,
}

/// A single value with its raw bytes and type code.
#[derive(Debug, Clone)]
pub struct ValueDump {
    pub name: String,
    pub ty: u32,
    pub data: Vec<u8>,
}

impl ValueDump {
    /// Display form of this value's data (`reg query` style).
    pub fn display(&self) -> String {
        value::format_display(self.ty, &self.data)
    }
}

impl Session {
    /// Open an existing hive file. A missing file is an error.
    pub fn open(path: &Path) -> CliResult<Session> {
        let bytes = std::fs::read(path)
            .map_err(|e| CliError::Io(format!("cannot open hive {}: {e}", path.display())))?;
        let hive = Hive::from_file_bytes(&bytes)?;
        Ok(Session {
            hive,
            path: path.to_path_buf(),
        })
    }

    /// Create a fresh empty hive bound to `path` (not yet written to disk).
    pub fn create(path: &Path) -> Session {
        Session {
            hive: Hive::new_empty(),
            path: path.to_path_buf(),
        }
    }

    /// Open the hive if it exists, else start a fresh empty one at `path`.
    pub fn open_or_create(path: &Path) -> CliResult<Session> {
        if path.exists() {
            Self::open(path)
        } else {
            Ok(Self::create(path))
        }
    }

    pub fn hive(&self) -> &Hive {
        &self.hive
    }

    pub fn hive_mut(&mut self) -> &mut Hive {
        &mut self.hive
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the hive back to its file.
    pub fn save(&self) -> CliResult<u64> {
        let bytes = self.hive.to_file();
        std::fs::write(&self.path, &bytes)
            .map_err(|e| CliError::Io(format!("cannot write hive {}: {e}", self.path.display())))?;
        Ok(bytes.len() as u64)
    }

    /// Write the hive to a different file (used by `reg save`).
    pub fn save_as(&self, dest: &Path) -> CliResult<u64> {
        let bytes = self.hive.to_file();
        std::fs::write(dest, &bytes)
            .map_err(|e| CliError::Io(format!("cannot write hive {}: {e}", dest.display())))?;
        Ok(bytes.len() as u64)
    }

    /// Does `path` exist in this hive?
    pub fn exists(&self, path: &str) -> CliResult<bool> {
        Ok(self.hive.resolve(path)?.is_some())
    }

    /// Read every value on the key at `path`, sorted case-insensitively by name.
    pub fn read_values(&self, path: &str) -> CliResult<Vec<ValueDump>> {
        let mut out = Vec::new();
        for name in self.hive.values(path)? {
            if let Some((ty, data)) = self.hive.get_value(path, &name)? {
                out.push(ValueDump { name, ty, data });
            }
        }
        out.sort_by(|a, b| a.name.to_uppercase().cmp(&b.name.to_uppercase()));
        Ok(out)
    }

    /// Dump a single key (its values and immediate subkey names).
    pub fn dump_key(&self, path: &str) -> CliResult<KeyDump> {
        if !self.exists(path)? {
            return Err(CliError::not_found(format!(
                "the system was unable to find the specified registry key: {path}"
            )));
        }
        Ok(KeyDump {
            path: path.to_string(),
            values: self.read_values(path)?,
            subkeys: self.hive.subkeys(path)?,
        })
    }

    /// Recursively dump the key at `path` and every descendant, pre-order
    /// (parent before children), each level name-sorted.
    pub fn dump_recursive(&self, path: &str) -> CliResult<Vec<KeyDump>> {
        let mut out = Vec::new();
        self.dump_into(path, &mut out)?;
        Ok(out)
    }

    fn dump_into(&self, path: &str, out: &mut Vec<KeyDump>) -> CliResult<()> {
        let dump = self.dump_key(path)?;
        let children = dump.subkeys.clone();
        out.push(dump);
        for sub in children {
            let child = if path.is_empty() {
                sub
            } else {
                format!("{path}\\{sub}")
            };
            self.dump_into(&child, out)?;
        }
        Ok(())
    }

    /// Copy the subtree at `src` to `dst` within this same hive (values and all
    /// descendants). Used by `reg copy` for the in-hive case.
    pub fn copy_subtree(&mut self, src: &str, dst: &str) -> CliResult<()> {
        self.hive.create_key(dst)?;
        for v in self.read_values(src)? {
            self.hive.set_value(dst, &v.name, v.ty, &v.data)?;
        }
        for sub in self.hive.subkeys(src)? {
            let s = if src.is_empty() { sub.clone() } else { format!("{src}\\{sub}") };
            let d = if dst.is_empty() { sub.clone() } else { format!("{dst}\\{sub}") };
            self.copy_subtree(&s, &d)?;
        }
        Ok(())
    }
}
