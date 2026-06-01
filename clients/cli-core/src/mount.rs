//! The mount map: bind predefined registry roots (and subpaths under them) to
//! offline hive files.
//!
//! There is no live registry on Linux, so a registry path has to resolve to a
//! file. A mount entry binds a mount point (a [`RegPath`], for example
//! `HKLM\SYSTEM`) to a hive file. Resolving `HKLM\SYSTEM\CurrentControlSet`
//! finds the longest mount point that prefixes it (`HKLM\SYSTEM`), giving the
//! file plus the in-hive subpath (`CurrentControlSet`). This keeps
//! `reg query HKLM\SYSTEM\...` syntax identical to Windows.
//!
//! The map persists in a small text file so it survives across separate `reg`
//! invocations (this is how `reg load` / `reg unload` work without a daemon).
//! Format, one entry per line, `#` comments allowed:
//!
//! ```text
//! HKLM\SYSTEM   = /data/hives/SYSTEM
//! HKCU          = /home/me/NTUSER.DAT
//! ```

use crate::error::{CliError, CliResult};
use crate::path::{name_eq, RegPath, Root};
use std::path::{Path, PathBuf};

/// One mount: a mount-point path bound to a hive file.
#[derive(Debug, Clone)]
pub struct Mount {
    pub point: RegPath,
    pub file: PathBuf,
}

/// The full mount map.
#[derive(Debug, Clone, Default)]
pub struct MountMap {
    pub mounts: Vec<Mount>,
    /// The file the map was loaded from (where `load`/`unload` persist edits).
    pub source: Option<PathBuf>,
}

/// Where a resolved registry path lives: a hive file and the subpath inside it.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub file: PathBuf,
    /// In-hive components below the hive root (joinable for libreg).
    pub in_hive: Vec<String>,
}

impl Resolved {
    /// The in-hive path as libreg expects it (backslash-joined, `""` = root).
    pub fn in_hive_path(&self) -> String {
        self.in_hive.join("\\")
    }
}

impl MountMap {
    /// The default config path: `$LIBREG_HIVES` if set, else
    /// `$XDG_CONFIG_HOME/libreg/hives.conf`, else `~/.config/libreg/hives.conf`.
    pub fn default_path() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("LIBREG_HIVES") {
            return Some(PathBuf::from(p));
        }
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("libreg").join("hives.conf"))
    }

    /// Load the mount map from its default location. A missing file is an empty
    /// map (not an error): the user simply has no mounts yet.
    pub fn load_default() -> CliResult<MountMap> {
        match Self::default_path() {
            Some(p) => Self::load_from(&p),
            None => Ok(MountMap::default()),
        }
    }

    /// Load a mount map from a specific file (missing file = empty map).
    pub fn load_from(path: &Path) -> CliResult<MountMap> {
        let mut map = MountMap {
            mounts: Vec::new(),
            source: Some(path.to_path_buf()),
        };
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(map),
            Err(e) => return Err(CliError::Io(format!("reading {}: {e}", path.display()))),
        };
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (point, file) = line.split_once('=').ok_or_else(|| {
                CliError::usage(format!(
                    "{}:{}: mount line must be 'POINT = file'",
                    path.display(),
                    lineno + 1
                ))
            })?;
            let point = RegPath::parse(point.trim())?;
            map.mounts.push(Mount {
                point,
                file: PathBuf::from(file.trim()),
            });
        }
        Ok(map)
    }

    /// Persist this map back to its source file, creating parent directories.
    pub fn save(&self) -> CliResult<()> {
        let path = self
            .source
            .as_ref()
            .ok_or_else(|| CliError::usage("mount map has no source file to save to"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = String::new();
        out.push_str("# libreg mount map: registry root/subpath -> hive file\n");
        for m in &self.mounts {
            out.push_str(&format!("{} = {}\n", m.point.display_long(), m.file.display()));
        }
        std::fs::write(path, out)?;
        Ok(())
    }

    /// Add or replace the mount for an exact mount point.
    pub fn insert(&mut self, point: RegPath, file: PathBuf) {
        self.remove(&point);
        self.mounts.push(Mount { point, file });
    }

    /// Remove the mount whose point matches exactly. Returns whether one went.
    pub fn remove(&mut self, point: &RegPath) -> bool {
        let before = self.mounts.len();
        self.mounts
            .retain(|m| !(m.point.root == point.root && comps_eq(&m.point.components, &point.components)));
        self.mounts.len() != before
    }

    /// Resolve a registry path to a hive file and in-hive subpath, choosing the
    /// longest matching mount point.
    pub fn resolve(&self, path: &RegPath) -> CliResult<Resolved> {
        let mut best: Option<&Mount> = None;
        for m in &self.mounts {
            if m.point.root != path.root {
                continue;
            }
            if is_prefix(&m.point.components, &path.components) {
                let better = match best {
                    Some(b) => m.point.components.len() > b.point.components.len(),
                    None => true,
                };
                if better {
                    best = Some(m);
                }
            }
        }
        let m = best.ok_or_else(|| {
            CliError::NoMount(format!(
                "no hive is mounted for {} (add a mount or pass --hive)",
                path.display_long()
            ))
        })?;
        let in_hive = path.components[m.point.components.len()..].to_vec();
        Ok(Resolved {
            file: m.file.clone(),
            in_hive,
        })
    }

    /// Resolve with an explicit `--hive FILE` override: the file is taken as the
    /// hive whose root is the path's root, so the whole subpath is in-hive.
    pub fn resolve_with_override(&self, path: &RegPath, hive_override: Option<&Path>) -> CliResult<Resolved> {
        match hive_override {
            Some(file) => Ok(Resolved {
                file: file.to_path_buf(),
                in_hive: path.components.clone(),
            }),
            None => self.resolve(path),
        }
    }

    /// All mounts under a given root (used by regedit to list available roots).
    pub fn under_root(&self, root: Root) -> Vec<&Mount> {
        self.mounts.iter().filter(|m| m.point.root == root).collect()
    }
}

/// Is `prefix` a component-wise, case-insensitive prefix of `full`?
fn is_prefix(prefix: &[String], full: &[String]) -> bool {
    if prefix.len() > full.len() {
        return false;
    }
    prefix.iter().zip(full).all(|(a, b)| name_eq(a, b))
}

fn comps_eq(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| name_eq(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> MountMap {
        let mut m = MountMap::default();
        m.insert(RegPath::parse("HKLM\\SYSTEM").unwrap(), PathBuf::from("/h/SYSTEM"));
        m.insert(RegPath::parse("HKLM\\SOFTWARE").unwrap(), PathBuf::from("/h/SOFTWARE"));
        m.insert(RegPath::parse("HKCU").unwrap(), PathBuf::from("/h/NTUSER.DAT"));
        m
    }

    #[test]
    fn resolves_longest_prefix() {
        let m = map();
        let r = m
            .resolve(&RegPath::parse("HKLM\\SYSTEM\\CurrentControlSet\\Services").unwrap())
            .unwrap();
        assert_eq!(r.file, PathBuf::from("/h/SYSTEM"));
        assert_eq!(r.in_hive_path(), "CurrentControlSet\\Services");
    }

    #[test]
    fn resolves_root_mount() {
        let m = map();
        let r = m.resolve(&RegPath::parse("HKCU\\Software\\App").unwrap()).unwrap();
        assert_eq!(r.file, PathBuf::from("/h/NTUSER.DAT"));
        assert_eq!(r.in_hive_path(), "Software\\App");
    }

    #[test]
    fn unmapped_root_is_an_error() {
        let m = map();
        assert!(matches!(
            m.resolve(&RegPath::parse("HKCR\\X").unwrap()),
            Err(CliError::NoMount(_))
        ));
    }

    #[test]
    fn override_takes_whole_subpath() {
        let m = MountMap::default();
        let r = m
            .resolve_with_override(
                &RegPath::parse("HKLM\\Foo\\Bar").unwrap(),
                Some(Path::new("/tmp/x.hiv")),
            )
            .unwrap();
        assert_eq!(r.file, PathBuf::from("/tmp/x.hiv"));
        assert_eq!(r.in_hive_path(), "Foo\\Bar");
    }

    #[test]
    fn insert_replaces_and_remove_works() {
        let mut m = map();
        m.insert(RegPath::parse("HKCU").unwrap(), PathBuf::from("/h/other"));
        let r = m.resolve(&RegPath::parse("HKCU\\A").unwrap()).unwrap();
        assert_eq!(r.file, PathBuf::from("/h/other"));
        assert!(m.remove(&RegPath::parse("hkcu").unwrap()));
        assert!(m.resolve(&RegPath::parse("HKCU\\A").unwrap()).is_err());
    }
}
