//! Identify a hive file and the registry mount point it belongs at.
//!
//! Offline hives have no inherent knowledge of where they hang in the live
//! registry, but the standard Windows hives are recognizable two ways: by their
//! conventional file name (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, ...) and by the
//! shape of their top-level keys (a `Select` plus a `ControlSet001` is a SYSTEM
//! hive, a `Microsoft` plus a `Classes` is SOFTWARE, and so on). We use the file
//! name as the primary signal and the contents to confirm it or to classify a
//! hive whose name is nonstandard. This is what lets `regmount` build a correct
//! mount map by inspecting a directory of hive files.

use crate::error::CliResult;
use crate::path::RegPath;
use crate::session::Session;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The result of inspecting one hive file.
#[derive(Debug, Clone)]
pub struct Identification {
    /// The file inspected.
    pub file: PathBuf,
    /// A human-readable description of what kind of hive this is.
    pub kind: String,
    /// The mount point to bind it at, or `None` when we cannot tell.
    pub mount: Option<RegPath>,
    /// Why we decided (which signal matched), shown as a comment in the map.
    pub reason: String,
}

/// Open `path` as a hive and identify the registry mount point for it.
///
/// Returns an error only when the file cannot be read or is not a hive at all.
/// A readable hive that we cannot place is reported with `mount: None` rather
/// than as an error, so a directory scan can surface it for manual mapping.
pub fn identify_hive(path: &Path) -> CliResult<Identification> {
    let session = Session::open(path)?;
    let top: BTreeSet<String> = session
        .hive()
        .subkeys("")?
        .into_iter()
        .map(|k| k.to_ascii_lowercase())
        .collect();

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let by_name = by_filename(&file_name);
    let by_cont = by_content(&top);

    let (kind, mount_str, reason) = match (by_name, by_cont) {
        (Some((kn, mp)), Some((_, mpc))) if eq_ignore_case(mp, mpc) => (
            kn.to_string(),
            Some(mp),
            format!("file name '{file_name}' and contents agree"),
        ),
        (Some((kn, mp)), Some((kc, mpc))) => (
            kn.to_string(),
            Some(mp),
            format!("file name '{file_name}' says {mp}; contents look like {kc} ({mpc}). Using the name; check this one"),
        ),
        (Some((kn, mp)), None) => (
            kn.to_string(),
            Some(mp),
            format!("matched by file name '{file_name}'"),
        ),
        (None, Some((kc, mp))) => (
            kc.to_string(),
            Some(mp),
            format!("file name '{file_name}' is nonstandard; matched by contents"),
        ),
        (None, None) => (
            "unrecognized hive".to_string(),
            None,
            format!(
                "valid hive, but neither file name '{file_name}' nor its top-level keys [{}] match a known layout",
                sample(&top)
            ),
        ),
    };

    let mount = match mount_str {
        Some(s) => Some(RegPath::parse(s)?),
        None => None,
    };
    Ok(Identification {
        file: path.to_path_buf(),
        kind,
        mount,
        reason,
    })
}

/// Map a standard Windows hive file name to its kind and mount point.
fn by_filename(name_lower: &str) -> Option<(&'static str, &'static str)> {
    let m = match name_lower {
        "system" => ("Windows SYSTEM hive", "HKLM\\SYSTEM"),
        "software" => ("Windows SOFTWARE hive", "HKLM\\SOFTWARE"),
        "sam" => ("Windows SAM hive", "HKLM\\SAM"),
        "security" => ("Windows SECURITY hive", "HKLM\\SECURITY"),
        "components" => ("Windows COMPONENTS hive", "HKLM\\COMPONENTS"),
        "drivers" => ("Windows DRIVERS hive", "HKLM\\DRIVERS"),
        "default" => ("Windows DEFAULT user hive", "HKU\\.DEFAULT"),
        "ntuser.dat" => ("per-user NTUSER hive", "HKCU"),
        "usrclass.dat" => ("per-user classes hive", "HKCU\\Software\\Classes"),
        "bcd" => ("Boot Configuration Data hive", "HKLM\\BCD00000000"),
        _ => return None,
    };
    Some(m)
}

/// Classify a hive by the shape of its top-level keys (all lowercased).
fn by_content(top: &BTreeSet<String>) -> Option<(&'static str, &'static str)> {
    let has = |k: &str| top.contains(k);
    let any_starts = |p: &str| top.iter().any(|k| k.starts_with(p));

    if has("select") && any_starts("controlset") {
        return Some(("a SYSTEM hive (Select + ControlSet)", "HKLM\\SYSTEM"));
    }
    if has("microsoft") && (has("classes") || has("wow6432node")) {
        return Some(("a SOFTWARE hive (Microsoft + Classes)", "HKLM\\SOFTWARE"));
    }
    if has("sam") && has("domains") {
        return Some(("a SAM hive (SAM + Domains)", "HKLM\\SAM"));
    }
    if has("policy") && !has("microsoft") {
        return Some(("a SECURITY hive (Policy)", "HKLM\\SECURITY"));
    }
    if has("software")
        && (has("environment") || has("control panel") || has("keyboard layout") || has("console"))
    {
        return Some(("a user hive (NTUSER.DAT shape)", "HKCU"));
    }
    if has("local settings") || any_starts(".") {
        return Some((
            "a user classes hive (UsrClass.dat shape)",
            "HKCU\\Software\\Classes",
        ));
    }
    None
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// A short, comment-friendly sample of the top-level key names.
fn sample(top: &BTreeSet<String>) -> String {
    const MAX: usize = 6;
    let mut names: Vec<&str> = top.iter().take(MAX).map(|s| s.as_str()).collect();
    if top.len() > MAX {
        names.push("...");
    }
    names.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value;

    /// Build a hive at `dir/name` whose root has the given top-level subkeys.
    fn write_hive(dir: &Path, name: &str, subkeys: &[&str]) -> PathBuf {
        let path = dir.join(name);
        let mut s = Session::create(&path);
        for k in subkeys {
            s.hive_mut().create_key(k).unwrap();
        }
        // A value on the root so even an empty-subkey hive is well formed.
        s.hive_mut().set_value("", "_", value::REG_SZ, &value::build_sz("x")).unwrap();
        s.save().unwrap();
        path
    }

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("libreg_identify_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn system_by_content_even_with_odd_name() {
        let dir = tmpdir();
        let p = write_hive(&dir, "weirdname.bin", &["Select", "ControlSet001", "Setup"]);
        let id = identify_hive(&p).unwrap();
        assert_eq!(id.mount.unwrap().display_long(), "HKEY_LOCAL_MACHINE\\SYSTEM");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn software_by_filename() {
        let dir = tmpdir();
        let p = write_hive(&dir, "SOFTWARE", &[]);
        let id = identify_hive(&p).unwrap();
        assert_eq!(id.mount.unwrap().display_long(), "HKEY_LOCAL_MACHINE\\SOFTWARE");
        assert!(id.reason.contains("file name"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn user_hive_by_content() {
        let dir = tmpdir();
        let p = write_hive(&dir, "NTUSER.DAT", &["Software", "Environment", "Control Panel"]);
        let id = identify_hive(&p).unwrap();
        assert_eq!(id.mount.unwrap().display_long(), "HKEY_CURRENT_USER");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn unrecognized_hive_has_no_mount() {
        let dir = tmpdir();
        let p = write_hive(&dir, "mystery.dat", &["Alpha", "Beta"]);
        let id = identify_hive(&p).unwrap();
        assert!(id.mount.is_none());
        assert!(id.kind.contains("unrecognized"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn not_a_hive_is_an_error() {
        let dir = tmpdir();
        let p = dir.join("notahive.txt");
        std::fs::write(&p, b"this is not a registry hive").unwrap();
        assert!(identify_hive(&p).is_err());
        std::fs::remove_file(&p).ok();
    }
}
