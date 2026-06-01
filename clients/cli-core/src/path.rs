//! Windows-style registry path parsing.
//!
//! A registry path names a predefined root (`HKEY_LOCAL_MACHINE`, or the short
//! `HKLM`) followed by a backslash-separated subpath, for example
//! `HKLM\SYSTEM\CurrentControlSet\Services\Foo`. This module splits a path into
//! its root and its components, and normalizes it back to a canonical string.

use crate::error::{CliError, CliResult};
use std::fmt;

/// A predefined registry root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Root {
    LocalMachine,
    CurrentUser,
    ClassesRoot,
    Users,
    CurrentConfig,
}

impl Root {
    /// The long, canonical `HKEY_*` name.
    pub fn long(self) -> &'static str {
        match self {
            Root::LocalMachine => "HKEY_LOCAL_MACHINE",
            Root::CurrentUser => "HKEY_CURRENT_USER",
            Root::ClassesRoot => "HKEY_CLASSES_ROOT",
            Root::Users => "HKEY_USERS",
            Root::CurrentConfig => "HKEY_CURRENT_CONFIG",
        }
    }

    /// The short abbreviation (`HKLM`, `HKCU`, ...).
    pub fn short(self) -> &'static str {
        match self {
            Root::LocalMachine => "HKLM",
            Root::CurrentUser => "HKCU",
            Root::ClassesRoot => "HKCR",
            Root::Users => "HKU",
            Root::CurrentConfig => "HKCC",
        }
    }

    /// Parse a root token, accepting both the long and short forms, case
    /// insensitively. Returns `None` if the token is not a known root.
    pub fn parse(token: &str) -> Option<Root> {
        let t = token.to_ascii_uppercase();
        let candidates = [
            Root::LocalMachine,
            Root::CurrentUser,
            Root::ClassesRoot,
            Root::Users,
            Root::CurrentConfig,
        ];
        candidates
            .into_iter()
            .find(|r| r.long() == t || r.short() == t)
    }
}

impl fmt::Display for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.long())
    }
}

/// A parsed registry path: a root plus its subpath components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegPath {
    pub root: Root,
    /// Subpath components below the root (never contains empty strings).
    pub components: Vec<String>,
}

impl RegPath {
    /// Parse a `ROOT\\a\\b\\c` path. A leading machine prefix (`\\\\HOST\\`) is
    /// rejected: there is no remote registry on Linux.
    pub fn parse(input: &str) -> CliResult<RegPath> {
        let trimmed = input.trim();
        if trimmed.starts_with("\\\\") {
            return Err(CliError::unsupported(
                "remote registry paths (\\\\machine\\...) are not supported on offline hives",
            ));
        }
        let mut parts = trimmed.split('\\').filter(|s| !s.is_empty());
        let root_token = parts
            .next()
            .ok_or_else(|| CliError::usage("empty registry path"))?;
        let root = Root::parse(root_token).ok_or_else(|| {
            CliError::usage(format!(
                "'{root_token}' is not a valid registry root (expected HKLM, HKCU, HKCR, HKU, or HKCC)"
            ))
        })?;
        let components = parts.map(|s| s.to_string()).collect();
        Ok(RegPath { root, components })
    }

    /// The subpath joined with backslashes (empty string means the root).
    pub fn subpath(&self) -> String {
        self.components.join("\\")
    }

    /// The canonical display form using the long root name.
    pub fn display_long(&self) -> String {
        if self.components.is_empty() {
            self.root.long().to_string()
        } else {
            format!("{}\\{}", self.root.long(), self.subpath())
        }
    }

    /// Append a single component, returning the extended path.
    pub fn child(&self, name: &str) -> RegPath {
        let mut c = self.components.clone();
        c.push(name.to_string());
        RegPath {
            root: self.root,
            components: c,
        }
    }
}

impl fmt::Display for RegPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_long())
    }
}

/// Case-insensitive component comparison, matching registry name semantics.
pub fn name_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_and_long_roots() {
        assert_eq!(RegPath::parse("HKLM").unwrap().root, Root::LocalMachine);
        assert_eq!(
            RegPath::parse("HKEY_CURRENT_USER\\Software").unwrap().root,
            Root::CurrentUser
        );
        assert_eq!(RegPath::parse("hkcr").unwrap().root, Root::ClassesRoot);
    }

    #[test]
    fn splits_subpath_and_ignores_doubled_separators() {
        let p = RegPath::parse("HKLM\\SYSTEM\\\\Foo\\Bar\\").unwrap();
        assert_eq!(p.components, vec!["SYSTEM", "Foo", "Bar"]);
        assert_eq!(p.subpath(), "SYSTEM\\Foo\\Bar");
        assert_eq!(p.display_long(), "HKEY_LOCAL_MACHINE\\SYSTEM\\Foo\\Bar");
    }

    #[test]
    fn rejects_unknown_root_and_remote() {
        assert!(RegPath::parse("HKXX\\Foo").is_err());
        assert!(RegPath::parse("\\\\server\\HKLM\\Foo").is_err());
    }

    #[test]
    fn root_only_path_has_empty_subpath() {
        let p = RegPath::parse("HKCU").unwrap();
        assert!(p.components.is_empty());
        assert_eq!(p.subpath(), "");
        assert_eq!(p.display_long(), "HKEY_CURRENT_USER");
    }
}
