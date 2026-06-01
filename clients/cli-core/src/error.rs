//! A single error type for the client utilities.

use std::fmt;

/// Anything that can go wrong running a client command. The `Display` text is
/// what the CLI prints; the variants let callers tailor the process exit code.
#[derive(Debug)]
pub enum CliError {
    /// The user's request was malformed (bad path, bad flag, bad data).
    Usage(String),
    /// A registry key or value the command needs does not exist.
    NotFound(String),
    /// A key/value the command would create already exists (and no force flag).
    Exists(String),
    /// No hive file is mapped for the requested root (see the mount map).
    NoMount(String),
    /// The verb cannot work on an offline hive (a running-service operation).
    Unsupported(String),
    /// An I/O failure touching a hive file or the mount config.
    Io(String),
    /// libreg rejected the operation.
    Hive(String),
}

impl CliError {
    pub fn usage(m: impl Into<String>) -> Self {
        CliError::Usage(m.into())
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        CliError::NotFound(m.into())
    }
    pub fn unsupported(m: impl Into<String>) -> Self {
        CliError::Unsupported(m.into())
    }

    /// The process exit code convention this error maps to. `reg.exe` returns 1
    /// for "not found" on query and 0 on success; we keep a simple nonzero for
    /// every error and reserve specific codes for callers that want them.
    pub fn exit_code(&self) -> i32 {
        1
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(m) => write!(f, "{m}"),
            CliError::NotFound(m) => write!(f, "{m}"),
            CliError::Exists(m) => write!(f, "{m}"),
            CliError::NoMount(m) => write!(f, "{m}"),
            CliError::Unsupported(m) => write!(f, "{m}"),
            CliError::Io(m) => write!(f, "{m}"),
            CliError::Hive(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e.to_string())
    }
}

impl From<libreg::logical::LogicalError> for CliError {
    fn from(e: libreg::logical::LogicalError) -> Self {
        use libreg::logical::LogicalError as L;
        match e {
            L::NotFound => CliError::NotFound("the system cannot find the key or value specified".into()),
            L::HasSubkeys => CliError::Usage("the key has subkeys (use a recursive delete)".into()),
            L::Unsupported(w) => CliError::Unsupported(format!("operation not supported: {w}")),
            L::Format(fmt) => CliError::Hive(format!("hive format error: {fmt}")),
        }
    }
}

pub type CliResult<T> = Result<T, CliError>;
