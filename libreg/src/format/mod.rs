//! Layer 0: on-disk hive structures.
//!
//! Everything here is a pure parser or serializer. No allocation policy,
//! no caching, no interpretation of cell relationships. Read raw bytes
//! into a typed value, write a typed value back into raw bytes, and make
//! the round trip exact.

pub mod base_block;
pub mod cell;
pub mod db;
pub mod empty_hive;
pub mod hbin;
pub mod lf;
pub mod lh;
pub mod li;
pub mod nk;
pub mod ri;
pub mod security_descriptor;
pub mod sk;
pub mod vk;

/// Errors raised while parsing or serializing on-disk structures.
///
/// These are deliberately low level. Higher layers map them onto the
/// agent-visible error codes listed in CONTRACTS.md (for example
/// `HIVE_CORRUPT`); Layer 0 does not know about that vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// The provided buffer was smaller than the structure requires.
    Truncated {
        /// Bytes the structure needs.
        expected: usize,
        /// Bytes actually available.
        found: usize,
    },
    /// A magic signature did not match the expected value.
    BadSignature {
        /// Human readable name of the structure, e.g. "base block".
        structure: &'static str,
        /// The four signature bytes that were found.
        found: [u8; 4],
    },
    /// A structure would read past the end of the bytes available to it.
    OutOfBounds {
        /// Human readable name of the structure, e.g. "cell".
        structure: &'static str,
        /// Byte offset where the structure begins.
        offset: usize,
        /// Bytes the structure needs from `offset`.
        need: usize,
        /// Bytes actually available from `offset`.
        available: usize,
    },
    /// A cell declared a size of zero, which is never valid (invariant 6).
    ZeroCellSize {
        /// Byte offset of the offending cell within the hive bins data.
        offset: usize,
    },
    /// A length field was not a multiple of the required alignment.
    Unaligned {
        /// Human readable name of the structure, e.g. "hbin".
        structure: &'static str,
        /// The value that failed the alignment check.
        value: u32,
        /// The alignment it had to be a multiple of.
        align: u32,
    },
}

impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FormatError::Truncated { expected, found } => write!(
                f,
                "buffer truncated: need {expected} bytes, found {found}"
            ),
            FormatError::BadSignature { structure, found } => write!(
                f,
                "bad {structure} signature: {found:02x?}"
            ),
            FormatError::OutOfBounds {
                structure,
                offset,
                need,
                available,
            } => write!(
                f,
                "{structure} at offset {offset:#x} needs {need} bytes, only {available} available"
            ),
            FormatError::ZeroCellSize { offset } => {
                write!(f, "cell at offset {offset:#x} has size zero")
            }
            FormatError::Unaligned {
                structure,
                value,
                align,
            } => write!(
                f,
                "{structure} value {value:#x} is not a multiple of {align}"
            ),
        }
    }
}

impl std::error::Error for FormatError {}

/// Read a little-endian `u32` from `buf` at `off`.
///
/// Endianness is always explicit in this crate (Hard Rule 6): we never
/// transmute or rely on the host byte order.
#[inline]
pub(crate) fn read_u32(buf: &[u8], off: usize) -> u32 {
    let bytes: [u8; 4] = buf[off..off + 4].try_into().expect("slice is 4 bytes");
    u32::from_le_bytes(bytes)
}

/// Read a little-endian `u16` from `buf` at `off`.
#[inline]
pub(crate) fn read_u16(buf: &[u8], off: usize) -> u16 {
    let bytes: [u8; 2] = buf[off..off + 2].try_into().expect("slice is 2 bytes");
    u16::from_le_bytes(bytes)
}

/// Read a little-endian `i32` from `buf` at `off`.
#[inline]
pub(crate) fn read_i32(buf: &[u8], off: usize) -> i32 {
    let bytes: [u8; 4] = buf[off..off + 4].try_into().expect("slice is 4 bytes");
    i32::from_le_bytes(bytes)
}

/// Read a little-endian `u64` from `buf` at `off`.
#[inline]
pub(crate) fn read_u64(buf: &[u8], off: usize) -> u64 {
    let bytes: [u8; 8] = buf[off..off + 8].try_into().expect("slice is 8 bytes");
    u64::from_le_bytes(bytes)
}
