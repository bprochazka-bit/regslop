//! Small helpers shared across modules: UTF-16 conversion and a monotonic
//! handle-id generator.

use std::sync::atomic::{AtomicU64, Ordering};

/// Encode a Rust string as a null-terminated UTF-16 buffer suitable for a
/// `PCWSTR` argument.
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Decode exactly `len` UTF-16 code units (no implicit null stripping).
pub fn from_wide_exact(buf: &[u16], len: usize) -> String {
    let len = len.min(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// Split a REG_MULTI_SZ payload (double-null-terminated UTF-16) into strings.
/// Trailing empty segments produced by the terminators are dropped.
pub fn parse_multi_sz(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &u in &units {
        if u == 0 {
            if cur.is_empty() {
                break; // the final terminator
            }
            out.push(String::from_utf16_lossy(&cur));
            cur.clear();
        } else {
            cur.push(u);
        }
    }
    if !cur.is_empty() {
        out.push(String::from_utf16_lossy(&cur));
    }
    out
}

/// Build a REG_MULTI_SZ payload: each string UTF-16, null-terminated, with a
/// final extra null. An empty list still gets the two terminating nulls.
pub fn build_multi_sz(strings: &[String]) -> Vec<u8> {
    let mut units: Vec<u16> = Vec::new();
    for s in strings {
        units.extend(s.encode_utf16());
        units.push(0);
    }
    units.push(0); // double terminator
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for u in units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes
}

/// Encode a Rust string as a REG_SZ payload: UTF-16 with a single null.
pub fn build_sz(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((s.len() + 1) * 2);
    for u in s.encode_utf16().chain(std::iter::once(0)) {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes
}

/// Decode a REG_SZ / REG_EXPAND_SZ / REG_LINK payload, stripping one trailing
/// null if present.
pub fn parse_sz(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if units.last() == Some(&0) {
        units.pop();
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_sz_roundtrip() {
        let strings = vec!["one".to_string(), "two".to_string()];
        let bytes = build_multi_sz(&strings);
        // Double-null terminated: ...two\0\0
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 0]);
        assert_eq!(parse_multi_sz(&bytes), strings);
    }

    #[test]
    fn empty_multi_sz() {
        let bytes = build_multi_sz(&[]);
        assert_eq!(bytes, vec![0, 0]); // just the terminator
        assert_eq!(parse_multi_sz(&bytes), Vec::<String>::new());
    }

    #[test]
    fn sz_strips_one_trailing_null() {
        let bytes = build_sz("hi");
        assert_eq!(parse_sz(&bytes), "hi");
        // A payload without a terminator decodes the same.
        let no_null: Vec<u8> = "hi".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(parse_sz(&no_null), "hi");
    }

    #[test]
    fn wide_roundtrip() {
        let w = to_wide("abc");
        assert_eq!(w, vec![b'a' as u16, b'b' as u16, b'c' as u16, 0]);
        assert_eq!(from_wide_exact(&w, 3), "abc");
    }
}

static HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a process-unique opaque handle string. The other agent must not
/// parse it, so the exact shape is internal.
pub fn next_handle_id() -> String {
    let n = HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("h_{n:08x}")
}
