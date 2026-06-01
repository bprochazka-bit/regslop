//! Registry value type codec for the clients.
//!
//! Maps REG_* type names to the numeric codes libreg stores, parses the data a
//! user types on a command line into raw bytes, and formats raw bytes for
//! display. String types use UTF-16LE on disk (the registry's encoding), so the
//! codec converts to and from UTF-8 for the user.

use crate::error::{CliError, CliResult};

pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_BE: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_RESOURCE_LIST: u32 = 8;
pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
pub const REG_QWORD: u32 = 11;

/// The CONTRACTS type name for a code (unknown codes are treated as binary).
pub fn type_name(ty: u32) -> &'static str {
    match ty {
        REG_NONE => "REG_NONE",
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY => "REG_BINARY",
        REG_DWORD => "REG_DWORD",
        REG_DWORD_BE => "REG_DWORD_BIG_ENDIAN",
        REG_LINK => "REG_LINK",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_RESOURCE_LIST => "REG_RESOURCE_LIST",
        REG_FULL_RESOURCE_DESCRIPTOR => "REG_FULL_RESOURCE_DESCRIPTOR",
        REG_RESOURCE_REQUIREMENTS_LIST => "REG_RESOURCE_REQUIREMENTS_LIST",
        REG_QWORD => "REG_QWORD",
        _ => "REG_BINARY",
    }
}

/// Parse a `/t` type token. Accepts the canonical names plus the `REG_DWORD_BE`
/// short form `reg.exe` also accepts.
pub fn type_from_name(name: &str) -> Option<u32> {
    let n = name.to_ascii_uppercase();
    Some(match n.as_str() {
        "REG_NONE" => REG_NONE,
        "REG_SZ" => REG_SZ,
        "REG_EXPAND_SZ" => REG_EXPAND_SZ,
        "REG_BINARY" => REG_BINARY,
        "REG_DWORD" => REG_DWORD,
        "REG_DWORD_LITTLE_ENDIAN" => REG_DWORD,
        "REG_DWORD_BIG_ENDIAN" | "REG_DWORD_BE" => REG_DWORD_BE,
        "REG_LINK" => REG_LINK,
        "REG_MULTI_SZ" => REG_MULTI_SZ,
        "REG_RESOURCE_LIST" => REG_RESOURCE_LIST,
        "REG_FULL_RESOURCE_DESCRIPTOR" => REG_FULL_RESOURCE_DESCRIPTOR,
        "REG_RESOURCE_REQUIREMENTS_LIST" => REG_RESOURCE_REQUIREMENTS_LIST,
        "REG_QWORD" | "REG_QWORD_LITTLE_ENDIAN" => REG_QWORD,
        _ => return None,
    })
}

/// Encode command-line `/d` data of the given type into raw bytes. `separator`
/// is the REG_MULTI_SZ element separator (`reg.exe` default is `\0`, overridable
/// with `/s`).
pub fn encode_cli(ty: u32, data: &str, separator: &str) -> CliResult<Vec<u8>> {
    let bad = |what: &str| CliError::usage(format!("{} requires {what}", type_name(ty)));
    Ok(match ty {
        REG_NONE => Vec::new(),
        REG_SZ | REG_EXPAND_SZ | REG_LINK => build_sz(data),
        REG_DWORD => parse_int(data).and_then(|v| u32::try_from(v).ok()).ok_or_else(|| bad("a 32-bit integer"))?.to_le_bytes().to_vec(),
        REG_DWORD_BE => parse_int(data).and_then(|v| u32::try_from(v).ok()).ok_or_else(|| bad("a 32-bit integer"))?.to_be_bytes().to_vec(),
        REG_QWORD => parse_int(data).ok_or_else(|| bad("a 64-bit integer"))?.to_le_bytes().to_vec(),
        REG_MULTI_SZ => {
            let parts: Vec<&str> = if separator.is_empty() || data.is_empty() {
                if data.is_empty() { Vec::new() } else { vec![data] }
            } else {
                data.split(separator).collect()
            };
            build_multi_sz(&parts)
        }
        // REG_BINARY and the opaque resource types take a hex string.
        _ => parse_hex(data).ok_or_else(|| bad("hex digit pairs (for example 0a0b0c)"))?,
    })
}

/// Format raw value bytes for `reg query`-style display.
pub fn format_display(ty: u32, bytes: &[u8]) -> String {
    match ty {
        REG_NONE => String::new(),
        REG_SZ | REG_EXPAND_SZ | REG_LINK => parse_sz(bytes),
        REG_DWORD => format!("0x{:x}", read_u32_le(bytes)),
        REG_DWORD_BE => format!("0x{:x}", read_u32_be(bytes)),
        REG_QWORD => format!("0x{:x}", read_u64_le(bytes)),
        REG_MULTI_SZ => parse_multi_sz(bytes).join("\\0"),
        _ => to_hex_upper(bytes),
    }
}

// ---- string helpers (UTF-16LE on disk) -------------------------------------

pub fn build_sz(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity((s.len() + 1) * 2);
    for u in s.encode_utf16().chain(std::iter::once(0)) {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

pub fn parse_sz(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    if units.last() == Some(&0) {
        units.pop();
    }
    String::from_utf16_lossy(&units)
}

pub fn build_multi_sz(parts: &[&str]) -> Vec<u8> {
    let mut units: Vec<u16> = Vec::new();
    for p in parts {
        units.extend(p.encode_utf16());
        units.push(0);
    }
    units.push(0); // double terminator
    let mut out = Vec::with_capacity(units.len() * 2);
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

pub fn parse_multi_sz(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &u in &units {
        if u == 0 {
            if cur.is_empty() {
                break;
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

// ---- integer and hex helpers ----------------------------------------------

/// Parse an integer in decimal or `0x`-prefixed hexadecimal.
pub fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

/// Parse a hex string into bytes. Accepts optional spaces or commas between
/// pairs (so `0a 0b`, `0a,0b`, and `0a0b` all parse).
pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace() && *c != ',').collect();
    if !cleaned.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

pub fn to_hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

fn read_u32_le(b: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let n = b.len().min(4);
    buf[..n].copy_from_slice(&b[..n]);
    u32::from_le_bytes(buf)
}

fn read_u32_be(b: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let n = b.len().min(4);
    buf[..n].copy_from_slice(&b[..n]);
    u32::from_be_bytes(buf)
}

fn read_u64_le(b: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = b.len().min(8);
    buf[..n].copy_from_slice(&b[..n]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sz_round_trip() {
        let b = encode_cli(REG_SZ, "hello", "\\0").unwrap();
        assert_eq!(format_display(REG_SZ, &b), "hello");
        // Null terminated UTF-16LE: 6 code units * 2 bytes.
        assert_eq!(b.len(), 12);
    }

    #[test]
    fn dword_hex_and_decimal() {
        assert_eq!(encode_cli(REG_DWORD, "0x10", "").unwrap(), vec![0x10, 0, 0, 0]);
        assert_eq!(encode_cli(REG_DWORD, "16", "").unwrap(), vec![0x10, 0, 0, 0]);
        assert_eq!(format_display(REG_DWORD, &[0x10, 0, 0, 0]), "0x10");
        assert!(encode_cli(REG_DWORD, "notanumber", "").is_err());
    }

    #[test]
    fn dword_be_orders_bytes() {
        assert_eq!(encode_cli(REG_DWORD_BE, "0x01020304", "").unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn qword_round_trip() {
        let b = encode_cli(REG_QWORD, "0x1122334455667788", "").unwrap();
        assert_eq!(format_display(REG_QWORD, &b), "0x1122334455667788");
    }

    #[test]
    fn binary_hex_round_trip() {
        let b = encode_cli(REG_BINARY, "0a0B0c", "").unwrap();
        assert_eq!(b, vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(format_display(REG_BINARY, &b), "0A0B0C");
        // An odd number of hex digits is rejected.
        assert!(encode_cli(REG_BINARY, "abc", "").is_err());
    }

    #[test]
    fn multi_sz_uses_separator() {
        let b = encode_cli(REG_MULTI_SZ, "one\\0two\\0three", "\\0").unwrap();
        assert_eq!(parse_multi_sz(&b), vec!["one", "two", "three"]);
        assert_eq!(format_display(REG_MULTI_SZ, &b), "one\\0two\\0three");
        // Empty multi-sz is just the double terminator.
        let empty = encode_cli(REG_MULTI_SZ, "", "\\0").unwrap();
        assert_eq!(parse_multi_sz(&empty), Vec::<String>::new());
    }

    #[test]
    fn type_names_round_trip() {
        for ty in [REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BE, REG_LINK, REG_MULTI_SZ, REG_QWORD] {
            assert_eq!(type_from_name(type_name(ty)), Some(ty), "round trip {ty}");
        }
        assert_eq!(type_from_name("reg_dword_be"), Some(REG_DWORD_BE));
        assert_eq!(type_from_name("REG_BOGUS"), None);
    }
}
