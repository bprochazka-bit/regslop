//! Registry value codec: convert between libreg's (REG type code, raw bytes)
//! form and the CONTRACTS JSON `{ type, data }` representation. Mirrors
//! agents/windows/src/valuec.rs so the two agents emit identical canonical
//! `data`, with the Linux error codes (BAD_REQUEST for an unknown type name,
//! TYPE_MISMATCH for a known type carrying the wrong shape; CONTRACTS 0.1.4).

use crate::error::{AgentError, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

const REG_NONE: u32 = 0;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_DWORD_BIG_ENDIAN: u32 = 5;
const REG_LINK: u32 = 6;
const REG_MULTI_SZ: u32 = 7;
const REG_RESOURCE_LIST: u32 = 8;
const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
const REG_QWORD: u32 = 11;

/// CONTRACTS type name for a REG type code. Unknown codes fall back to the
/// opaque binary representation (base64), as the contract allows.
pub fn type_name(ty: u32) -> &'static str {
    match ty {
        REG_NONE => "REG_NONE",
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY => "REG_BINARY",
        REG_DWORD => "REG_DWORD",
        REG_DWORD_BIG_ENDIAN => "REG_DWORD_BE",
        REG_LINK => "REG_LINK",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_RESOURCE_LIST => "REG_RESOURCE_LIST",
        REG_FULL_RESOURCE_DESCRIPTOR => "REG_FULL_RESOURCE_DESCRIPTOR",
        REG_RESOURCE_REQUIREMENTS_LIST => "REG_RESOURCE_REQUIREMENTS_LIST",
        REG_QWORD => "REG_QWORD",
        _ => "REG_BINARY",
    }
}

fn type_from_name(name: &str) -> Option<u32> {
    Some(match name {
        "REG_NONE" => REG_NONE,
        "REG_SZ" => REG_SZ,
        "REG_EXPAND_SZ" => REG_EXPAND_SZ,
        "REG_BINARY" => REG_BINARY,
        "REG_DWORD" => REG_DWORD,
        "REG_DWORD_BE" => REG_DWORD_BIG_ENDIAN,
        "REG_LINK" => REG_LINK,
        "REG_MULTI_SZ" => REG_MULTI_SZ,
        "REG_RESOURCE_LIST" => REG_RESOURCE_LIST,
        "REG_FULL_RESOURCE_DESCRIPTOR" => REG_FULL_RESOURCE_DESCRIPTOR,
        "REG_RESOURCE_REQUIREMENTS_LIST" => REG_RESOURCE_REQUIREMENTS_LIST,
        "REG_QWORD" => REG_QWORD,
        _ => return None,
    })
}

/// Decode raw value bytes into the JSON `data` for a given type code.
pub fn decode(ty: u32, bytes: &[u8]) -> Value {
    match ty {
        REG_NONE => Value::Null,
        REG_SZ | REG_EXPAND_SZ | REG_LINK => Value::String(parse_sz(bytes)),
        REG_DWORD => json!(read_u32_le(bytes)),
        REG_DWORD_BIG_ENDIAN => json!(read_u32_be(bytes)),
        REG_QWORD => {
            let v = read_u64_le(bytes);
            // Beyond 2^53 a JSON number loses precision, so emit a string
            // (CONTRACTS), matching the Windows agent's v > (1<<53) rule.
            if v > (1u64 << 53) {
                Value::String(v.to_string())
            } else {
                json!(v)
            }
        }
        REG_MULTI_SZ => Value::Array(parse_multi_sz(bytes).into_iter().map(Value::String).collect()),
        // REG_BINARY and the opaque resource types.
        _ => Value::String(B64.encode(bytes)),
    }
}

/// Encode a `{ type, data }` pair into (REG type code, raw bytes) for storage.
/// An unknown type name is BAD_REQUEST; a known type with the wrong data shape
/// is TYPE_MISMATCH.
pub fn encode(type_name_in: &str, data: &Value) -> Result<(u32, Vec<u8>)> {
    let ty = type_from_name(type_name_in)
        .ok_or_else(|| AgentError::bad_request(format!("unknown value type: {type_name_in}")))?;
    let mismatch = |what: &str| AgentError::type_mismatch(format!("{type_name_in} expects {what}"));

    let bytes = match ty {
        REG_NONE => Vec::new(),
        REG_SZ | REG_EXPAND_SZ | REG_LINK => build_sz(data.as_str().ok_or_else(|| mismatch("a string"))?),
        REG_BINARY | REG_RESOURCE_LIST | REG_FULL_RESOURCE_DESCRIPTOR | REG_RESOURCE_REQUIREMENTS_LIST => {
            let s = data.as_str().ok_or_else(|| mismatch("a base64 string"))?;
            B64.decode(s).map_err(|e| AgentError::type_mismatch(format!("invalid base64: {e}")))?
        }
        REG_DWORD => {
            let v = as_u32(data).ok_or_else(|| mismatch("a 32-bit integer"))?;
            v.to_le_bytes().to_vec()
        }
        REG_DWORD_BIG_ENDIAN => {
            let v = as_u32(data).ok_or_else(|| mismatch("a 32-bit integer"))?;
            v.to_be_bytes().to_vec()
        }
        REG_QWORD => {
            let v = as_u64(data).ok_or_else(|| mismatch("an integer or numeric string"))?;
            v.to_le_bytes().to_vec()
        }
        REG_MULTI_SZ => {
            let arr = data.as_array().ok_or_else(|| mismatch("an array of strings"))?;
            let mut strings = Vec::with_capacity(arr.len());
            for item in arr {
                strings.push(item.as_str().ok_or_else(|| mismatch("an array of strings"))?.to_string());
            }
            build_multi_sz(&strings)
        }
        _ => return Err(mismatch("a supported type")),
    };
    Ok((ty, bytes))
}

fn as_u32(v: &Value) -> Option<u32> {
    v.as_u64().filter(|n| *n <= u32::MAX as u64).map(|n| n as u32)
}

/// Accept an integer from a JSON number or a numeric string (QWORDs above 2^53
/// arrive as strings per CONTRACTS).
fn as_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.parse::<u64>().ok())
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

fn build_sz(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((s.len() + 1) * 2);
    for u in s.encode_utf16().chain(std::iter::once(0)) {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes
}

fn parse_sz(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    if units.last() == Some(&0) {
        units.pop();
    }
    String::from_utf16_lossy(&units)
}

fn build_multi_sz(strings: &[String]) -> Vec<u8> {
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

fn parse_multi_sz(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &u in &units {
        if u == 0 {
            if cur.is_empty() {
                break; // final terminator
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Code;

    fn roundtrip(name: &str, data: Value) {
        let (ty, bytes) = encode(name, &data).expect("encode");
        assert_eq!(decode(ty, &bytes), data, "round trip failed for {name}");
        assert_eq!(type_name(ty), name, "type name mismatch");
    }

    #[test]
    fn sz_and_multi_roundtrip() {
        roundtrip("REG_SZ", json!("hello"));
        roundtrip("REG_SZ", json!(""));
        roundtrip("REG_EXPAND_SZ", json!("%PATH%"));
        roundtrip("REG_MULTI_SZ", json!(["one", "two", "three"]));
        roundtrip("REG_MULTI_SZ", json!([]));
    }

    #[test]
    fn dword_endianness_and_qword_threshold() {
        let (ty, bytes) = encode("REG_DWORD", &json!(0x1234_5678u64)).unwrap();
        assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(decode(ty, &bytes), json!(0x1234_5678u64));

        let (ty, bytes) = encode("REG_DWORD_BE", &json!(0x1234_5678u64)).unwrap();
        assert_eq!(bytes, vec![0x12, 0x34, 0x56, 0x78]);

        // 2^32 < 2^53 -> number; 2^60 -> string.
        let (ty, bytes) = encode("REG_QWORD", &json!("4294967296")).unwrap();
        assert_eq!(decode(ty, &bytes), json!(4294967296u64));
        let big = (1u64 << 60) + 7;
        let (ty, bytes) = encode("REG_QWORD", &json!(big.to_string())).unwrap();
        assert_eq!(decode(ty, &bytes), Value::String(big.to_string()));
    }

    #[test]
    fn binary_and_none() {
        let (ty, bytes) = encode("REG_BINARY", &json!("AQID")).unwrap();
        assert_eq!(bytes, vec![1, 2, 3]);
        assert_eq!(decode(ty, &bytes), json!("AQID"));
        let (ty, bytes) = encode("REG_NONE", &Value::Null).unwrap();
        assert!(bytes.is_empty());
        assert_eq!(decode(ty, &bytes), Value::Null);
    }

    #[test]
    fn error_codes_match_contract() {
        // Unknown type name -> BAD_REQUEST (0.1.4); wrong shape -> TYPE_MISMATCH.
        assert_eq!(encode("REG_NOPE", &json!(1)).unwrap_err().code, Code::BadRequest);
        assert_eq!(encode("REG_DWORD", &json!("nan")).unwrap_err().code, Code::TypeMismatch);
        assert_eq!(encode("REG_SZ", &json!(123)).unwrap_err().code, Code::TypeMismatch);
    }
}
