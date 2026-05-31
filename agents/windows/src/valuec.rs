//! Registry value codec: convert between offreg's (type DWORD, raw bytes) form
//! and the CONTRACTS JSON `{ type, data }` representation.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use crate::error::AgentError;
use crate::offreg::*;
use crate::util::{build_multi_sz, build_sz, parse_multi_sz, parse_sz};

/// CONTRACTS type name for an offreg type DWORD. Unknown types fall back to the
/// opaque binary representation.
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

/// offreg type DWORD for a CONTRACTS type name.
pub fn type_from_name(name: &str) -> Option<u32> {
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

/// Decode raw offreg bytes into the JSON `data` value for a given type.
pub fn decode(ty: u32, bytes: &[u8]) -> Value {
    match ty {
        REG_NONE => Value::Null,
        REG_SZ | REG_EXPAND_SZ | REG_LINK => Value::String(parse_sz(bytes)),
        REG_DWORD => {
            let v = read_u32_le(bytes);
            json!(v)
        }
        REG_DWORD_BIG_ENDIAN => {
            let v = read_u32_be(bytes);
            json!(v)
        }
        REG_QWORD => {
            let v = read_u64_le(bytes);
            // Values beyond 2^53 lose precision as JSON numbers, so emit a
            // string, as CONTRACTS specifies.
            if v > (1u64 << 53) {
                Value::String(v.to_string())
            } else {
                json!(v)
            }
        }
        REG_MULTI_SZ => Value::Array(
            parse_multi_sz(bytes)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
        // REG_BINARY and the opaque resource types.
        _ => Value::String(B64.encode(bytes)),
    }
}

/// Encode a JSON `{ type, data }` pair into (offreg type DWORD, raw bytes).
pub fn encode(type_name_in: &str, data: &Value) -> Result<(u32, Vec<u8>), AgentError> {
    let ty = type_from_name(type_name_in)
        .ok_or_else(|| AgentError::new("TYPE_MISMATCH", format!("unknown type {type_name_in}")))?;
    let mismatch = |what: &str| AgentError::new("TYPE_MISMATCH", format!("{type_name_in} expects {what}"));

    let bytes = match ty {
        REG_NONE => Vec::new(),
        REG_SZ | REG_EXPAND_SZ | REG_LINK => {
            let s = data.as_str().ok_or_else(|| mismatch("a string"))?;
            build_sz(s)
        }
        REG_BINARY | REG_RESOURCE_LIST | REG_FULL_RESOURCE_DESCRIPTOR
        | REG_RESOURCE_REQUIREMENTS_LIST => {
            let s = data.as_str().ok_or_else(|| mismatch("a base64 string"))?;
            B64.decode(s)
                .map_err(|e| AgentError::new("TYPE_MISMATCH", format!("invalid base64: {e}")))?
        }
        REG_DWORD => {
            let v = as_u64(data).ok_or_else(|| mismatch("an integer"))?;
            (v as u32).to_le_bytes().to_vec()
        }
        REG_DWORD_BIG_ENDIAN => {
            let v = as_u64(data).ok_or_else(|| mismatch("an integer"))?;
            (v as u32).to_be_bytes().to_vec()
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

/// Accept an integer from either a JSON number or a numeric string (QWORDs
/// above 2^53 arrive as strings per CONTRACTS).
fn as_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(i) = v.as_i64() {
        return Some(i as u64);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn roundtrip(type_name_in: &str, data: Value) {
        let (ty, bytes) = encode(type_name_in, &data).expect("encode");
        let back = decode(ty, &bytes);
        assert_eq!(back, data, "round trip failed for {type_name_in}");
        assert_eq!(type_name(ty), type_name_in, "type name mismatch");
    }

    #[test]
    fn sz_roundtrip() {
        roundtrip("REG_SZ", json!("hello"));
        roundtrip("REG_SZ", json!(""));
        roundtrip("REG_EXPAND_SZ", json!("%PATH%"));
        roundtrip("REG_LINK", json!("\\Registry\\Machine"));
    }

    #[test]
    fn dword_endianness() {
        let (ty, bytes) = encode("REG_DWORD", &json!(0x1234_5678u64)).unwrap();
        assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]); // little-endian
        assert_eq!(decode(ty, &bytes), json!(0x1234_5678u64));

        let (ty, bytes) = encode("REG_DWORD_BE", &json!(0x1234_5678u64)).unwrap();
        assert_eq!(bytes, vec![0x12, 0x34, 0x56, 0x78]); // big-endian
        assert_eq!(decode(ty, &bytes), json!(0x1234_5678u64));
    }

    #[test]
    fn qword_large_is_string() {
        let big = (1u64 << 60) + 7;
        let (ty, bytes) = encode("REG_QWORD", &json!(big.to_string())).unwrap();
        assert_eq!(bytes.len(), 8);
        // Beyond 2^53 the decoded form is a string, not a number.
        assert_eq!(decode(ty, &bytes), Value::String(big.to_string()));
    }

    #[test]
    fn qword_small_is_number() {
        let (ty, bytes) = encode("REG_QWORD", &json!(42)).unwrap();
        assert_eq!(decode(ty, &bytes), json!(42u64));
    }

    #[test]
    fn multi_sz_roundtrip() {
        roundtrip("REG_MULTI_SZ", json!(["alpha", "beta", "gamma"]));
        roundtrip("REG_MULTI_SZ", json!([]));
    }

    #[test]
    fn binary_base64() {
        // "AQID" is base64 for bytes [1,2,3].
        let (ty, bytes) = encode("REG_BINARY", &json!("AQID")).unwrap();
        assert_eq!(bytes, vec![1, 2, 3]);
        assert_eq!(decode(ty, &bytes), json!("AQID"));
    }

    #[test]
    fn none_is_null() {
        let (ty, bytes) = encode("REG_NONE", &Value::Null).unwrap();
        assert!(bytes.is_empty());
        assert_eq!(decode(ty, &bytes), Value::Null);
    }

    #[test]
    fn type_mismatch_is_reported() {
        let e = encode("REG_DWORD", &json!("not a number")).unwrap_err();
        assert_eq!(e.code, "TYPE_MISMATCH");
        let e = encode("REG_SZ", &json!(123)).unwrap_err();
        assert_eq!(e.code, "TYPE_MISMATCH");
    }
}
