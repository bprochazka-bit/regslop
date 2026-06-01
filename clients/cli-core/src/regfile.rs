//! Import and export of the `.reg` text format
//! (`Windows Registry Editor Version 5.00`).
//!
//! Export produces UTF-16LE with a BOM, matching what Windows `reg export` and
//! regedit write. Import accepts UTF-16LE, UTF-16BE, or UTF-8 (BOM-detected).
//! The parser yields a list of [`RegOp`] the caller applies through the mount
//! map, so this module never needs to know how roots map to files.

use crate::error::{CliError, CliResult};
use crate::session::ValueDump;
use crate::value;

pub const HEADER: &str = "Windows Registry Editor Version 5.00";

/// One operation parsed from a `.reg` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegOp {
    /// Create the key at this full display path (root included).
    AddKey(String),
    /// Delete the key at this full display path (`[-HKEY...]`).
    DelKey(String),
    /// Set a value on a key (name `""` is the default value).
    SetValue {
        key: String,
        name: String,
        ty: u32,
        data: Vec<u8>,
    },
    /// Delete a named value (`"name"=-`).
    DelValue { key: String, name: String },
}

// ---- export ----------------------------------------------------------------

/// Format the header and a blank line.
pub fn export_header() -> String {
    format!("{HEADER}\r\n\r\n")
}

/// Format one key block: the `[path]` line, then one line per value.
pub fn export_key(display_path: &str, values: &[ValueDump]) -> String {
    let mut s = format!("[{display_path}]\r\n");
    for v in values {
        s.push_str(&export_value_line(&v.name, v.ty, &v.data));
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    s
}

/// Format a single `"name"=data` (or `@=data`) line, without the line break.
pub fn export_value_line(name: &str, ty: u32, data: &[u8]) -> String {
    let lhs = if name.is_empty() {
        "@".to_string()
    } else {
        format!("\"{}\"", escape_str(name))
    };
    let rhs = match ty {
        value::REG_SZ => format!("\"{}\"", escape_str(&value::parse_sz(data))),
        value::REG_DWORD => format!("dword:{:08x}", read_u32_le(data)),
        value::REG_QWORD => format!("hex(b):{}", hex_csv(data)),
        value::REG_EXPAND_SZ => format!("hex(2):{}", hex_csv(data)),
        value::REG_BINARY => format!("hex:{}", hex_csv(data)),
        value::REG_MULTI_SZ => format!("hex(7):{}", hex_csv(data)),
        value::REG_NONE => "hex(0):".to_string(),
        other => format!("hex({:x}):{}", other, hex_csv(data)),
    };
    format!("{lhs}={rhs}")
}

/// Encode a full `.reg` document (header + blocks) as UTF-16LE with a BOM.
pub fn to_utf16le_bom(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for u in text.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

// ---- import ----------------------------------------------------------------

/// Decode `.reg` bytes (UTF-16LE/BE or UTF-8, BOM-detected) into text.
pub fn decode_text(bytes: &[u8]) -> CliResult<String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    } else {
        let start = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 };
        String::from_utf8(bytes[start..].to_vec())
            .map_err(|e| CliError::usage(format!("reg file is not valid UTF-8: {e}")))
    }
}

/// Parse a `.reg` document into a list of operations.
pub fn parse(bytes: &[u8]) -> CliResult<Vec<RegOp>> {
    let text = decode_text(bytes)?;
    let mut lines = text.lines();
    let header = lines.next().unwrap_or("").trim();
    if !header.starts_with("Windows Registry Editor Version 5")
        && !header.starts_with("REGEDIT4")
    {
        return Err(CliError::usage(format!(
            "not a recognized .reg file (first line was {header:?})"
        )));
    }

    // Reassemble continued hex lines (a line ending in '\' continues).
    let mut logical: Vec<String> = Vec::new();
    let mut acc = String::new();
    for raw in lines {
        let line = raw.trim_end();
        if acc.is_empty() && (line.trim().is_empty() || line.trim_start().starts_with(';')) {
            continue;
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            acc.push_str(stripped.trim_start());
        } else {
            acc.push_str(line.trim_start());
            logical.push(std::mem::take(&mut acc));
        }
    }
    if !acc.is_empty() {
        logical.push(acc);
    }

    let mut ops = Vec::new();
    let mut current_key: Option<String> = None;
    for line in logical {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(del) = inner.strip_prefix('-') {
                ops.push(RegOp::DelKey(del.trim().to_string()));
                current_key = None;
            } else {
                let key = inner.trim().to_string();
                ops.push(RegOp::AddKey(key.clone()));
                current_key = Some(key);
            }
            continue;
        }
        // Otherwise it is a value line under the current key.
        let key = current_key.clone().ok_or_else(|| {
            CliError::usage(format!("value line outside any key block: {line}"))
        })?;
        let (name, rhs) = split_value_line(line)?;
        if rhs.trim() == "-" {
            ops.push(RegOp::DelValue { key, name });
        } else {
            let (ty, data) = parse_value_data(rhs.trim())?;
            ops.push(RegOp::SetValue { key, name, ty, data });
        }
    }
    Ok(ops)
}

/// Split a value line into (name, rhs). `@=...` is the default value.
fn split_value_line(line: &str) -> CliResult<(String, String)> {
    if let Some(rest) = line.strip_prefix('@') {
        let rhs = rest
            .strip_prefix('=')
            .ok_or_else(|| CliError::usage(format!("malformed default value line: {line}")))?;
        return Ok((String::new(), rhs.to_string()));
    }
    if !line.starts_with('"') {
        return Err(CliError::usage(format!("malformed value line: {line}")));
    }
    // Find the closing quote, honoring backslash escapes.
    let bytes = line.as_bytes();
    let mut i = 1;
    let mut name = String::new();
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '\\' && i + 1 < bytes.len() {
            name.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if c == '"' {
            i += 1;
            break;
        }
        name.push(c);
        i += 1;
    }
    let rest = &line[i..];
    let rhs = rest
        .strip_prefix('=')
        .ok_or_else(|| CliError::usage(format!("missing '=' in value line: {line}")))?;
    Ok((name, rhs.to_string()))
}

/// Parse the right-hand side of a value line into (type code, raw bytes).
fn parse_value_data(rhs: &str) -> CliResult<(u32, Vec<u8>)> {
    if let Some(inner) = rhs.strip_prefix('"') {
        let s = inner
            .strip_suffix('"')
            .ok_or_else(|| CliError::usage(format!("unterminated string: {rhs}")))?;
        return Ok((value::REG_SZ, value::build_sz(&unescape_str(s))));
    }
    if let Some(hex) = rhs.strip_prefix("dword:") {
        let v = u32::from_str_radix(hex.trim(), 16)
            .map_err(|_| CliError::usage(format!("bad dword: {rhs}")))?;
        return Ok((value::REG_DWORD, v.to_le_bytes().to_vec()));
    }
    if let Some(rest) = rhs.strip_prefix("hex") {
        // Either "hex:" (binary) or "hex(N):" (type N).
        let (ty, payload) = if let Some(after) = rest.strip_prefix('(') {
            let (num, tail) = after
                .split_once(')')
                .ok_or_else(|| CliError::usage(format!("bad hex type: {rhs}")))?;
            let ty = u32::from_str_radix(num.trim(), 16)
                .map_err(|_| CliError::usage(format!("bad hex type number: {rhs}")))?;
            let payload = tail
                .strip_prefix(':')
                .ok_or_else(|| CliError::usage(format!("missing ':' after hex type: {rhs}")))?;
            (ty, payload)
        } else {
            let payload = rest
                .strip_prefix(':')
                .ok_or_else(|| CliError::usage(format!("missing ':' after hex: {rhs}")))?;
            (value::REG_BINARY, payload)
        };
        let bytes = parse_hex_csv(payload)?;
        return Ok((ty, bytes));
    }
    Err(CliError::usage(format!("unrecognized value data: {rhs}")))
}

// ---- small helpers ---------------------------------------------------------

fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn unescape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn hex_csv(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_hex_csv(s: &str) -> CliResult<Vec<u8>> {
    let mut out = Vec::new();
    for tok in s.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        out.push(u8::from_str_radix(t, 16).map_err(|_| CliError::usage(format!("bad hex byte: {t}")))?);
    }
    Ok(out)
}

fn read_u32_le(b: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let n = b.len().min(4);
    buf[..n].copy_from_slice(&b[..n]);
    u32::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_value_lines_match_windows_forms() {
        assert_eq!(
            export_value_line("", value::REG_SZ, &value::build_sz("hi")),
            "@=\"hi\""
        );
        assert_eq!(
            export_value_line("Count", value::REG_DWORD, &7u32.to_le_bytes()),
            "\"Count\"=dword:00000007"
        );
        assert_eq!(
            export_value_line("Bin", value::REG_BINARY, &[0x0a, 0x0b]),
            "\"Bin\"=hex:0a,0b"
        );
        assert_eq!(
            export_value_line("Path", value::REG_EXPAND_SZ, &value::build_sz("%TMP%")).split_once(':').unwrap().0,
            "\"Path\"=hex(2)"
        );
    }

    #[test]
    fn round_trips_through_parse() {
        let mut doc = export_header();
        doc.push_str(&export_key(
            "HKEY_LOCAL_MACHINE\\Software\\App",
            &[
                ValueDump { name: String::new(), ty: value::REG_SZ, data: value::build_sz("Default") },
                ValueDump { name: "Count".into(), ty: value::REG_DWORD, data: 42u32.to_le_bytes().to_vec() },
                ValueDump { name: "Blob".into(), ty: value::REG_BINARY, data: vec![1, 2, 3, 4] },
                ValueDump { name: "Multi".into(), ty: value::REG_MULTI_SZ, data: value::build_multi_sz(&["a", "b"]) },
            ],
        ));
        let ops = parse(doc.as_bytes()).unwrap();
        assert_eq!(ops[0], RegOp::AddKey("HKEY_LOCAL_MACHINE\\Software\\App".into()));
        assert!(matches!(&ops[1], RegOp::SetValue { name, ty, .. } if name.is_empty() && *ty == value::REG_SZ));
        match &ops[2] {
            RegOp::SetValue { name, ty, data, .. } => {
                assert_eq!(name, "Count");
                assert_eq!(*ty, value::REG_DWORD);
                assert_eq!(read_u32_le(data), 42);
            }
            other => panic!("expected dword set, got {other:?}"),
        }
        match &ops[4] {
            RegOp::SetValue { name, ty, data, .. } => {
                assert_eq!(name, "Multi");
                assert_eq!(*ty, value::REG_MULTI_SZ);
                assert_eq!(value::parse_multi_sz(data), vec!["a", "b"]);
            }
            other => panic!("expected multi set, got {other:?}"),
        }
    }

    #[test]
    fn parses_key_and_value_deletions() {
        let doc = format!(
            "{HEADER}\r\n\r\n[-HKEY_CURRENT_USER\\Gone]\r\n[HKEY_CURRENT_USER\\Keep]\r\n\"Old\"=-\r\n"
        );
        let ops = parse(doc.as_bytes()).unwrap();
        assert_eq!(ops[0], RegOp::DelKey("HKEY_CURRENT_USER\\Gone".into()));
        assert_eq!(ops[1], RegOp::AddKey("HKEY_CURRENT_USER\\Keep".into()));
        assert_eq!(
            ops[2],
            RegOp::DelValue { key: "HKEY_CURRENT_USER\\Keep".into(), name: "Old".into() }
        );
    }

    #[test]
    fn handles_continued_hex_lines() {
        let doc = format!(
            "{HEADER}\r\n\r\n[HKEY_USERS\\K]\r\n\"B\"=hex:01,02,\\\r\n  03,04\r\n"
        );
        let ops = parse(doc.as_bytes()).unwrap();
        match &ops[1] {
            RegOp::SetValue { data, ty, .. } => {
                assert_eq!(*ty, value::REG_BINARY);
                assert_eq!(data, &vec![1, 2, 3, 4]);
            }
            other => panic!("expected binary set, got {other:?}"),
        }
    }

    #[test]
    fn utf16_round_trip_decodes() {
        let text = format!("{HEADER}\r\n\r\n[HKEY_USERS\\K]\r\n@=\"v\"\r\n");
        let bytes = to_utf16le_bom(&text);
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        let ops = parse(&bytes).unwrap();
        assert_eq!(ops[0], RegOp::AddKey("HKEY_USERS\\K".into()));
    }

    #[test]
    fn escapes_backslashes_and_quotes() {
        let line = export_value_line("a\\b", value::REG_SZ, &value::build_sz("c\"d\\e"));
        assert_eq!(line, "\"a\\\\b\"=\"c\\\"d\\\\e\"");
        let (name, rhs) = split_value_line(&line).unwrap();
        assert_eq!(name, "a\\b");
        let (ty, data) = parse_value_data(&rhs).unwrap();
        assert_eq!(ty, value::REG_SZ);
        assert_eq!(value::parse_sz(&data), "c\"d\\e");
    }
}
