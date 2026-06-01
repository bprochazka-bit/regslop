//! A tiny JSON writer (no external crates).
//!
//! Just enough to build response objects and arrays of strings. We never need
//! to parse JSON: request bodies arrive as URL-encoded form data.

/// Escape and quote a string as a JSON string literal.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A JSON array of strings.
pub fn string_array(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| string(s)).collect();
    format!("[{}]", parts.join(","))
}

/// A JSON object from pre-rendered `("key", raw_json_value)` pairs.
pub fn object(fields: &[(&str, String)]) -> String {
    let parts: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{}:{}", string(k), v))
        .collect();
    format!("{{{}}}", parts.join(","))
}
