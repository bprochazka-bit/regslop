//! SDDL <-> binary security descriptor conversion for the client utilities.
//!
//! libreg stores key security as a self-relative binary descriptor
//! (`Hive::key_security` returns the bytes, `set_key_security` takes them) and
//! provides the on-disk codec in `format::security_descriptor`. This module
//! bridges that binary form and the human-readable SDDL string so `regedit` can
//! display and edit permissions.
//!
//! It mirrors the agent-side codec (`agents/linux/src/sddl.rs`) so the SDDL
//! tokens match what the agents and the differential harness emit (ADR 0003):
//! owner, group, and a DACL of access-allowed/denied ACEs, with well-known SID
//! aliases and key-rights tokens recognized by name, and `S-1-...` / `0x...`
//! fallbacks for everything else. We cannot import the agent's copy (different
//! subtree, different error type), so the logic is duplicated here.

use crate::error::{CliError, CliResult};
use libreg::format::security_descriptor as sd;
use sd::{Ace, Acl, SecurityDescriptor, Sid};

const ACCESS_ALLOWED: u8 = 0x00;
const ACCESS_DENIED: u8 = 0x01;

// --- SID <-> string ---------------------------------------------------------

fn authority_value(sid: &Sid) -> u64 {
    sid.identifier_authority.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

fn sid_to_string(sid: &Sid) -> String {
    match (authority_value(sid), sid.sub_authorities.as_slice()) {
        (5, [18]) => "SY".to_string(),
        (5, [32, 544]) => "BA".to_string(),
        (5, [32, 545]) => "BU".to_string(),
        (1, [0]) => "WD".to_string(),
        (5, [12]) => "RC".to_string(),
        (auth, subs) => {
            let mut s = format!("S-1-{auth}");
            for sub in subs {
                s.push_str(&format!("-{sub}"));
            }
            s
        }
    }
}

fn sid_from_string(s: &str) -> CliResult<Sid> {
    Ok(match s {
        "SY" => Sid::local_system(),
        "BA" => Sid::administrators(),
        "BU" => Sid::new(5, &[32, 545]),
        "WD" => Sid::everyone(),
        "RC" => Sid::restricted_code(),
        _ if s.starts_with("S-1-") => {
            let mut parts = s[4..].split('-');
            let auth: u64 = parts
                .next()
                .and_then(|p| p.parse().ok())
                .ok_or_else(|| CliError::usage(format!("bad SID authority in {s}")))?;
            if auth > u8::MAX as u64 {
                return Err(CliError::usage(format!("SID authority too large in {s}")));
            }
            let mut subs = Vec::new();
            for p in parts {
                subs.push(p.parse().map_err(|_| CliError::usage(format!("bad sub-authority in {s}")))?);
            }
            Sid::new(auth as u8, &subs)
        }
        _ => return Err(CliError::usage(format!("unknown SID or alias: {s}"))),
    })
}

// --- access mask <-> rights token -------------------------------------------

fn mask_to_string(mask: u32) -> String {
    match mask {
        sd::KEY_ALL_ACCESS => "KA".to_string(),
        sd::KEY_READ => "KR".to_string(),
        other => format!("0x{other:x}"),
    }
}

fn mask_from_string(s: &str) -> CliResult<u32> {
    match s {
        "KA" => Ok(sd::KEY_ALL_ACCESS),
        "KR" => Ok(sd::KEY_READ),
        _ if s.starts_with("0x") || s.starts_with("0X") => {
            u32::from_str_radix(&s[2..], 16).map_err(|_| CliError::usage(format!("bad access mask: {s}")))
        }
        _ => Err(CliError::usage(format!("unknown rights token: {s}"))),
    }
}

// --- ACE flags <-> token string ---------------------------------------------

const FLAG_TABLE: &[(u8, &str)] = &[
    (0x01, "OI"), // OBJECT_INHERIT_ACE
    (0x02, "CI"), // CONTAINER_INHERIT_ACE
    (0x04, "NP"), // NO_PROPAGATE_INHERIT_ACE
    (0x08, "IO"), // INHERIT_ONLY_ACE
    (0x10, "ID"), // INHERITED_ACE
];

fn flags_to_string(flags: u8) -> String {
    let mut out = String::new();
    for (bit, tok) in FLAG_TABLE {
        if flags & bit != 0 {
            out.push_str(tok);
        }
    }
    out
}

fn flags_from_string(s: &str) -> CliResult<u8> {
    let s = s.to_uppercase();
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(CliError::usage(format!("odd-length ACE flags: {s}")));
    }
    let mut flags = 0u8;
    for pair in bytes.chunks(2) {
        let tok = std::str::from_utf8(pair).unwrap_or("");
        match FLAG_TABLE.iter().find(|(_, t)| *t == tok) {
            Some((bit, _)) => flags |= bit,
            None => return Err(CliError::usage(format!("unknown ACE flag token: {tok}"))),
        }
    }
    Ok(flags)
}

// --- ACE <-> SDDL -----------------------------------------------------------

fn ace_to_string(ace: &Ace) -> CliResult<String> {
    let ty = match ace.ace_type {
        ACCESS_ALLOWED => "A",
        ACCESS_DENIED => "D",
        other => return Err(CliError::usage(format!("unsupported ACE type {other:#x}"))),
    };
    // (type;flags;rights;object_guid;inherit_object_guid;sid)
    Ok(format!(
        "({ty};{};{};;;{})",
        flags_to_string(ace.flags),
        mask_to_string(ace.mask),
        sid_to_string(&ace.sid)
    ))
}

fn ace_from_string(inner: &str) -> CliResult<Ace> {
    let f: Vec<&str> = inner.split(';').collect();
    if f.len() < 6 {
        return Err(CliError::usage(format!("malformed ACE: ({inner})")));
    }
    let ace_type = match f[0].trim().to_uppercase().as_str() {
        "A" => ACCESS_ALLOWED,
        "D" => ACCESS_DENIED,
        other => return Err(CliError::usage(format!("unsupported ACE type: {other}"))),
    };
    let flags = flags_from_string(f[1].trim())?;
    let mask = mask_from_string(f[2].trim())?;
    let sid = sid_from_string(f[5].trim())?;
    Ok(Ace { ace_type, flags, mask, sid })
}

/// Split a DACL/SACL body into its `(...)` ACE groups.
fn split_aces(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '(' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != ')' {
                j += 1;
            }
            out.push(chars[i + 1..j].iter().collect());
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

// --- top level --------------------------------------------------------------

/// Convert a libreg binary security descriptor to its SDDL string.
pub fn to_sddl(bytes: &[u8]) -> CliResult<String> {
    let desc = SecurityDescriptor::parse(bytes)
        .map_err(|e| CliError::Hive(format!("bad security descriptor: {e}")))?;
    let mut out = String::new();
    if let Some(owner) = &desc.owner {
        out.push_str(&format!("O:{}", sid_to_string(owner)));
    }
    if let Some(group) = &desc.group {
        out.push_str(&format!("G:{}", sid_to_string(group)));
    }
    if let Some(dacl) = &desc.dacl {
        out.push_str("D:");
        for ace in &dacl.aces {
            out.push_str(&ace_to_string(ace)?);
        }
    }
    Ok(out)
}

/// Parse an SDDL string into a libreg binary security descriptor.
pub fn from_sddl(sddl: &str) -> CliResult<Vec<u8>> {
    let mut desc = SecurityDescriptor {
        control: 0,
        owner: None,
        group: None,
        dacl: None,
        sacl: None,
    };
    for (letter, body) in split_components(sddl) {
        match letter {
            'O' => desc.owner = Some(sid_from_string(body.trim())?),
            'G' => desc.group = Some(sid_from_string(body.trim())?),
            'D' => {
                let mut aces = Vec::new();
                for inner in split_aces(&body) {
                    aces.push(ace_from_string(&inner)?);
                }
                desc.dacl = Some(Acl::new(aces));
            }
            // SACL is accepted but dropped: offline key security is
            // owner/group/DACL, and the harness compares the SACL only when both
            // sides have one (ADR 0003). Storing one is out of scope here.
            'S' => {}
            _ => {}
        }
    }
    Ok(desc.to_bytes())
}

/// Split an SDDL string into its `O:`/`G:`/`D:`/`S:` components, respecting
/// parenthesis depth so ACE bodies are not mistaken for component markers.
fn split_components(s: &str) -> Vec<(char, String)> {
    let chars: Vec<char> = s.chars().collect();
    let mut depth = 0i32;
    let mut starts: Vec<usize> = Vec::new();
    for i in 0..chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => depth -= 1,
            'O' | 'G' | 'D' | 'S' if depth == 0 && chars.get(i + 1) == Some(&':') => starts.push(i),
            _ => {}
        }
    }
    let mut out = Vec::new();
    for (k, &start) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(chars.len());
        out.push((chars[start], chars[start + 2..end].iter().collect()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_descriptor_round_trips() {
        let bytes = sd::default_key_security_descriptor_bytes();
        let sddl = to_sddl(&bytes).unwrap();
        assert_eq!(sddl, "O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)");
        // SDDL -> binary -> SDDL is stable, and binary matches libreg's default.
        assert_eq!(from_sddl(&sddl).unwrap(), bytes);
        assert_eq!(to_sddl(&from_sddl(&sddl).unwrap()).unwrap(), sddl);
    }

    #[test]
    fn custom_descriptor_round_trips() {
        let sddl = "O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;BU)";
        assert_eq!(to_sddl(&from_sddl(sddl).unwrap()).unwrap(), sddl);
    }

    #[test]
    fn generic_sid_and_hex_mask() {
        let sddl = "O:BAG:BAD:(A;;0x1;;;S-1-5-21-7-8-9)";
        let parsed = to_sddl(&from_sddl(sddl).unwrap()).unwrap();
        assert!(parsed.contains("S-1-5-21-7-8-9"), "{parsed}");
        assert!(parsed.contains("0x1"), "{parsed}");
    }

    #[test]
    fn deny_ace_and_inherit_flags() {
        let sddl = "O:SYG:SYD:(D;OICI;KA;;;WD)";
        assert_eq!(to_sddl(&from_sddl(sddl).unwrap()).unwrap(), sddl);
    }
}
