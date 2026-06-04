//! SDDL <-> binary security descriptor conversion for the libreg backend.
//!
//! Security descriptors travel on the wire as SDDL (CONTRACTS "Security"); the
//! agent owns the conversion to and from the self-relative binary form (ADR
//! 0003). libreg stores and returns the binary descriptor (`key_security` /
//! `set_key_security`) and provides the on-disk codec (`format::security_descriptor`),
//! so this module only bridges SDDL text and those structured types.
//!
//! Scope: owner, group, and a DACL of access-allowed/denied ACEs, which is what
//! offline-hive key security uses. Well-known SID aliases and key-rights tokens
//! offreg emits are recognized by name (so the harness comparator, which keys on
//! the SDDL tokens, matches); anything else falls back to `S-1-...` / `0x...`.

use crate::error::{AgentError, Result};
use libreg::format::security_descriptor as sd;
use sd::{Ace, Acl, SecurityDescriptor, Sid};

const ACCESS_ALLOWED: u8 = 0x00;
const ACCESS_DENIED: u8 = 0x01;

// --- SID <-> string ---

fn authority_value(sid: &Sid) -> u64 {
    sid.identifier_authority.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

/// Well-known SID aliases with fixed, absolute SIDs (the standard SDDL "SID
/// String" table). Used in BOTH directions so a round-trip preserves the alias
/// offreg emits and the harness comparator (which keys on SDDL tokens) matches.
/// These are the abbreviations that appear in real registry ACLs, e.g. AU
/// (Authenticated Users, S-1-5-11) and CO (Creator Owner, S-1-3-0). Issue #102.
///
/// The domain-relative abbreviations (LA = local administrator RID 500, LG =
/// local guest RID 501) are intentionally absent: they expand to
/// `S-1-5-21-<machine>-50x`, which has no fixed value for an offline hive with no
/// machine context (even Win32 `ConvertStringSidToSid` rejects them standalone),
/// so they fall through to the `S-1-...` path rather than being given a fabricated
/// SID that would not round-trip against offreg.
const SID_ALIASES: &[(&str, u64, &[u32])] = &[
    ("SY", 5, &[18]),         // Local System
    ("BA", 5, &[32, 544]),    // Built-in Administrators
    ("BU", 5, &[32, 545]),    // Built-in Users
    ("WD", 1, &[0]),          // Everyone
    ("RC", 5, &[12]),         // Restricted Code
    ("AU", 5, &[11]),         // Authenticated Users
    ("AN", 5, &[7]),          // Anonymous
    ("IU", 5, &[4]),          // Interactive
    ("NU", 5, &[2]),          // Network
    ("SU", 5, &[6]),          // Service
    ("CO", 3, &[0]),          // Creator Owner
    ("CG", 3, &[1]),          // Creator Group
    ("WR", 5, &[33]),         // Write Restricted Code
    ("PU", 5, &[32, 547]),    // Power Users
    ("AO", 5, &[32, 548]),    // Account Operators
    ("BG", 5, &[32, 546]),    // Built-in Guests
    ("BO", 5, &[32, 551]),    // Backup Operators
    ("ER", 5, &[32, 573]),    // Event Log Readers
];

fn sid_to_string(sid: &Sid) -> String {
    let auth = authority_value(sid);
    let subs = sid.sub_authorities.as_slice();
    for (alias, a, s) in SID_ALIASES {
        if *a == auth && *s == subs {
            return alias.to_string();
        }
    }
    let mut s = format!("S-1-{auth}");
    for sub in subs {
        s.push_str(&format!("-{sub}"));
    }
    s
}

fn sid_from_string(s: &str) -> Result<Sid> {
    for (alias, auth, subs) in SID_ALIASES {
        if *alias == s {
            return Ok(Sid::new(*auth as u8, subs));
        }
    }
    if let Some(rest) = s.strip_prefix("S-1-") {
        let mut parts = rest.split('-');
        let auth: u64 = parts
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| AgentError::bad_request(format!("bad SID authority in {s}")))?;
        if auth > u8::MAX as u64 {
            return Err(AgentError::bad_request(format!("SID authority too large in {s}")));
        }
        let mut subs = Vec::new();
        for p in parts {
            subs.push(p.parse().map_err(|_| AgentError::bad_request(format!("bad sub-authority in {s}")))?);
        }
        return Ok(Sid::new(auth as u8, &subs));
    }
    Err(AgentError::bad_request(format!("unknown SID or alias: {s}")))
}

// --- access mask <-> rights token ---

fn mask_to_string(mask: u32) -> String {
    match mask {
        sd::KEY_ALL_ACCESS => "KA".to_string(),
        sd::KEY_READ => "KR".to_string(),
        other => format!("0x{other:x}"),
    }
}

fn mask_from_string(s: &str) -> Result<u32> {
    match s {
        "KA" => Ok(sd::KEY_ALL_ACCESS),
        "KR" => Ok(sd::KEY_READ),
        _ if s.starts_with("0x") || s.starts_with("0X") => u32::from_str_radix(&s[2..], 16)
            .map_err(|_| AgentError::bad_request(format!("bad access mask: {s}"))),
        _ => Err(AgentError::bad_request(format!("unknown rights token: {s}"))),
    }
}

// --- ACE flags <-> token string ---

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

fn flags_from_string(s: &str) -> Result<u8> {
    let s = s.to_uppercase();
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(AgentError::bad_request(format!("odd-length ACE flags: {s}")));
    }
    let mut flags = 0u8;
    for pair in bytes.chunks(2) {
        let tok = std::str::from_utf8(pair).unwrap_or("");
        match FLAG_TABLE.iter().find(|(_, t)| *t == tok) {
            Some((bit, _)) => flags |= bit,
            None => return Err(AgentError::bad_request(format!("unknown ACE flag token: {tok}"))),
        }
    }
    Ok(flags)
}

// --- ACE <-> SDDL ---

fn ace_to_string(ace: &Ace) -> Result<String> {
    let ty = match ace.ace_type {
        ACCESS_ALLOWED => "A",
        ACCESS_DENIED => "D",
        other => return Err(AgentError::bad_request(format!("unsupported ACE type {other:#x}"))),
    };
    // (type;flags;rights;object_guid;inherit_object_guid;sid)
    Ok(format!(
        "({ty};{};{};;;{})",
        flags_to_string(ace.flags),
        mask_to_string(ace.mask),
        sid_to_string(&ace.sid)
    ))
}

fn ace_from_string(inner: &str) -> Result<Ace> {
    let f: Vec<&str> = inner.split(';').collect();
    if f.len() < 6 {
        return Err(AgentError::bad_request(format!("malformed ACE: ({inner})")));
    }
    let ace_type = match f[0].trim().to_uppercase().as_str() {
        "A" => ACCESS_ALLOWED,
        "D" => ACCESS_DENIED,
        other => return Err(AgentError::bad_request(format!("unsupported ACE type: {other}"))),
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

// --- top level ---

/// Convert a libreg binary security descriptor to its SDDL string.
pub fn to_sddl(bytes: &[u8]) -> Result<String> {
    let desc = SecurityDescriptor::parse(bytes)
        .map_err(|e| AgentError::new(crate::error::Code::HiveCorrupt, format!("bad security descriptor: {e}")))?;
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
pub fn from_sddl(sddl: &str) -> Result<Vec<u8>> {
    let mut desc = SecurityDescriptor { control: 0, owner: None, group: None, dacl: None, sacl: None };
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
            // SACL is accepted but dropped: offline key security is owner/group
            // /DACL, and the harness compares the SACL only when both sides have
            // one (ADR 0003). Storing one is out of scope here.
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
        // SDDL -> binary -> SDDL is stable.
        assert_eq!(to_sddl(&from_sddl(&sddl).unwrap()).unwrap(), sddl);
    }

    #[test]
    fn custom_descriptor_round_trips() {
        let sddl = "O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;BU)";
        assert_eq!(to_sddl(&from_sddl(sddl).unwrap()).unwrap(), sddl);
    }

    #[test]
    fn standard_sid_aliases_round_trip() {
        // Every absolute alias parses and emits back to the same token (issue #102).
        for (alias, _, _) in SID_ALIASES {
            let sddl = format!("O:BAG:BAD:(A;;KA;;;{alias})");
            let got = to_sddl(&from_sddl(&sddl).unwrap()).unwrap();
            assert_eq!(got, sddl, "alias {alias} did not round-trip");
        }
        // AU and CO in particular (the ones that appear constantly) must parse.
        assert!(from_sddl("O:BAG:BAD:(A;;KA;;;AU)").is_ok());
        assert!(from_sddl("O:BAG:BAD:(A;;KA;;;CO)").is_ok());
    }

    #[test]
    fn domain_relative_aliases_fall_through() {
        // LA/LG have no fixed offline SID; they are not invented as aliases.
        assert!(from_sddl("O:BAG:BAD:(A;;KA;;;LA)").is_err());
    }

    #[test]
    fn generic_sid_and_hex_mask() {
        // A SID without a well-known alias and a non-standard mask.
        let sddl = "O:BAG:BAD:(A;;0x1;;;S-1-5-21-7-8-9)";
        let parsed = to_sddl(&from_sddl(sddl).unwrap()).unwrap();
        assert!(parsed.contains("S-1-5-21-7-8-9"), "{parsed}");
        assert!(parsed.contains("0x1"), "{parsed}");
    }
}
