//! SDDL parser and security-descriptor comparator, per ADR 0003
//! (docs/adr/0003-sddl-security.md) and the "Security" section of CONTRACTS
//! 0.1.2.
//!
//! Security descriptors travel as SDDL strings, but semantic equality is NOT
//! decided by comparing those strings: SDDL is not canonical (ACE ordering and
//! component spacing differ between producers for descriptors that are
//! semantically identical). Instead we parse each side back into owner SID,
//! group SID, and the DACL/SACL ACE lists, then compare:
//!
//!   - owner SID and group SID for exact equality;
//!   - DACL as an ACE list in canonical category order (explicit deny, explicit
//!     allow, inherited deny, inherited allow), each ACE compared by
//!     (type, flags, access mask, trustee SID);
//!   - the SACL the same way, but ONLY when BOTH sides report one. Offline
//!     hives do not always expose a readable SACL and offreg may omit it, so a
//!     one-sided SACL is "not comparable", never a semantic difference.
//!
//! `compare` returns only genuine differences. A one-sided SACL produces no
//! difference by design (see `one_sided_sacl` for callers that want to surface
//! it as a warning).

/// One parsed access control entry. Tokens are upper-cased and, where order is
/// not meaningful (flag and rights alias lists), canonicalized so benign
/// formatting differences do not register as semantic differences.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ace {
    ace_type: String,
    ace_flags: String,
    rights: String,
    object_guid: String,
    inherit_object_guid: String,
    trustee: String,
}

impl Ace {
    fn parse(inner: &str) -> Ace {
        let f: Vec<String> = inner.split(';').map(|x| x.trim().to_uppercase()).collect();
        let g = |n: usize| f.get(n).cloned().unwrap_or_default();
        Ace {
            ace_type: g(0),
            ace_flags: canon_tokens(&g(1)),
            rights: canon_tokens(&g(2)),
            object_guid: g(3),
            inherit_object_guid: g(4),
            trustee: g(5),
        }
    }

    /// Canonical category for Windows ACE ordering: explicit deny (0), explicit
    /// allow (1), inherited deny (2), inherited allow (3). Inherited ACEs carry
    /// the `ID` flag; deny ACE types start with `D` (`D`, `OD`).
    fn category(&self) -> u8 {
        let inherited = self.ace_flags.contains("ID");
        let deny = self.ace_type.ends_with('D'); // "D" or "OD"
        match (inherited, deny) {
            (false, true) => 0,
            (false, false) => 1,
            (true, true) => 2,
            (true, false) => 3,
        }
    }
}

/// Canonicalize a token list made of two-character aliases (ACE flags like
/// `CIOIID`, rights like `KAKR`) by splitting into pairs and sorting, so the
/// same set in a different emission order compares equal. A hex access mask
/// (`0X...`) or any odd or non-alphabetic string is left as-is.
fn canon_tokens(s: &str) -> String {
    let s = s.trim().to_uppercase();
    if s.is_empty() || s.starts_with("0X") || s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_alphabetic()) {
        return s;
    }
    let mut pairs: Vec<String> = s.as_bytes().chunks(2).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    pairs.sort();
    pairs.concat()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Acl {
    /// ACL flags prefix (e.g. `P`, `AI`, `AR`), upper-cased. These carry
    /// meaning-bearing control bits (protected, auto-inherited).
    flags: String,
    aces: Vec<Ace>,
}

impl Acl {
    fn parse(body: &str) -> Acl {
        let first_paren = body.find('(');
        let (flags, rest) = match first_paren {
            Some(p) => (body[..p].to_string(), &body[p..]),
            None => (body.to_string(), ""),
        };
        let chars: Vec<char> = rest.chars().collect();
        let mut aces = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '(' {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != ')' {
                    j += 1;
                }
                let inner: String = chars[i + 1..j].iter().collect();
                aces.push(Ace::parse(&inner));
                i = j + 1;
            } else {
                i += 1;
            }
        }
        // Stable sort into canonical category order; relative order within a
        // category (which Windows preserves) is left untouched.
        aces.sort_by_key(Ace::category);
        Acl { flags: flags.trim().to_uppercase(), aces }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Descriptor {
    owner: Option<String>,
    group: Option<String>,
    dacl: Option<Acl>,
    sacl: Option<Acl>,
}

impl Descriptor {
    fn parse(sddl: &str) -> Descriptor {
        let mut d = Descriptor { owner: None, group: None, dacl: None, sacl: None };
        for (letter, body) in split_components(sddl) {
            match letter {
                'O' => d.owner = Some(body.trim().to_uppercase()),
                'G' => d.group = Some(body.trim().to_uppercase()),
                'D' => d.dacl = Some(Acl::parse(body.trim())),
                'S' => d.sacl = Some(Acl::parse(body.trim())),
                _ => {}
            }
        }
        d
    }
}

/// Split an SDDL string into its `O:`/`G:`/`D:`/`S:` components. Scanning
/// respects parenthesis depth so ACE bodies (which contain SIDs and rights) are
/// never mistaken for component markers. A marker is one of O/G/D/S at depth 0
/// immediately followed by `:`; SID bodies contain no such two-character
/// sequence at depth 0, so this is unambiguous.
fn split_components(s: &str) -> Vec<(char, String)> {
    let chars: Vec<char> = s.chars().collect();
    let mut depth = 0i32;
    let mut starts: Vec<usize> = Vec::new();
    for i in 0..chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => depth -= 1,
            'O' | 'G' | 'D' | 'S' if depth == 0 && chars.get(i + 1) == Some(&':') => {
                starts.push(i);
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for (k, &start) in starts.iter().enumerate() {
        let letter = chars[start];
        let body_start = start + 2; // skip the letter and ':'
        let body_end = starts.get(k + 1).copied().unwrap_or(chars.len());
        let body: String = chars[body_start..body_end].iter().collect();
        out.push((letter, body));
    }
    out
}

/// True when exactly one of the two descriptors reports a SACL. The harness
/// treats this as "not comparable" (a warning), never a semantic difference.
pub fn one_sided_sacl(left: &str, right: &str) -> bool {
    let l = Descriptor::parse(left);
    let r = Descriptor::parse(right);
    l.sacl.is_some() != r.sacl.is_some()
}

/// Compare two SDDL strings as normalized security descriptors. Returns a list
/// of human-readable differences; an empty list means semantically equal. A
/// one-sided SACL is excluded (see module docs and `one_sided_sacl`).
pub fn compare(left: &str, right: &str) -> Vec<String> {
    if left == right {
        return Vec::new();
    }
    let l = Descriptor::parse(left);
    let r = Descriptor::parse(right);
    let mut out = Vec::new();

    if l.owner != r.owner {
        out.push(format!("owner differs: left={:?}, right={:?}", l.owner, r.owner));
    }
    if l.group != r.group {
        out.push(format!("group differs: left={:?}, right={:?}", l.group, r.group));
    }
    diff_acl("DACL", &l.dacl, &r.dacl, &mut out);

    // SACL only when both sides report one.
    match (&l.sacl, &r.sacl) {
        (Some(_), Some(_)) => diff_acl("SACL", &l.sacl, &r.sacl, &mut out),
        _ => {} // one-sided or absent: not comparable
    }
    out
}

fn diff_acl(which: &str, l: &Option<Acl>, r: &Option<Acl>, out: &mut Vec<String>) {
    match (l, r) {
        (Some(la), Some(ra)) => {
            if la.flags != ra.flags {
                out.push(format!("{which} flags differ: left={:?}, right={:?}", la.flags, ra.flags));
            }
            if la.aces.len() != ra.aces.len() {
                out.push(format!(
                    "{which} ACE count differs: left={}, right={}",
                    la.aces.len(),
                    ra.aces.len()
                ));
                return;
            }
            for (i, (lace, race)) in la.aces.iter().zip(ra.aces.iter()).enumerate() {
                if lace != race {
                    out.push(format!("{which} ACE[{i}] differs: left={lace:?}, right={race:?}"));
                }
            }
        }
        (Some(_), None) => out.push(format!("{which} present on left, absent on right")),
        (None, Some(_)) => out.push(format!("{which} absent on left, present on right")),
        (None, None) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_descriptors_are_equal() {
        let s = "O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;BU)";
        assert!(compare(s, s).is_empty());
    }

    #[test]
    fn within_category_order_is_significant() {
        // ADR 0003 compares the DACL as an ordered ACE list. Reordering two
        // distinct ACEs in the same category (both explicit allow) is a real
        // difference, not a benign formatting one.
        let a = "O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;BU)";
        let b = "O:BAG:BAD:(A;;KR;;;BU)(A;;KA;;;SY)";
        assert!(!compare(a, b).is_empty());
    }

    #[test]
    fn flag_token_order_does_not_matter() {
        let a = "O:BAG:BAD:(A;CIOI;KA;;;SY)";
        let b = "O:BAG:BAD:(A;OICI;KA;;;SY)";
        assert!(compare(a, b).is_empty(), "{:?}", compare(a, b));
    }

    #[test]
    fn differing_owner_is_caught() {
        let a = "O:BAG:BAD:(A;;KA;;;SY)";
        let b = "O:SYG:BAD:(A;;KA;;;SY)";
        let d = compare(a, b);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("owner"));
    }

    #[test]
    fn differing_dacl_ace_is_caught() {
        let a = "O:BAG:BAD:(A;;KA;;;SY)";
        let b = "O:BAG:BAD:(A;;KR;;;SY)";
        let d = compare(a, b);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("DACL"));
    }

    #[test]
    fn one_sided_sacl_is_not_a_difference() {
        let with_sacl = "O:BAG:BAD:(A;;KA;;;SY)S:(AU;;KA;;;WD)";
        let without = "O:BAG:BAD:(A;;KA;;;SY)";
        assert!(compare(with_sacl, without).is_empty(), "{:?}", compare(with_sacl, without));
        assert!(one_sided_sacl(with_sacl, without));
        assert!(!one_sided_sacl(with_sacl, with_sacl));
    }

    #[test]
    fn two_sided_sacl_difference_is_caught() {
        let a = "O:BAG:BAD:(A;;KA;;;SY)S:(AU;;KA;;;WD)";
        let b = "O:BAG:BAD:(A;;KA;;;SY)S:(AU;;KR;;;WD)";
        let d = compare(a, b);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("SACL"));
    }

    #[test]
    fn deny_ace_sorts_before_allow() {
        // Same ACEs, emitted in different category order; canonical ordering
        // (deny before allow) makes them equal.
        let a = "O:BAG:BAD:(D;;KA;;;BG)(A;;KA;;;SY)";
        let b = "O:BAG:BAD:(A;;KA;;;SY)(D;;KA;;;BG)";
        assert!(compare(a, b).is_empty(), "{:?}", compare(a, b));
    }

    #[test]
    fn sid_owner_not_split_as_component() {
        // A full SID owner contains no false O/G/D/S markers at depth 0.
        let s = "O:S-1-5-32-544G:S-1-5-18D:(A;;KA;;;SY)";
        let d = Descriptor::parse(s);
        assert_eq!(d.owner.as_deref(), Some("S-1-5-32-544"));
        assert_eq!(d.group.as_deref(), Some("S-1-5-18"));
        assert!(d.dacl.is_some());
    }
}
