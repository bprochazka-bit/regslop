//! Self-relative SECURITY_DESCRIPTOR encoding and decoding.
//!
//! An sk cell (see [`super::sk`]) stores a self-relative
//! SECURITY_DESCRIPTOR: a fixed 20-byte header followed by the owner SID,
//! group SID, and the DACL/SACL, each located by an offset in the header.
//! This module models those structures as typed values and round-trips them
//! to and from bytes, the same contract every other Layer 0 module honors.
//!
//! It also builds the canonical default descriptor a freshly created key
//! carries, ratified in CONTRACTS 0.1.6 (the Security section, issue #11):
//!
//! ```text
//!   O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)
//! ```
//!
//! owner and group Administrators; SYSTEM and Administrators full control,
//! Everyone and Restricted Code read, all container-inheritable. The
//! contract decides equality on the SDDL-normalized descriptor (ADR 0003),
//! so byte-for-byte equality with offreg is not promised here: only that
//! this binary form converts to that SDDL. The agents own SDDL conversion;
//! libreg owns the binary form that lives in the hive.
//!
//! Layout produced by [`SecurityDescriptor::to_bytes`]:
//!
//! ```text
//!   0x00  20  header (revision, control, four offsets)
//!   0x14  ..  owner SID
//!   ....  ..  group SID
//!   ....  ..  DACL (when present)
//!   ....  ..  SACL (when present)
//! ```

use super::{read_u16, read_u32, FormatError};

/// Self-relative descriptor: offsets are relative to the descriptor start.
pub const SE_SELF_RELATIVE: u16 = 0x8000;
/// A DACL is present (the `dacl_offset` field is meaningful).
pub const SE_DACL_PRESENT: u16 = 0x0004;
/// A SACL is present (the `sacl_offset` field is meaningful).
pub const SE_SACL_PRESENT: u16 = 0x0010;

/// Revision stored in the descriptor header and in every SID.
pub const SD_REVISION: u8 = 1;
/// Revision stored in an ACL header (ACL_REVISION).
pub const ACL_REVISION: u8 = 2;

/// `ACCESS_ALLOWED_ACE_TYPE`.
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
/// `CONTAINER_INHERIT_ACE`: subkeys inherit this ACE.
pub const CONTAINER_INHERIT_ACE: u8 = 0x02;

/// `KEY_ALL_ACCESS` (SDDL `KA`): full control over a key.
pub const KEY_ALL_ACCESS: u32 = 0x000f_003f;
/// `KEY_READ` (SDDL `KR`): query, enumerate, and notify.
pub const KEY_READ: u32 = 0x0002_0019;

const SD_HEADER_SIZE: usize = 20;
const ACL_HEADER_SIZE: usize = 8;
const ACE_HEADER_SIZE: usize = 8; // type(1) + flags(1) + size(2) + mask(4)

const OFF_CONTROL: usize = 0x02;
const OFF_OWNER: usize = 0x04;
const OFF_GROUP: usize = 0x08;
const OFF_SACL: usize = 0x0c;
const OFF_DACL: usize = 0x10;

/// A security identifier (SID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    /// SID revision, always 1.
    pub revision: u8,
    /// The 6-byte identifier authority, stored big-endian on disk.
    pub identifier_authority: [u8; 6],
    /// Sub-authorities (relative identifiers), each little-endian on disk.
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Build a SID from an authority value and its sub-authorities.
    pub fn new(authority: u8, sub_authorities: &[u32]) -> Sid {
        Sid {
            revision: SD_REVISION,
            identifier_authority: [0, 0, 0, 0, 0, authority],
            sub_authorities: sub_authorities.to_vec(),
        }
    }

    /// Local System, S-1-5-18 (SDDL `SY`).
    pub fn local_system() -> Sid {
        Sid::new(5, &[18])
    }

    /// Built-in Administrators, S-1-5-32-544 (SDDL `BA`).
    pub fn administrators() -> Sid {
        Sid::new(5, &[32, 544])
    }

    /// Everyone / World, S-1-1-0 (SDDL `WD`).
    pub fn everyone() -> Sid {
        Sid::new(1, &[0])
    }

    /// Restricted Code, S-1-5-12 (SDDL `RC`).
    pub fn restricted_code() -> Sid {
        Sid::new(5, &[12])
    }

    /// On-disk length in bytes: 8-byte header plus 4 bytes per sub-authority.
    pub fn byte_len(&self) -> usize {
        8 + 4 * self.sub_authorities.len()
    }

    /// Append the on-disk SID bytes to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.push(self.revision);
        out.push(self.sub_authorities.len() as u8);
        out.extend_from_slice(&self.identifier_authority);
        for sub in &self.sub_authorities {
            out.extend_from_slice(&sub.to_le_bytes());
        }
    }

    /// Parse a SID at `off` within `buf`.
    pub fn parse_at(buf: &[u8], off: usize) -> Result<Sid, FormatError> {
        if off + 8 > buf.len() {
            return Err(FormatError::OutOfBounds {
                structure: "SID header",
                offset: off,
                need: 8,
                available: buf.len().saturating_sub(off),
            });
        }
        let revision = buf[off];
        let count = buf[off + 1] as usize;
        let identifier_authority: [u8; 6] =
            buf[off + 2..off + 8].try_into().expect("slice is 6 bytes");
        let need = 8 + 4 * count;
        if off + need > buf.len() {
            return Err(FormatError::OutOfBounds {
                structure: "SID sub-authorities",
                offset: off,
                need,
                available: buf.len().saturating_sub(off),
            });
        }
        let mut sub_authorities = Vec::with_capacity(count);
        for i in 0..count {
            sub_authorities.push(read_u32(buf, off + 8 + 4 * i));
        }
        Ok(Sid {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }
}

/// A single access-allowed/denied ACE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// ACE type, e.g. [`ACCESS_ALLOWED_ACE_TYPE`].
    pub ace_type: u8,
    /// Inheritance and audit flags, e.g. [`CONTAINER_INHERIT_ACE`].
    pub flags: u8,
    /// Access mask, e.g. [`KEY_ALL_ACCESS`].
    pub mask: u32,
    /// The trustee this ACE applies to.
    pub sid: Sid,
}

impl Ace {
    /// An access-allowed ACE for `sid` granting `mask` with `flags`.
    pub fn allow(sid: Sid, mask: u32, flags: u8) -> Ace {
        Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags,
            mask,
            sid,
        }
    }

    /// On-disk length in bytes (header plus the embedded SID).
    pub fn byte_len(&self) -> usize {
        ACE_HEADER_SIZE + self.sid.byte_len()
    }

    /// Append the on-disk ACE bytes to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.push(self.ace_type);
        out.push(self.flags);
        out.extend_from_slice(&(self.byte_len() as u16).to_le_bytes());
        out.extend_from_slice(&self.mask.to_le_bytes());
        self.sid.write_to(out);
    }

    /// Parse an ACE at `off` within `buf`. Returns the ACE and its size.
    pub fn parse_at(buf: &[u8], off: usize) -> Result<(Ace, usize), FormatError> {
        if off + ACE_HEADER_SIZE > buf.len() {
            return Err(FormatError::OutOfBounds {
                structure: "ACE header",
                offset: off,
                need: ACE_HEADER_SIZE,
                available: buf.len().saturating_sub(off),
            });
        }
        let ace_type = buf[off];
        let flags = buf[off + 1];
        let size = read_u16(buf, off + 2) as usize;
        if size < ACE_HEADER_SIZE || off + size > buf.len() {
            return Err(FormatError::OutOfBounds {
                structure: "ACE body",
                offset: off,
                need: size,
                available: buf.len().saturating_sub(off),
            });
        }
        let mask = read_u32(buf, off + 4);
        let sid = Sid::parse_at(buf, off + ACE_HEADER_SIZE)?;
        Ok((
            Ace {
                ace_type,
                flags,
                mask,
                sid,
            },
            size,
        ))
    }
}

/// An access control list (DACL or SACL): a header plus a list of ACEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    /// ACL revision, normally [`ACL_REVISION`].
    pub revision: u8,
    /// The ACEs, in on-disk order.
    pub aces: Vec<Ace>,
}

impl Acl {
    /// An ACL at the standard revision holding `aces`.
    pub fn new(aces: Vec<Ace>) -> Acl {
        Acl {
            revision: ACL_REVISION,
            aces,
        }
    }

    /// On-disk length in bytes (header plus every ACE).
    pub fn byte_len(&self) -> usize {
        ACL_HEADER_SIZE + self.aces.iter().map(Ace::byte_len).sum::<usize>()
    }

    /// Append the on-disk ACL bytes to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.push(self.revision);
        out.push(0); // Sbz1
        out.extend_from_slice(&(self.byte_len() as u16).to_le_bytes());
        out.extend_from_slice(&(self.aces.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
        for ace in &self.aces {
            ace.write_to(out);
        }
    }

    /// Parse an ACL at `off` within `buf`.
    pub fn parse_at(buf: &[u8], off: usize) -> Result<Acl, FormatError> {
        if off + ACL_HEADER_SIZE > buf.len() {
            return Err(FormatError::OutOfBounds {
                structure: "ACL header",
                offset: off,
                need: ACL_HEADER_SIZE,
                available: buf.len().saturating_sub(off),
            });
        }
        let revision = buf[off];
        let size = read_u16(buf, off + 2) as usize;
        let ace_count = read_u16(buf, off + 4) as usize;
        if off + size > buf.len() {
            return Err(FormatError::OutOfBounds {
                structure: "ACL body",
                offset: off,
                need: size,
                available: buf.len().saturating_sub(off),
            });
        }
        let mut aces = Vec::with_capacity(ace_count);
        let mut cursor = off + ACL_HEADER_SIZE;
        for _ in 0..ace_count {
            let (ace, ace_size) = Ace::parse_at(buf, cursor)?;
            cursor += ace_size;
            aces.push(ace);
        }
        Ok(Acl { revision, aces })
    }
}

/// A self-relative security descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor {
    /// Control flags. [`SE_SELF_RELATIVE`] is set by [`Self::to_bytes`].
    pub control: u16,
    /// Owner SID, if present.
    pub owner: Option<Sid>,
    /// Group SID, if present.
    pub group: Option<Sid>,
    /// Discretionary ACL, if [`SE_DACL_PRESENT`] is set.
    pub dacl: Option<Acl>,
    /// System ACL, if [`SE_SACL_PRESENT`] is set.
    pub sacl: Option<Acl>,
}

impl SecurityDescriptor {
    /// Serialize to a self-relative descriptor.
    ///
    /// Body order is SACL, DACL, owner, group, which is what offreg (and
    /// `RtlAbsoluteToSelfRelativeSD`) emit: confirmed against the root sk in
    /// the offreg reference hives (tests/corpus/synthetic), where the DACL
    /// sits right after the 20-byte header and owner/group follow it. A
    /// reader uses the header offsets, so the order does not change the SDDL
    /// the agents derive (ADR 0003); matching it gives byte parity too.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut control = self.control | SE_SELF_RELATIVE;
        if self.dacl.is_some() {
            control |= SE_DACL_PRESENT;
        }
        if self.sacl.is_some() {
            control |= SE_SACL_PRESENT;
        }

        // Bodies follow the fixed header in the order SACL, DACL, owner,
        // group; compute each offset as it is placed.
        let mut cursor = SD_HEADER_SIZE;
        let sacl_off = self.sacl.as_ref().map(|a| {
            let o = cursor;
            cursor += a.byte_len();
            o as u32
        });
        let dacl_off = self.dacl.as_ref().map(|a| {
            let o = cursor;
            cursor += a.byte_len();
            o as u32
        });
        let owner_off = self.owner.as_ref().map(|s| {
            let o = cursor;
            cursor += s.byte_len();
            o as u32
        });
        let group_off = self.group.as_ref().map(|s| {
            let o = cursor;
            cursor += s.byte_len();
            o as u32
        });

        let mut out = Vec::with_capacity(cursor);
        out.push(SD_REVISION);
        out.push(0); // Sbz1
        out.extend_from_slice(&control.to_le_bytes());
        out.extend_from_slice(&owner_off.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&group_off.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&sacl_off.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&dacl_off.unwrap_or(0).to_le_bytes());
        if let Some(a) = &self.sacl {
            a.write_to(&mut out);
        }
        if let Some(a) = &self.dacl {
            a.write_to(&mut out);
        }
        if let Some(s) = &self.owner {
            s.write_to(&mut out);
        }
        if let Some(s) = &self.group {
            s.write_to(&mut out);
        }
        debug_assert_eq!(out.len(), cursor);
        out
    }

    /// Parse a self-relative descriptor.
    pub fn parse(buf: &[u8]) -> Result<SecurityDescriptor, FormatError> {
        if buf.len() < SD_HEADER_SIZE {
            return Err(FormatError::Truncated {
                expected: SD_HEADER_SIZE,
                found: buf.len(),
            });
        }
        let control = read_u16(buf, OFF_CONTROL);
        let owner_off = read_u32(buf, OFF_OWNER) as usize;
        let group_off = read_u32(buf, OFF_GROUP) as usize;
        let sacl_off = read_u32(buf, OFF_SACL) as usize;
        let dacl_off = read_u32(buf, OFF_DACL) as usize;

        let owner = if owner_off != 0 {
            Some(Sid::parse_at(buf, owner_off)?)
        } else {
            None
        };
        let group = if group_off != 0 {
            Some(Sid::parse_at(buf, group_off)?)
        } else {
            None
        };
        let dacl = if control & SE_DACL_PRESENT != 0 && dacl_off != 0 {
            Some(Acl::parse_at(buf, dacl_off)?)
        } else {
            None
        };
        let sacl = if control & SE_SACL_PRESENT != 0 && sacl_off != 0 {
            Some(Acl::parse_at(buf, sacl_off)?)
        } else {
            None
        };
        Ok(SecurityDescriptor {
            control,
            owner,
            group,
            dacl,
            sacl,
        })
    }
}

/// The default security descriptor a freshly created key carries, ratified
/// in CONTRACTS 0.1.6 (issue #11):
///
/// ```text
///   O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)
/// ```
///
/// Owner and group are Administrators. The DACL grants SYSTEM and
/// Administrators [`KEY_ALL_ACCESS`] and Everyone and Restricted Code
/// [`KEY_READ`], every ACE [`CONTAINER_INHERIT_ACE`]. No SACL.
///
/// This is the default for the create path (Layer 1+). It is NOT yet wired
/// to the empty-hive root key: the root's descriptor is a separate offreg
/// question that the corpus or harness has not confirmed (libreg/STATE.md).
pub fn default_key_security_descriptor() -> SecurityDescriptor {
    let dacl = Acl::new(vec![
        Ace::allow(Sid::local_system(), KEY_ALL_ACCESS, CONTAINER_INHERIT_ACE),
        Ace::allow(Sid::administrators(), KEY_ALL_ACCESS, CONTAINER_INHERIT_ACE),
        Ace::allow(Sid::everyone(), KEY_READ, CONTAINER_INHERIT_ACE),
        Ace::allow(Sid::restricted_code(), KEY_READ, CONTAINER_INHERIT_ACE),
    ]);
    SecurityDescriptor {
        control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
        owner: Some(Sid::administrators()),
        group: Some(Sid::administrators()),
        dacl: Some(dacl),
        sacl: None,
    }
}

/// The ratified default descriptor as on-disk bytes.
pub fn default_key_security_descriptor_bytes() -> Vec<u8> {
    default_key_security_descriptor().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_well_known_bytes() {
        let mut out = Vec::new();
        Sid::local_system().write_to(&mut out);
        assert_eq!(
            out,
            [0x01, 0x01, 0, 0, 0, 0, 0, 0x05, 0x12, 0, 0, 0],
            "S-1-5-18"
        );

        let mut out = Vec::new();
        Sid::administrators().write_to(&mut out);
        assert_eq!(
            out,
            [0x01, 0x02, 0, 0, 0, 0, 0, 0x05, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0],
            "S-1-5-32-544"
        );

        let mut out = Vec::new();
        Sid::everyone().write_to(&mut out);
        assert_eq!(
            out,
            [0x01, 0x01, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0],
            "S-1-1-0"
        );

        let mut out = Vec::new();
        Sid::restricted_code().write_to(&mut out);
        assert_eq!(
            out,
            [0x01, 0x01, 0, 0, 0, 0, 0, 0x05, 0x0c, 0, 0, 0],
            "S-1-5-12"
        );
    }

    #[test]
    fn sid_round_trips() {
        for sid in [
            Sid::local_system(),
            Sid::administrators(),
            Sid::everyone(),
            Sid::restricted_code(),
        ] {
            let mut bytes = Vec::new();
            sid.write_to(&mut bytes);
            assert_eq!(bytes.len(), sid.byte_len());
            let parsed = Sid::parse_at(&bytes, 0).expect("parse SID");
            assert_eq!(parsed, sid);
        }
    }

    #[test]
    fn ace_round_trips_and_sizes() {
        let ace = Ace::allow(Sid::local_system(), KEY_ALL_ACCESS, CONTAINER_INHERIT_ACE);
        let mut bytes = Vec::new();
        ace.write_to(&mut bytes);
        // header(8) + SID(12) = 20.
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(bytes[1], CONTAINER_INHERIT_ACE);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 20);
        assert_eq!(
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            KEY_ALL_ACCESS
        );
        let (parsed, size) = Ace::parse_at(&bytes, 0).expect("parse ACE");
        assert_eq!(size, 20);
        assert_eq!(parsed, ace);
    }

    #[test]
    fn acl_round_trips() {
        let acl = Acl::new(vec![
            Ace::allow(Sid::local_system(), KEY_ALL_ACCESS, CONTAINER_INHERIT_ACE),
            Ace::allow(Sid::everyone(), KEY_READ, CONTAINER_INHERIT_ACE),
        ]);
        let mut bytes = Vec::new();
        acl.write_to(&mut bytes);
        assert_eq!(bytes.len(), acl.byte_len());
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 2, "ACE count");
        let parsed = Acl::parse_at(&bytes, 0).expect("parse ACL");
        assert_eq!(parsed, acl);
    }

    #[test]
    fn default_descriptor_round_trips() {
        let sd = default_key_security_descriptor();
        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::parse(&bytes).expect("parse SD");
        assert_eq!(parsed, sd);
    }

    #[test]
    fn default_descriptor_structure() {
        let sd = default_key_security_descriptor();
        let bytes = sd.to_bytes();

        // Header: revision 1, self-relative + DACL present, no SACL.
        assert_eq!(bytes[0], SD_REVISION);
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert_eq!(control, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        assert_eq!(read_u32(&bytes, OFF_SACL), 0, "no SACL offset");
        assert_ne!(read_u32(&bytes, OFF_DACL), 0, "DACL present");

        // Owner and group are both Administrators.
        let owner = Sid::parse_at(&bytes, read_u32(&bytes, OFF_OWNER) as usize).unwrap();
        let group = Sid::parse_at(&bytes, read_u32(&bytes, OFF_GROUP) as usize).unwrap();
        assert_eq!(owner, Sid::administrators());
        assert_eq!(group, Sid::administrators());

        // DACL: four ACEs in the ratified order, all container-inheritable.
        let dacl = sd.dacl.as_ref().unwrap();
        assert_eq!(dacl.aces.len(), 4);
        for ace in &dacl.aces {
            assert_eq!(ace.ace_type, ACCESS_ALLOWED_ACE_TYPE);
            assert_eq!(ace.flags, CONTAINER_INHERIT_ACE);
        }
        assert_eq!(dacl.aces[0].sid, Sid::local_system());
        assert_eq!(dacl.aces[0].mask, KEY_ALL_ACCESS);
        assert_eq!(dacl.aces[1].sid, Sid::administrators());
        assert_eq!(dacl.aces[1].mask, KEY_ALL_ACCESS);
        assert_eq!(dacl.aces[2].sid, Sid::everyone());
        assert_eq!(dacl.aces[2].mask, KEY_READ);
        assert_eq!(dacl.aces[3].sid, Sid::restricted_code());
        assert_eq!(dacl.aces[3].mask, KEY_READ);

        // Total: header(20) + owner(16) + group(16) + DACL(8 + 20+24+20+20).
        assert_eq!(bytes.len(), 20 + 16 + 16 + (8 + 20 + 24 + 20 + 20));
    }

    #[test]
    fn parse_rejects_truncated_header() {
        assert!(matches!(
            SecurityDescriptor::parse(&[0u8; 4]),
            Err(FormatError::Truncated {
                expected: 20,
                found: 4
            })
        ));
    }

    #[test]
    fn parse_rejects_sid_past_end() {
        let mut bytes = default_key_security_descriptor().to_bytes();
        // Point the owner offset just before the end so the SID overruns.
        let bad = (bytes.len() - 2) as u32;
        bytes[OFF_OWNER..OFF_OWNER + 4].copy_from_slice(&bad.to_le_bytes());
        assert!(matches!(
            SecurityDescriptor::parse(&bytes),
            Err(FormatError::OutOfBounds { .. })
        ));
    }
}
