//! Security cells ("sk") and a minimal default security descriptor.
//!
//! An sk cell holds a self-relative SECURITY_DESCRIPTOR shared by one or
//! more keys. sk cells form a doubly linked list (CONTRACTS invariant 13)
//! and carry a reference count (invariant 14).
//!
//! Layout of the sk record (offsets relative to the start of the record,
//! after the cell size field):
//!
//! ```text
//!   0x00  2   signature "sk"
//!   0x02  2   reserved
//!   0x04  4   flink: offset of the next sk cell
//!   0x08  4   blink: offset of the previous sk cell
//!   0x0C  4   reference count
//!   0x10  4   security descriptor size
//!   0x14  ..  self-relative security descriptor
//! ```

use super::{read_u32, FormatError};

/// The "sk" signature.
pub const SK_SIGNATURE: [u8; 2] = *b"sk";

/// Fixed size of the sk record before the descriptor.
pub const SK_HEADER_SIZE: usize = 0x14;

const OFF_FLINK: usize = 0x04;
const OFF_BLINK: usize = 0x08;
const OFF_REFCOUNT: usize = 0x0c;
const OFF_DESC_SIZE: usize = 0x10;

/// A parsed security cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityCell {
    /// Offset of the next sk cell in the ring.
    pub flink: u32,
    /// Offset of the previous sk cell in the ring.
    pub blink: u32,
    /// Number of keys referencing this descriptor.
    pub refcount: u32,
    /// Raw self-relative security descriptor bytes.
    pub descriptor: Vec<u8>,
}

impl SecurityCell {
    /// Parse an sk record from a cell payload.
    pub fn parse(payload: &[u8]) -> Result<SecurityCell, FormatError> {
        if payload.len() < SK_HEADER_SIZE {
            return Err(FormatError::OutOfBounds {
                structure: "sk header",
                offset: 0,
                need: SK_HEADER_SIZE,
                available: payload.len(),
            });
        }
        let signature: [u8; 2] = payload[0..2].try_into().expect("slice is 2 bytes");
        if signature != SK_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "sk",
                found: [signature[0], signature[1], 0, 0],
            });
        }

        let desc_size = read_u32(payload, OFF_DESC_SIZE) as usize;
        let desc_end = SK_HEADER_SIZE + desc_size;
        if desc_end > payload.len() {
            return Err(FormatError::OutOfBounds {
                structure: "sk descriptor",
                offset: SK_HEADER_SIZE,
                need: desc_size,
                available: payload.len() - SK_HEADER_SIZE,
            });
        }

        Ok(SecurityCell {
            flink: read_u32(payload, OFF_FLINK),
            blink: read_u32(payload, OFF_BLINK),
            refcount: read_u32(payload, OFF_REFCOUNT),
            descriptor: payload[SK_HEADER_SIZE..desc_end].to_vec(),
        })
    }

    /// Serialize the sk record (without the cell size field).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = vec![0u8; SK_HEADER_SIZE + self.descriptor.len()];
        buf[0..2].copy_from_slice(&SK_SIGNATURE);
        buf[OFF_FLINK..OFF_FLINK + 4].copy_from_slice(&self.flink.to_le_bytes());
        buf[OFF_BLINK..OFF_BLINK + 4].copy_from_slice(&self.blink.to_le_bytes());
        buf[OFF_REFCOUNT..OFF_REFCOUNT + 4].copy_from_slice(&self.refcount.to_le_bytes());
        buf[OFF_DESC_SIZE..OFF_DESC_SIZE + 4]
            .copy_from_slice(&(self.descriptor.len() as u32).to_le_bytes());
        buf[SK_HEADER_SIZE..].copy_from_slice(&self.descriptor);
        buf
    }

    /// A lone sk cell at `self_offset`: flink and blink point to itself
    /// (a one-element ring) with the given descriptor and refcount.
    pub fn lone(self_offset: u32, refcount: u32, descriptor: Vec<u8>) -> SecurityCell {
        SecurityCell {
            flink: self_offset,
            blink: self_offset,
            refcount,
            descriptor,
        }
    }
}

/// Build a minimal valid self-relative security descriptor for the
/// empty-hive root key.
///
/// Owner and group are set to the Local System SID (S-1-5-18); no SACL is
/// present and the DACL is NULL (no SE_DACL_PRESENT control bit), which
/// grants unrestricted access. This is a placeholder default. The exact
/// descriptor offreg writes for the ROOT of a freshly created hive has NOT
/// been confirmed; see libreg/STATE.md (spec question) before relying on
/// byte equality. The empty-hive builder accepts any descriptor, so the
/// agent or harness can substitute the offreg-correct one.
///
/// This is distinct from the default a freshly created (non-root) KEY
/// carries, which CONTRACTS 0.1.6 ratified: see
/// [`super::security_descriptor::default_key_security_descriptor`]. That
/// descriptor is not used here, because whether offreg gives the hive root
/// the same descriptor as an ordinary created key is unconfirmed.
pub fn default_security_descriptor() -> Vec<u8> {
    // SECURITY_DESCRIPTOR_RELATIVE header is 20 bytes; two 12-byte SIDs
    // follow it (owner at 0x14, group at 0x20).
    const HEADER: usize = 20;
    let owner_off = HEADER as u32; // 0x14
    let group_off = (HEADER + SID_LOCAL_SYSTEM.len()) as u32; // 0x20

    let mut sd = Vec::with_capacity(HEADER + 2 * SID_LOCAL_SYSTEM.len());
    sd.push(1); // Revision
    sd.push(0); // Sbz1
    sd.extend_from_slice(&SE_SELF_RELATIVE.to_le_bytes()); // Control
    sd.extend_from_slice(&owner_off.to_le_bytes()); // Owner offset
    sd.extend_from_slice(&group_off.to_le_bytes()); // Group offset
    sd.extend_from_slice(&0u32.to_le_bytes()); // Sacl offset (none)
    sd.extend_from_slice(&0u32.to_le_bytes()); // Dacl offset (NULL DACL)
    sd.extend_from_slice(&SID_LOCAL_SYSTEM); // Owner
    sd.extend_from_slice(&SID_LOCAL_SYSTEM); // Group
    debug_assert_eq!(sd.len(), HEADER + 2 * SID_LOCAL_SYSTEM.len());
    sd
}

/// SE_SELF_RELATIVE control flag.
const SE_SELF_RELATIVE: u16 = 0x8000;

/// The Local System SID, S-1-5-18, in binary form:
/// Revision 1, 1 sub-authority, identifier authority 5, sub-authority 18.
const SID_LOCAL_SYSTEM: [u8; 12] = [
    0x01, // Revision
    0x01, // SubAuthorityCount
    0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (big-endian: 5)
    0x12, 0x00, 0x00, 0x00, // SubAuthority[0] = 18 (little-endian)
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::cell::{encode_cell, Cell};

    #[test]
    fn lone_round_trips() {
        let sk = SecurityCell::lone(0x78, 1, default_security_descriptor());
        let payload = sk.to_payload();
        let parsed = SecurityCell::parse(&payload).expect("parse");
        assert_eq!(parsed, sk);
        assert_eq!(parsed.flink, 0x78);
        assert_eq!(parsed.blink, 0x78);
        assert_eq!(parsed.refcount, 1);
    }

    #[test]
    fn round_trips_through_a_cell() {
        let sk = SecurityCell::lone(0x78, 10, default_security_descriptor());
        let cell_bytes = encode_cell(&sk.to_payload(), true);
        let cell = Cell::parse_at(&cell_bytes, 0).expect("frame cell");
        let parsed = SecurityCell::parse(cell.data).expect("parse padded");
        assert_eq!(parsed, sk);
    }

    #[test]
    fn default_descriptor_is_self_relative() {
        let sd = default_security_descriptor();
        assert_eq!(sd[0], 1, "revision");
        let control = u16::from_le_bytes([sd[2], sd[3]]);
        assert_eq!(control & SE_SELF_RELATIVE, SE_SELF_RELATIVE);
        let owner_off = u32::from_le_bytes([sd[4], sd[5], sd[6], sd[7]]) as usize;
        // Owner SID begins with revision 1.
        assert_eq!(sd[owner_off], 1);
    }

    #[test]
    fn rejects_bad_signature() {
        let sk = SecurityCell::lone(0x78, 1, vec![0u8; 4]);
        let mut payload = sk.to_payload();
        payload[0..2].copy_from_slice(b"nk");
        assert!(matches!(
            SecurityCell::parse(&payload),
            Err(FormatError::BadSignature { structure: "sk", .. })
        ));
    }

    #[test]
    fn rejects_descriptor_past_end() {
        let sk = SecurityCell::lone(0x78, 1, vec![0u8; 4]);
        let mut payload = sk.to_payload();
        payload[OFF_DESC_SIZE..OFF_DESC_SIZE + 4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(matches!(
            SecurityCell::parse(&payload),
            Err(FormatError::OutOfBounds { structure: "sk descriptor", .. })
        ));
    }
}
