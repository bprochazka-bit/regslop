//! Hash-leaf subkey lists ("lh").
//!
//! The "lh" subkey list is the form offreg and modern Windows write for
//! version 1.5 hives. Like "lf" (see [`super::lf`]) it records, for one
//! parent key, the offsets of its immediate subkeys, but each element
//! carries a 4-byte name *hash* rather than the first four name bytes,
//! which lets a lookup reject non-matching subkeys with a single integer
//! compare.
//!
//! Layout of the lh record (offsets relative to the start of the record,
//! i.e. just after the cell's 4-byte size field):
//!
//! ```text
//!   0x00  2   signature "lh"
//!   0x02  2   number of elements
//!   0x04  ..  elements, 8 bytes each:
//!               0x00  4   subkey nk offset (from the hive bins data)
//!               0x04  4   name hash (see name_hash)
//! ```
//!
//! This is a pure Layer 0 structure. As with lf, the sorted-by-name
//! invariant is maintained by the logical layer; this module round-trips
//! the elements in whatever order it is given.

use super::{read_u16, read_u32, FormatError};

/// The "lh" signature.
pub const LH_SIGNATURE: [u8; 2] = *b"lh";

/// Fixed size of the lh record header before the elements.
pub const LH_HEADER_SIZE: usize = 0x04;

/// Size of one lh element on disk.
pub const LH_ELEMENT_SIZE: usize = 8;

const OFF_COUNT: usize = 0x02;

/// One hash-leaf element: a subkey offset and its name hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashLeafEntry {
    /// Offset of the subkey's nk cell, relative to the hive bins data.
    pub key_offset: u32,
    /// Hash of the subkey name (see [`name_hash`]).
    pub name_hash: u32,
}

impl HashLeafEntry {
    /// Build an element for the subkey at `key_offset` whose name is
    /// `name`, computing the hash with [`name_hash`].
    pub fn new(key_offset: u32, name: &str) -> HashLeafEntry {
        HashLeafEntry {
            key_offset,
            name_hash: name_hash(name),
        }
    }
}

/// A parsed hash-leaf subkey list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HashLeaf {
    /// Elements in on-disk order (one per immediate subkey).
    pub entries: Vec<HashLeafEntry>,
}

impl HashLeaf {
    /// Parse an lh record from a cell payload (the bytes after the cell
    /// size field).
    pub fn parse(payload: &[u8]) -> Result<HashLeaf, FormatError> {
        if payload.len() < LH_HEADER_SIZE {
            return Err(FormatError::OutOfBounds {
                structure: "lh header",
                offset: 0,
                need: LH_HEADER_SIZE,
                available: payload.len(),
            });
        }
        let signature: [u8; 2] = payload[0..2].try_into().expect("slice is 2 bytes");
        if signature != LH_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "lh",
                found: [signature[0], signature[1], 0, 0],
            });
        }

        let count = read_u16(payload, OFF_COUNT) as usize;
        let need = LH_HEADER_SIZE + count * LH_ELEMENT_SIZE;
        if need > payload.len() {
            return Err(FormatError::OutOfBounds {
                structure: "lh elements",
                offset: LH_HEADER_SIZE,
                need: count * LH_ELEMENT_SIZE,
                available: payload.len() - LH_HEADER_SIZE,
            });
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let base = LH_HEADER_SIZE + i * LH_ELEMENT_SIZE;
            entries.push(HashLeafEntry {
                key_offset: read_u32(payload, base),
                name_hash: read_u32(payload, base + 4),
            });
        }
        Ok(HashLeaf { entries })
    }

    /// Serialize the lh record (without the cell size field). The returned
    /// bytes are `LH_HEADER_SIZE + entries.len() * LH_ELEMENT_SIZE` long;
    /// the caller wraps them in a cell, which adds the size field and the
    /// 8-byte padding.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = vec![0u8; LH_HEADER_SIZE + self.entries.len() * LH_ELEMENT_SIZE];
        buf[0..2].copy_from_slice(&LH_SIGNATURE);
        buf[OFF_COUNT..OFF_COUNT + 2].copy_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for (i, e) in self.entries.iter().enumerate() {
            let base = LH_HEADER_SIZE + i * LH_ELEMENT_SIZE;
            buf[base..base + 4].copy_from_slice(&e.key_offset.to_le_bytes());
            buf[base + 4..base + 8].copy_from_slice(&e.name_hash.to_le_bytes());
        }
        buf
    }

    /// Number of subkeys recorded in this list.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the list holds no subkeys.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute the lh name hash for a subkey name.
///
/// The algorithm matches the Windows registry: iterate the name's UTF-16
/// code units, uppercase each, and fold with `hash = hash * 37 + unit`
/// in wrapping 32-bit arithmetic. Operating on code units (not raw bytes)
/// keeps the result independent of host endianness (Hard Rule 6).
///
/// CAVEAT: only ASCII case folding (a-z -> A-Z) is applied here. The
/// kernel uses `RtlUpcaseUnicodeChar`, whose table for non-ASCII letters
/// has NOT been verified against offreg. Subkey names outside ASCII may
/// therefore hash differently; this is a spec question (see
/// libreg/STATE.md) to resolve before relying on byte equality for such
/// names. ASCII subkey names, which cover the create paths exercised so
/// far, are correct.
pub fn name_hash(name: &str) -> u32 {
    let mut hash: u32 = 0;
    for unit in name.encode_utf16() {
        // ASCII lowercase letters fold to uppercase; everything else,
        // including already-uppercase and non-ASCII, passes through.
        let upper = if (b'a' as u16..=b'z' as u16).contains(&unit) {
            unit - 0x20
        } else {
            unit
        };
        hash = hash.wrapping_mul(37).wrapping_add(upper as u32);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::cell::{encode_cell, Cell};

    fn sample() -> HashLeaf {
        HashLeaf {
            entries: vec![
                HashLeafEntry::new(0x20, "Alpha"),
                HashLeafEntry::new(0x140, "Beta"),
            ],
        }
    }

    #[test]
    fn round_trips() {
        let lh = sample();
        let payload = lh.to_payload();
        let parsed = HashLeaf::parse(&payload).expect("parse");
        assert_eq!(parsed, lh);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn empty_list_round_trips() {
        let lh = HashLeaf::default();
        assert!(lh.is_empty());
        let parsed = HashLeaf::parse(&lh.to_payload()).expect("parse");
        assert_eq!(parsed, lh);
        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn round_trips_through_a_cell() {
        let lh = sample();
        let cell_bytes = encode_cell(&lh.to_payload(), true);
        let cell = Cell::parse_at(&cell_bytes, 0).expect("frame cell");
        assert!(cell.allocated);
        let parsed = HashLeaf::parse(cell.data).expect("parse from padded payload");
        assert_eq!(parsed, lh);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut payload = sample().to_payload();
        payload[0..2].copy_from_slice(b"lf");
        assert!(matches!(
            HashLeaf::parse(&payload),
            Err(FormatError::BadSignature { structure: "lh", .. })
        ));
    }

    #[test]
    fn rejects_count_past_end() {
        let mut payload = sample().to_payload();
        payload[OFF_COUNT..OFF_COUNT + 2].copy_from_slice(&99u16.to_le_bytes());
        assert!(matches!(
            HashLeaf::parse(&payload),
            Err(FormatError::OutOfBounds { structure: "lh elements", .. })
        ));
    }

    #[test]
    fn hash_is_case_insensitive_for_ascii() {
        // Upcasing means the hash ignores ASCII case.
        assert_eq!(name_hash("Software"), name_hash("SOFTWARE"));
        assert_eq!(name_hash("Software"), name_hash("software"));
        assert_eq!(name_hash(""), 0);
    }

    #[test]
    fn hash_matches_known_values() {
        // Reference values for the hash = 37*hash + upcase(ch) algorithm,
        // computed by hand so a refactor that changes the fold is caught.
        // "A" -> 'A' = 0x41 = 65.
        assert_eq!(name_hash("A"), 65);
        // "AB" -> 37*65 + 'B'(66) = 2405 + 66 = 2471.
        assert_eq!(name_hash("AB"), 2471);
        // "ab" upcases to "AB", so it must match.
        assert_eq!(name_hash("ab"), 2471);
    }

    #[test]
    fn hash_distinguishes_different_names() {
        assert_ne!(name_hash("Alpha"), name_hash("Beta"));
    }
}
