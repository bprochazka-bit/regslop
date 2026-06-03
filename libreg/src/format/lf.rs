//! Fast-leaf subkey lists ("lf").
//!
//! A subkey list cell records, for one parent key, the offsets of its
//! immediate subkeys (CONTRACTS invariant 11). The "lf" variant is a
//! "fast leaf": each element pairs a subkey's nk offset with a 4-byte
//! name hint (the first four bytes of the subkey name as stored on disk),
//! which lets a lookup skip most cells without dereferencing them.
//!
//! Layout of the lf record (offsets relative to the start of the record,
//! i.e. just after the cell's 4-byte size field):
//!
//! ```text
//!   0x00  2   signature "lf"
//!   0x02  2   number of elements
//!   0x04  ..  elements, 8 bytes each:
//!               0x00  4   subkey nk offset (from the hive bins data)
//!               0x04  4   name hint (first 4 name bytes, zero padded)
//! ```
//!
//! This is a pure Layer 0 structure. The on-disk invariant that elements
//! are sorted case-insensitively by subkey name is a tree property the
//! logical layer maintains; this module round-trips whatever order it is
//! given and does not sort or deduplicate.

use super::{read_u16, read_u32, FormatError};

/// The "lf" signature.
pub const LF_SIGNATURE: [u8; 2] = *b"lf";

/// Fixed size of the lf record header before the elements.
pub const LF_HEADER_SIZE: usize = 0x04;

/// Size of one lf element on disk.
pub const LF_ELEMENT_SIZE: usize = 8;

const OFF_COUNT: usize = 0x02;

/// One fast-leaf element: a subkey offset and its 4-byte name hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastLeafEntry {
    /// Offset of the subkey's nk cell, relative to the hive bins data.
    pub key_offset: u32,
    /// First four bytes of the subkey name, zero padded (the on-disk
    /// hint). Held verbatim; this module does not decode it.
    pub name_hint: [u8; 4],
}

/// A parsed fast-leaf subkey list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FastLeaf {
    /// Elements in on-disk order (one per immediate subkey).
    pub entries: Vec<FastLeafEntry>,
}

impl FastLeaf {
    /// Parse an lf record from a cell payload (the bytes after the cell
    /// size field).
    pub fn parse(payload: &[u8]) -> Result<FastLeaf, FormatError> {
        if payload.len() < LF_HEADER_SIZE {
            return Err(FormatError::OutOfBounds {
                structure: "lf header",
                offset: 0,
                need: LF_HEADER_SIZE,
                available: payload.len(),
            });
        }
        let signature: [u8; 2] = payload[0..2].try_into().expect("slice is 2 bytes");
        if signature != LF_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "lf",
                found: [signature[0], signature[1], 0, 0],
            });
        }

        let count = read_u16(payload, OFF_COUNT) as usize;
        let need = LF_HEADER_SIZE + count * LF_ELEMENT_SIZE;
        if need > payload.len() {
            return Err(FormatError::OutOfBounds {
                structure: "lf elements",
                offset: LF_HEADER_SIZE,
                need: count * LF_ELEMENT_SIZE,
                available: payload.len() - LF_HEADER_SIZE,
            });
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let base = LF_HEADER_SIZE + i * LF_ELEMENT_SIZE;
            let name_hint: [u8; 4] = payload[base + 4..base + 8]
                .try_into()
                .expect("slice is 4 bytes");
            entries.push(FastLeafEntry {
                key_offset: read_u32(payload, base),
                name_hint,
            });
        }
        Ok(FastLeaf { entries })
    }

    /// Serialize the lf record (without the cell size field). The returned
    /// bytes are `LF_HEADER_SIZE + entries.len() * LF_ELEMENT_SIZE` long;
    /// the caller wraps them in a cell, which adds the size field and the
    /// 8-byte padding.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = vec![0u8; LF_HEADER_SIZE + self.entries.len() * LF_ELEMENT_SIZE];
        buf[0..2].copy_from_slice(&LF_SIGNATURE);
        buf[OFF_COUNT..OFF_COUNT + 2].copy_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for (i, e) in self.entries.iter().enumerate() {
            let base = LF_HEADER_SIZE + i * LF_ELEMENT_SIZE;
            buf[base..base + 4].copy_from_slice(&e.key_offset.to_le_bytes());
            buf[base + 4..base + 8].copy_from_slice(&e.name_hint);
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

/// Compute the 4-byte fast-leaf name hint for a subkey name: the first
/// four bytes of its on-disk name, zero padded when the name is shorter.
///
/// `name` is the raw on-disk name bytes (ASCII when KEY_COMP_NAME is set,
/// UTF-16LE otherwise), matching [`crate::format::nk::KeyNode::name`].
pub fn name_hint(name: &[u8]) -> [u8; 4] {
    let mut hint = [0u8; 4];
    let n = name.len().min(4);
    hint[..n].copy_from_slice(&name[..n]);
    hint
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::cell::{encode_cell, Cell};

    fn sample() -> FastLeaf {
        FastLeaf {
            entries: vec![
                FastLeafEntry {
                    key_offset: 0x20,
                    name_hint: name_hint(b"Alpha"),
                },
                FastLeafEntry {
                    key_offset: 0x140,
                    name_hint: name_hint(b"Be"),
                },
            ],
        }
    }

    #[test]
    fn round_trips() {
        let lf = sample();
        let payload = lf.to_payload();
        let parsed = FastLeaf::parse(&payload).expect("parse");
        assert_eq!(parsed, lf);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.entries[0].name_hint, *b"Alph");
        // A name shorter than 4 bytes is zero padded.
        assert_eq!(parsed.entries[1].name_hint, [b'B', b'e', 0, 0]);
    }

    #[test]
    fn empty_list_round_trips() {
        let lf = FastLeaf::default();
        assert!(lf.is_empty());
        let parsed = FastLeaf::parse(&lf.to_payload()).expect("parse");
        assert_eq!(parsed, lf);
        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn round_trips_through_a_cell() {
        // Wrapping in a cell pads to an 8-byte boundary; parsing the padded
        // payload must still recover exactly `count` elements.
        let lf = sample();
        let cell_bytes = encode_cell(&lf.to_payload(), true);
        let cell = Cell::parse_at(&cell_bytes, 0).expect("frame cell");
        assert!(cell.allocated);
        let parsed = FastLeaf::parse(cell.data).expect("parse from padded payload");
        assert_eq!(parsed, lf);
    }

    #[test]
    fn rejects_short_header() {
        let buf = [b'l', b'f', 0];
        assert!(matches!(
            FastLeaf::parse(&buf),
            Err(FormatError::OutOfBounds {
                structure: "lf header",
                ..
            })
        ));
    }

    #[test]
    fn rejects_bad_signature() {
        let mut payload = sample().to_payload();
        payload[0..2].copy_from_slice(b"lh");
        assert!(matches!(
            FastLeaf::parse(&payload),
            Err(FormatError::BadSignature {
                structure: "lf",
                ..
            })
        ));
    }

    #[test]
    fn rejects_count_past_end() {
        let mut payload = sample().to_payload();
        // Claim 99 elements in a payload that only holds 2.
        payload[OFF_COUNT..OFF_COUNT + 2].copy_from_slice(&99u16.to_le_bytes());
        assert!(matches!(
            FastLeaf::parse(&payload),
            Err(FormatError::OutOfBounds {
                structure: "lf elements",
                ..
            })
        ));
    }

    #[test]
    fn name_hint_padding() {
        assert_eq!(name_hint(b""), [0, 0, 0, 0]);
        assert_eq!(name_hint(b"A"), [b'A', 0, 0, 0]);
        assert_eq!(name_hint(b"ABCD"), [b'A', b'B', b'C', b'D']);
        // Longer than 4 bytes is truncated to the first 4.
        assert_eq!(name_hint(b"ABCDEFG"), [b'A', b'B', b'C', b'D']);
    }
}
