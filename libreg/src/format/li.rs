//! Index-leaf subkey lists ("li").
//!
//! An li is the simplest subkey list: a bare array of subkey nk offsets, with
//! no name hint or hash (unlike lf/lh). Old hives use it; modern hives write
//! lh instead (CONTRACTS invariant 11). libreg parses li so it can read such
//! hives, but does not emit it.
//!
//! Layout of the li record (offsets relative to the start of the record,
//! i.e. just after the cell's 4-byte size field):
//!
//! ```text
//!   0x00  2   signature "li"
//!   0x02  2   number of elements
//!   0x04  ..  elements, 4 bytes each: a subkey nk offset
//! ```

use super::{read_u16, read_u32, FormatError};

/// The "li" signature.
pub const LI_SIGNATURE: [u8; 2] = *b"li";

/// Fixed size of the li record header before the elements.
pub const LI_HEADER_SIZE: usize = 0x04;

/// Size of one li element on disk (a u32 offset).
pub const LI_ELEMENT_SIZE: usize = 4;

const OFF_COUNT: usize = 0x02;

/// A parsed index-leaf subkey list: the offsets of a key's subkeys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IndexLeaf {
    /// Subkey nk offsets, in on-disk (name-sorted) order.
    pub offsets: Vec<u32>,
}

impl IndexLeaf {
    /// Parse an li record from a cell payload.
    pub fn parse(payload: &[u8]) -> Result<IndexLeaf, FormatError> {
        if payload.len() < LI_HEADER_SIZE {
            return Err(FormatError::OutOfBounds {
                structure: "li header",
                offset: 0,
                need: LI_HEADER_SIZE,
                available: payload.len(),
            });
        }
        let signature: [u8; 2] = payload[0..2].try_into().expect("slice is 2 bytes");
        if signature != LI_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "li",
                found: [signature[0], signature[1], 0, 0],
            });
        }

        let count = read_u16(payload, OFF_COUNT) as usize;
        let need = LI_HEADER_SIZE + count * LI_ELEMENT_SIZE;
        if need > payload.len() {
            return Err(FormatError::OutOfBounds {
                structure: "li elements",
                offset: LI_HEADER_SIZE,
                need: count * LI_ELEMENT_SIZE,
                available: payload.len() - LI_HEADER_SIZE,
            });
        }

        let mut offsets = Vec::with_capacity(count);
        for i in 0..count {
            offsets.push(read_u32(payload, LI_HEADER_SIZE + i * LI_ELEMENT_SIZE));
        }
        Ok(IndexLeaf { offsets })
    }

    /// Serialize the li record (without the cell size field).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = vec![0u8; LI_HEADER_SIZE + self.offsets.len() * LI_ELEMENT_SIZE];
        buf[0..2].copy_from_slice(&LI_SIGNATURE);
        buf[OFF_COUNT..OFF_COUNT + 2].copy_from_slice(&(self.offsets.len() as u16).to_le_bytes());
        for (i, off) in self.offsets.iter().enumerate() {
            let base = LI_HEADER_SIZE + i * LI_ELEMENT_SIZE;
            buf[base..base + 4].copy_from_slice(&off.to_le_bytes());
        }
        buf
    }

    /// Number of subkeys recorded in this list.
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// True when the list holds no subkeys.
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::cell::{encode_cell, Cell};

    #[test]
    fn round_trips() {
        let li = IndexLeaf {
            offsets: vec![0x20, 0x140, 0x2a0],
        };
        let parsed = IndexLeaf::parse(&li.to_payload()).expect("parse");
        assert_eq!(parsed, li);
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn empty_round_trips() {
        let li = IndexLeaf::default();
        assert!(li.is_empty());
        assert_eq!(IndexLeaf::parse(&li.to_payload()).unwrap(), li);
    }

    #[test]
    fn round_trips_through_a_cell() {
        let li = IndexLeaf {
            offsets: vec![0x20, 0x140],
        };
        let cell_bytes = encode_cell(&li.to_payload(), true);
        let cell = Cell::parse_at(&cell_bytes, 0).expect("frame cell");
        assert_eq!(IndexLeaf::parse(cell.data).unwrap(), li);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut payload = IndexLeaf {
            offsets: vec![0x20],
        }
        .to_payload();
        payload[0..2].copy_from_slice(b"ri");
        assert!(matches!(
            IndexLeaf::parse(&payload),
            Err(FormatError::BadSignature {
                structure: "li",
                ..
            })
        ));
    }

    #[test]
    fn rejects_count_past_end() {
        let mut payload = IndexLeaf {
            offsets: vec![0x20],
        }
        .to_payload();
        payload[OFF_COUNT..OFF_COUNT + 2].copy_from_slice(&99u16.to_le_bytes());
        assert!(matches!(
            IndexLeaf::parse(&payload),
            Err(FormatError::OutOfBounds {
                structure: "li elements",
                ..
            })
        ));
    }
}
