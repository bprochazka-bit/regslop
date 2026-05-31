//! Index-root subkey lists ("ri").
//!
//! An ri does not list subkeys directly: it lists the offsets of other subkey
//! list cells (lf/lh/li leaves), chaining several leaves when one is not
//! enough. offreg promotes a single lh leaf to an ri of lh leaves once a key
//! has more than 507 subkeys (tests/corpus/synthetic/ref_ri.hiv: 1100 keys as
//! an ri of three lh leaves [507, 507, 86]).
//!
//! An ri MUST NOT point at another ri, and a non-root list MUST NOT point at
//! an ri (docs/hive-format.md 3.4); the tree is exactly two levels deep.
//!
//! Layout of the ri record (offsets relative to the start of the record):
//!
//! ```text
//!   0x00  2   signature "ri"
//!   0x02  2   number of leaves
//!   0x04  ..  leaves, 4 bytes each: the offset of an lf/lh/li cell
//! ```

use super::{read_u16, read_u32, FormatError};

/// The "ri" signature.
pub const RI_SIGNATURE: [u8; 2] = *b"ri";

/// Fixed size of the ri record header before the leaf offsets.
pub const RI_HEADER_SIZE: usize = 0x04;

/// Size of one ri element on disk (a u32 leaf offset).
pub const RI_ELEMENT_SIZE: usize = 4;

const OFF_COUNT: usize = 0x02;

/// A parsed index root: the offsets of the leaf subkey lists it chains.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IndexRoot {
    /// Offsets of the leaf list cells (lf/lh/li), in key order.
    pub leaf_offsets: Vec<u32>,
}

impl IndexRoot {
    /// Parse an ri record from a cell payload.
    pub fn parse(payload: &[u8]) -> Result<IndexRoot, FormatError> {
        if payload.len() < RI_HEADER_SIZE {
            return Err(FormatError::OutOfBounds {
                structure: "ri header",
                offset: 0,
                need: RI_HEADER_SIZE,
                available: payload.len(),
            });
        }
        let signature: [u8; 2] = payload[0..2].try_into().expect("slice is 2 bytes");
        if signature != RI_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "ri",
                found: [signature[0], signature[1], 0, 0],
            });
        }

        let count = read_u16(payload, OFF_COUNT) as usize;
        let need = RI_HEADER_SIZE + count * RI_ELEMENT_SIZE;
        if need > payload.len() {
            return Err(FormatError::OutOfBounds {
                structure: "ri leaves",
                offset: RI_HEADER_SIZE,
                need: count * RI_ELEMENT_SIZE,
                available: payload.len() - RI_HEADER_SIZE,
            });
        }

        let mut leaf_offsets = Vec::with_capacity(count);
        for i in 0..count {
            leaf_offsets.push(read_u32(payload, RI_HEADER_SIZE + i * RI_ELEMENT_SIZE));
        }
        Ok(IndexRoot { leaf_offsets })
    }

    /// Serialize the ri record (without the cell size field).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = vec![0u8; RI_HEADER_SIZE + self.leaf_offsets.len() * RI_ELEMENT_SIZE];
        buf[0..2].copy_from_slice(&RI_SIGNATURE);
        buf[OFF_COUNT..OFF_COUNT + 2]
            .copy_from_slice(&(self.leaf_offsets.len() as u16).to_le_bytes());
        for (i, off) in self.leaf_offsets.iter().enumerate() {
            let base = RI_HEADER_SIZE + i * RI_ELEMENT_SIZE;
            buf[base..base + 4].copy_from_slice(&off.to_le_bytes());
        }
        buf
    }

    /// Number of leaves this index root chains.
    pub fn len(&self) -> usize {
        self.leaf_offsets.len()
    }

    /// True when the index root chains no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaf_offsets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::cell::{encode_cell, Cell};

    #[test]
    fn round_trips() {
        let ri = IndexRoot {
            leaf_offsets: vec![0x1020, 0x2020, 0x138],
        };
        let parsed = IndexRoot::parse(&ri.to_payload()).expect("parse");
        assert_eq!(parsed, ri);
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn round_trips_through_a_cell() {
        let ri = IndexRoot {
            leaf_offsets: vec![0x1020, 0x2020],
        };
        let cell_bytes = encode_cell(&ri.to_payload(), true);
        let cell = Cell::parse_at(&cell_bytes, 0).expect("frame cell");
        assert_eq!(IndexRoot::parse(cell.data).unwrap(), ri);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut payload = IndexRoot {
            leaf_offsets: vec![0x20],
        }
        .to_payload();
        payload[0..2].copy_from_slice(b"li");
        assert!(matches!(
            IndexRoot::parse(&payload),
            Err(FormatError::BadSignature {
                structure: "ri",
                ..
            })
        ));
    }

    #[test]
    fn rejects_count_past_end() {
        let mut payload = IndexRoot {
            leaf_offsets: vec![0x20],
        }
        .to_payload();
        payload[OFF_COUNT..OFF_COUNT + 2].copy_from_slice(&99u16.to_le_bytes());
        assert!(matches!(
            IndexRoot::parse(&payload),
            Err(FormatError::OutOfBounds {
                structure: "ri leaves",
                ..
            })
        ));
    }
}
