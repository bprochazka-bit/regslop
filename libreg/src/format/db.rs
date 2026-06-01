//! Big-data cells ("db").
//!
//! A value whose data exceeds [`DB_MAX_SEGMENT`] bytes cannot fit in a single
//! data cell, so it is split into segments and indexed by a db cell. The vk's
//! data offset then points at the db cell instead of a plain data cell, and
//! its data size is the total (uncompressed) length (docs/hive-format.md 3.6;
//! CONTRACTS invariant 12).
//!
//! Layout of the db record (offsets relative to the start of the record,
//! i.e. just after the cell's 4-byte size field):
//!
//! ```text
//!   0x00  2   signature "db"
//!   0x02  2   segment count
//!   0x04  4   segment-list offset (a cell holding `count` u32 data offsets)
//! ```
//!
//! Each listed data cell holds up to [`DB_MAX_SEGMENT`] bytes; reassembly
//! concatenates the segments in order up to the vk's data size.
//!
//! NOTE: there is no db reference hive in tests/corpus/synthetic yet, so this
//! layout follows the documentation (Suhanov) and is NOT yet confirmed
//! byte-for-byte against offreg. The self-tests cover the libreg round trip;
//! a db corpus fixture is needed to verify offreg can load it (see STATE.md).

use super::{read_u16, read_u32, FormatError};

/// The "db" signature.
pub const DB_SIGNATURE: [u8; 2] = *b"db";

/// Fixed size of the db record.
pub const DB_HEADER_SIZE: usize = 0x08;

/// Maximum bytes per data segment, and the threshold at or below which a value
/// uses a single plain data cell instead of a db cell (0x3FD8).
pub const DB_MAX_SEGMENT: usize = 16344;

const OFF_SEGMENT_COUNT: usize = 0x02;
const OFF_SEGMENT_LIST: usize = 0x04;

/// A parsed big-data cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BigData {
    /// Number of data segments.
    pub segment_count: u16,
    /// Offset of the cell holding the segment data-cell offsets.
    pub segment_list_offset: u32,
}

impl BigData {
    /// Parse a db record from a cell payload.
    pub fn parse(payload: &[u8]) -> Result<BigData, FormatError> {
        if payload.len() < DB_HEADER_SIZE {
            return Err(FormatError::OutOfBounds {
                structure: "db header",
                offset: 0,
                need: DB_HEADER_SIZE,
                available: payload.len(),
            });
        }
        let signature: [u8; 2] = payload[0..2].try_into().expect("slice is 2 bytes");
        if signature != DB_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "db",
                found: [signature[0], signature[1], 0, 0],
            });
        }
        Ok(BigData {
            segment_count: read_u16(payload, OFF_SEGMENT_COUNT),
            segment_list_offset: read_u32(payload, OFF_SEGMENT_LIST),
        })
    }

    /// Serialize the db record (without the cell size field).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = vec![0u8; DB_HEADER_SIZE];
        buf[0..2].copy_from_slice(&DB_SIGNATURE);
        buf[OFF_SEGMENT_COUNT..OFF_SEGMENT_COUNT + 2]
            .copy_from_slice(&self.segment_count.to_le_bytes());
        buf[OFF_SEGMENT_LIST..OFF_SEGMENT_LIST + 4]
            .copy_from_slice(&self.segment_list_offset.to_le_bytes());
        buf
    }
}

/// Number of [`DB_MAX_SEGMENT`]-byte segments needed for `total` bytes.
pub fn segment_count_for(total: usize) -> usize {
    total.div_ceil(DB_MAX_SEGMENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::cell::{encode_cell, Cell};

    #[test]
    fn round_trips() {
        let db = BigData {
            segment_count: 7,
            segment_list_offset: 0x1234,
        };
        let parsed = BigData::parse(&db.to_payload()).expect("parse");
        assert_eq!(parsed, db);
    }

    #[test]
    fn round_trips_through_a_cell() {
        let db = BigData {
            segment_count: 2,
            segment_list_offset: 0x40,
        };
        let cell_bytes = encode_cell(&db.to_payload(), true);
        let cell = Cell::parse_at(&cell_bytes, 0).expect("frame cell");
        assert_eq!(BigData::parse(cell.data).unwrap(), db);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut payload = BigData {
            segment_count: 1,
            segment_list_offset: 0x40,
        }
        .to_payload();
        payload[0..2].copy_from_slice(b"vk");
        assert!(matches!(
            BigData::parse(&payload),
            Err(FormatError::BadSignature {
                structure: "db",
                ..
            })
        ));
    }

    #[test]
    fn rejects_short_header() {
        assert!(matches!(
            BigData::parse(&[b'd', b'b', 0]),
            Err(FormatError::OutOfBounds {
                structure: "db header",
                ..
            })
        ));
    }

    #[test]
    fn segment_count_matches_threshold() {
        assert_eq!(segment_count_for(1), 1);
        assert_eq!(segment_count_for(DB_MAX_SEGMENT), 1);
        assert_eq!(segment_count_for(DB_MAX_SEGMENT + 1), 2);
        assert_eq!(segment_count_for(100_000), 7); // 6*16344 = 98064, + 1936
    }
}
