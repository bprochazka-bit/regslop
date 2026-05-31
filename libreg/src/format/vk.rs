//! Value cells ("vk").
//!
//! A vk cell describes one named value of a key: its name, its REG_* data
//! type, and either its data inline or the offset of a data cell holding it.
//!
//! Layout of the vk record (offsets relative to the start of the record,
//! i.e. just after the cell's 4-byte size field), per docs/hive-format.md
//! section 3.2:
//!
//! ```text
//!   0x00  2   signature "vk"
//!   0x02  2   name length (bytes); 0 means the default value (name "")
//!   0x04  4   data size (top bit set => data stored inline)
//!   0x08  4   data offset, OR the inline data bytes when the top bit is set
//!   0x0C  4   data type (a REG_* constant)
//!   0x10  2   flags (bit 0 = VALUE_COMP_NAME, name is ASCII/Latin-1)
//!   0x12  2   spare
//!   0x14  ..  value name (ASCII when VALUE_COMP_NAME set, else UTF-16LE)
//! ```
//!
//! Like the other format modules this is a pure parser/serializer: it keeps
//! the raw `data_size` and `data_offset` words so the round trip is exact,
//! and exposes helpers to interpret the inline-data encoding. Deciding
//! whether data goes inline or into a separate cell is the logical layer's
//! job.

use super::{read_u16, read_u32, FormatError};

/// The "vk" signature.
pub const VK_SIGNATURE: [u8; 2] = *b"vk";

/// Fixed size of the vk record before the variable-length name.
pub const VK_HEADER_SIZE: usize = 0x14;

/// Set in `data_size` when the value's data is stored inline in the
/// `data_offset` field rather than in a separate data cell.
pub const VK_DATA_INLINE: u32 = 0x8000_0000;

/// Largest data length that fits inline (in the 4-byte `data_offset`).
pub const VK_INLINE_MAX: usize = 4;

/// Value name is stored as ASCII (Latin-1) rather than UTF-16LE.
pub const VALUE_COMP_NAME: u16 = 0x0001;

const OFF_NAME_LEN: usize = 0x02;
const OFF_DATA_SIZE: usize = 0x04;
const OFF_DATA_OFFSET: usize = 0x08;
const OFF_DATA_TYPE: usize = 0x0c;
const OFF_FLAGS: usize = 0x10;

/// A parsed value cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueKey {
    /// Raw data-size field, including the inline bit when set. Use
    /// [`data_len`](Self::data_len) for the actual length.
    pub data_size: u32,
    /// Raw data-offset field: an offset into the hive bins data, or the
    /// inline data bytes when [`is_inline`](Self::is_inline) is true.
    pub data_offset: u32,
    /// REG_* data type.
    pub data_type: u32,
    /// Flags (see [`VALUE_COMP_NAME`]).
    pub flags: u16,
    /// Raw on-disk name bytes (empty for the default value).
    pub name: Vec<u8>,
}

impl ValueKey {
    /// Parse a vk record from a cell payload (the bytes after the cell size
    /// field).
    pub fn parse(payload: &[u8]) -> Result<ValueKey, FormatError> {
        if payload.len() < VK_HEADER_SIZE {
            return Err(FormatError::OutOfBounds {
                structure: "vk header",
                offset: 0,
                need: VK_HEADER_SIZE,
                available: payload.len(),
            });
        }
        let signature: [u8; 2] = payload[0..2].try_into().expect("slice is 2 bytes");
        if signature != VK_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "vk",
                found: [signature[0], signature[1], 0, 0],
            });
        }

        let name_len = read_u16(payload, OFF_NAME_LEN) as usize;
        let name_end = VK_HEADER_SIZE + name_len;
        if name_end > payload.len() {
            return Err(FormatError::OutOfBounds {
                structure: "vk name",
                offset: VK_HEADER_SIZE,
                need: name_len,
                available: payload.len() - VK_HEADER_SIZE,
            });
        }

        Ok(ValueKey {
            data_size: read_u32(payload, OFF_DATA_SIZE),
            data_offset: read_u32(payload, OFF_DATA_OFFSET),
            data_type: read_u32(payload, OFF_DATA_TYPE),
            flags: read_u16(payload, OFF_FLAGS),
            name: payload[VK_HEADER_SIZE..name_end].to_vec(),
        })
    }

    /// Serialize the vk record (without the cell size field).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = vec![0u8; VK_HEADER_SIZE + self.name.len()];
        buf[0..2].copy_from_slice(&VK_SIGNATURE);
        buf[OFF_NAME_LEN..OFF_NAME_LEN + 2]
            .copy_from_slice(&(self.name.len() as u16).to_le_bytes());
        buf[OFF_DATA_SIZE..OFF_DATA_SIZE + 4].copy_from_slice(&self.data_size.to_le_bytes());
        buf[OFF_DATA_OFFSET..OFF_DATA_OFFSET + 4].copy_from_slice(&self.data_offset.to_le_bytes());
        buf[OFF_DATA_TYPE..OFF_DATA_TYPE + 4].copy_from_slice(&self.data_type.to_le_bytes());
        buf[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&self.flags.to_le_bytes());
        buf[VK_HEADER_SIZE..].copy_from_slice(&self.name);
        buf
    }

    /// Build a value whose data is stored inline. `data` must be at most
    /// [`VK_INLINE_MAX`] bytes; shorter data is zero padded into the
    /// `data_offset` word.
    pub fn new_inline(name: Vec<u8>, flags: u16, data_type: u32, data: &[u8]) -> ValueKey {
        assert!(data.len() <= VK_INLINE_MAX, "inline data exceeds 4 bytes");
        let mut packed = [0u8; 4];
        packed[..data.len()].copy_from_slice(data);
        ValueKey {
            data_size: VK_DATA_INLINE | data.len() as u32,
            data_offset: u32::from_le_bytes(packed),
            data_type,
            flags,
            name,
        }
    }

    /// Build a value whose data lives in a separate data cell at
    /// `data_offset`, of length `data_len`.
    pub fn new_pointer(
        name: Vec<u8>,
        flags: u16,
        data_type: u32,
        data_len: u32,
        data_offset: u32,
    ) -> ValueKey {
        ValueKey {
            data_size: data_len,
            data_offset,
            data_type,
            flags,
            name,
        }
    }

    /// True when the value's data is stored inline in `data_offset`.
    pub fn is_inline(&self) -> bool {
        self.data_size & VK_DATA_INLINE != 0
    }

    /// Actual data length in bytes, with the inline bit masked off.
    pub fn data_len(&self) -> u32 {
        self.data_size & !VK_DATA_INLINE
    }

    /// The inline data bytes (only meaningful when [`is_inline`](Self::is_inline)).
    pub fn inline_data(&self) -> Vec<u8> {
        let len = (self.data_len() as usize).min(VK_INLINE_MAX);
        self.data_offset.to_le_bytes()[..len].to_vec()
    }

    /// True when the name is ASCII-encoded (VALUE_COMP_NAME set). An empty
    /// (default) name is treated as ASCII.
    pub fn name_is_ascii(&self) -> bool {
        self.flags & VALUE_COMP_NAME != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::cell::{encode_cell, Cell};

    #[test]
    fn inline_round_trips() {
        // A REG_DWORD (type 4) value carrying 4 inline bytes.
        let vk = ValueKey::new_inline(
            b"Count".to_vec(),
            VALUE_COMP_NAME,
            4,
            &[0x78, 0x56, 0x34, 0x12],
        );
        assert!(vk.is_inline());
        assert_eq!(vk.data_len(), 4);
        assert_eq!(vk.inline_data(), vec![0x78, 0x56, 0x34, 0x12]);

        let parsed = ValueKey::parse(&vk.to_payload()).expect("parse");
        assert_eq!(parsed, vk);
        assert!(parsed.name_is_ascii());
        assert_eq!(parsed.data_type, 4);
    }

    #[test]
    fn short_inline_is_zero_padded() {
        // One inline byte: length 1, the other three bytes zero.
        let vk = ValueKey::new_inline(Vec::new(), 0, 3, &[0xAB]);
        assert_eq!(vk.data_len(), 1);
        assert_eq!(vk.inline_data(), vec![0xAB]);
        let parsed = ValueKey::parse(&vk.to_payload()).expect("parse");
        assert_eq!(parsed, vk);
        // Default value: empty name.
        assert_eq!(parsed.name.len(), 0);
    }

    #[test]
    fn pointer_round_trips() {
        let vk = ValueKey::new_pointer(b"Big".to_vec(), VALUE_COMP_NAME, 1, 2048, 0x1234);
        assert!(!vk.is_inline());
        assert_eq!(vk.data_len(), 2048);
        assert_eq!(vk.data_offset, 0x1234);
        let parsed = ValueKey::parse(&vk.to_payload()).expect("parse");
        assert_eq!(parsed, vk);
    }

    #[test]
    fn round_trips_through_a_cell() {
        let vk = ValueKey::new_inline(b"V".to_vec(), VALUE_COMP_NAME, 4, &[1, 0, 0, 0]);
        let cell_bytes = encode_cell(&vk.to_payload(), true);
        let cell = Cell::parse_at(&cell_bytes, 0).expect("frame cell");
        let parsed = ValueKey::parse(cell.data).expect("parse from padded payload");
        assert_eq!(parsed, vk);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut payload = ValueKey::new_inline(b"V".to_vec(), 0, 0, &[]).to_payload();
        payload[0..2].copy_from_slice(b"nk");
        assert!(matches!(
            ValueKey::parse(&payload),
            Err(FormatError::BadSignature {
                structure: "vk",
                ..
            })
        ));
    }

    #[test]
    fn rejects_short_header() {
        assert!(matches!(
            ValueKey::parse(&[b'v', b'k', 0, 0]),
            Err(FormatError::OutOfBounds {
                structure: "vk header",
                ..
            })
        ));
    }

    #[test]
    fn rejects_name_past_end() {
        let mut payload = ValueKey::new_inline(b"V".to_vec(), 0, 0, &[]).to_payload();
        payload[OFF_NAME_LEN..OFF_NAME_LEN + 2].copy_from_slice(&500u16.to_le_bytes());
        assert!(matches!(
            ValueKey::parse(&payload),
            Err(FormatError::OutOfBounds {
                structure: "vk name",
                ..
            })
        ));
    }
}
