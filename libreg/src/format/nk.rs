//! Key node cells ("nk").
//!
//! An nk cell describes one registry key: its flags, timestamp, links to
//! its parent, subkey list, value list, and security cell, plus its name.
//!
//! Layout of the nk record (offsets relative to the start of the record,
//! i.e. just after the cell's 4-byte size field), per Suhanov and offreg
//! hives:
//!
//! ```text
//!   0x00  2   signature "nk"
//!   0x02  2   flags
//!   0x04  8   last written timestamp (FILETIME)
//!   0x0C  4   access bits (0 on hives we create)
//!   0x10  4   parent key offset
//!   0x14  4   number of subkeys
//!   0x18  4   number of volatile subkeys
//!   0x1C  4   subkeys list offset
//!   0x20  4   volatile subkeys list offset
//!   0x24  4   number of values
//!   0x28  4   values list offset
//!   0x2C  4   security (sk) offset
//!   0x30  4   class name offset
//!   0x34  4   largest subkey name length
//!   0x38  4   largest subkey class name length
//!   0x3C  4   largest value name length
//!   0x40  4   largest value data length
//!   0x44  4   work var
//!   0x48  2   key name length (bytes)
//!   0x4A  2   class name length (bytes)
//!   0x4C  ..  key name (ASCII when KEY_COMP_NAME set, else UTF-16LE)
//! ```

use super::{read_u16, read_u32, read_u64, FormatError};

/// The "nk" signature.
pub const NK_SIGNATURE: [u8; 2] = *b"nk";

/// Fixed size of the nk record before the variable-length name.
pub const NK_HEADER_SIZE: usize = 0x4c;

/// Sentinel for "no offset" in a 32-bit link field.
pub const OFFSET_NONE: u32 = 0xffff_ffff;

// nk flag bits.
/// Key is volatile (not persisted).
pub const KEY_VOLATILE: u16 = 0x0001;
/// Mount point to another hive.
pub const KEY_HIVE_EXIT: u16 = 0x0002;
/// The root key of the hive.
pub const KEY_HIVE_ENTRY: u16 = 0x0004;
/// Key cannot be deleted.
pub const KEY_NO_DELETE: u16 = 0x0008;
/// Symbolic link key.
pub const KEY_SYM_LINK: u16 = 0x0010;
/// Name is stored as ASCII (Latin-1) rather than UTF-16LE.
pub const KEY_COMP_NAME: u16 = 0x0020;
/// Predefined handle key.
pub const KEY_PREDEF_HANDLE: u16 = 0x0040;

const OFF_FLAGS: usize = 0x02;
const OFF_LAST_WRITTEN: usize = 0x04;
const OFF_ACCESS_BITS: usize = 0x0c;
const OFF_PARENT: usize = 0x10;
const OFF_SUBKEY_COUNT: usize = 0x14;
const OFF_VOL_SUBKEY_COUNT: usize = 0x18;
const OFF_SUBKEYS_LIST: usize = 0x1c;
const OFF_VOL_SUBKEYS_LIST: usize = 0x20;
const OFF_VALUE_COUNT: usize = 0x24;
const OFF_VALUES_LIST: usize = 0x28;
const OFF_SECURITY: usize = 0x2c;
const OFF_CLASS_NAME: usize = 0x30;
const OFF_LARGEST_SUBKEY_NAME: usize = 0x34;
const OFF_LARGEST_SUBKEY_CLASS: usize = 0x38;
const OFF_LARGEST_VALUE_NAME: usize = 0x3c;
const OFF_LARGEST_VALUE_DATA: usize = 0x40;
const OFF_WORK_VAR: usize = 0x44;
const OFF_KEY_NAME_LEN: usize = 0x48;
const OFF_CLASS_NAME_LEN: usize = 0x4a;

/// A parsed key node.
///
/// `name` holds the raw on-disk name bytes: ASCII when [`KEY_COMP_NAME`]
/// is set in `flags`, UTF-16LE otherwise (CONTRACTS invariant 16). This
/// module keeps the bytes verbatim and does not decode them; decoding is
/// a higher-layer concern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyNode {
    pub flags: u16,
    pub last_written: u64,
    pub access_bits: u32,
    pub parent: u32,
    pub subkey_count: u32,
    pub volatile_subkey_count: u32,
    pub subkeys_list_offset: u32,
    pub volatile_subkeys_list_offset: u32,
    pub value_count: u32,
    pub values_list_offset: u32,
    pub security_offset: u32,
    pub class_name_offset: u32,
    pub largest_subkey_name_len: u32,
    pub largest_subkey_class_len: u32,
    pub largest_value_name_len: u32,
    pub largest_value_data_len: u32,
    pub work_var: u32,
    pub class_name_len: u16,
    /// Raw name bytes (see struct docs for encoding).
    pub name: Vec<u8>,
}

impl KeyNode {
    /// Parse an nk record from a cell payload (the bytes after the cell
    /// size field).
    pub fn parse(payload: &[u8]) -> Result<KeyNode, FormatError> {
        if payload.len() < NK_HEADER_SIZE {
            return Err(FormatError::OutOfBounds {
                structure: "nk header",
                offset: 0,
                need: NK_HEADER_SIZE,
                available: payload.len(),
            });
        }
        let signature: [u8; 2] = payload[0..2].try_into().expect("slice is 2 bytes");
        if signature != NK_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "nk",
                found: [signature[0], signature[1], 0, 0],
            });
        }

        let name_len = read_u16(payload, OFF_KEY_NAME_LEN) as usize;
        let name_end = NK_HEADER_SIZE + name_len;
        if name_end > payload.len() {
            return Err(FormatError::OutOfBounds {
                structure: "nk name",
                offset: NK_HEADER_SIZE,
                need: name_len,
                available: payload.len() - NK_HEADER_SIZE,
            });
        }

        Ok(KeyNode {
            flags: read_u16(payload, OFF_FLAGS),
            last_written: read_u64(payload, OFF_LAST_WRITTEN),
            access_bits: read_u32(payload, OFF_ACCESS_BITS),
            parent: read_u32(payload, OFF_PARENT),
            subkey_count: read_u32(payload, OFF_SUBKEY_COUNT),
            volatile_subkey_count: read_u32(payload, OFF_VOL_SUBKEY_COUNT),
            subkeys_list_offset: read_u32(payload, OFF_SUBKEYS_LIST),
            volatile_subkeys_list_offset: read_u32(payload, OFF_VOL_SUBKEYS_LIST),
            value_count: read_u32(payload, OFF_VALUE_COUNT),
            values_list_offset: read_u32(payload, OFF_VALUES_LIST),
            security_offset: read_u32(payload, OFF_SECURITY),
            class_name_offset: read_u32(payload, OFF_CLASS_NAME),
            largest_subkey_name_len: read_u32(payload, OFF_LARGEST_SUBKEY_NAME),
            largest_subkey_class_len: read_u32(payload, OFF_LARGEST_SUBKEY_CLASS),
            largest_value_name_len: read_u32(payload, OFF_LARGEST_VALUE_NAME),
            largest_value_data_len: read_u32(payload, OFF_LARGEST_VALUE_DATA),
            work_var: read_u32(payload, OFF_WORK_VAR),
            class_name_len: read_u16(payload, OFF_CLASS_NAME_LEN),
            name: payload[NK_HEADER_SIZE..name_end].to_vec(),
        })
    }

    /// Serialize the nk record (without the cell size field). The returned
    /// bytes are `NK_HEADER_SIZE + name.len()` long; the caller wraps them
    /// in a cell, which adds the size field and 8-byte padding.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut buf = vec![0u8; NK_HEADER_SIZE + self.name.len()];
        buf[0..2].copy_from_slice(&NK_SIGNATURE);
        buf[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&self.flags.to_le_bytes());
        buf[OFF_LAST_WRITTEN..OFF_LAST_WRITTEN + 8]
            .copy_from_slice(&self.last_written.to_le_bytes());
        buf[OFF_ACCESS_BITS..OFF_ACCESS_BITS + 4].copy_from_slice(&self.access_bits.to_le_bytes());
        buf[OFF_PARENT..OFF_PARENT + 4].copy_from_slice(&self.parent.to_le_bytes());
        buf[OFF_SUBKEY_COUNT..OFF_SUBKEY_COUNT + 4]
            .copy_from_slice(&self.subkey_count.to_le_bytes());
        buf[OFF_VOL_SUBKEY_COUNT..OFF_VOL_SUBKEY_COUNT + 4]
            .copy_from_slice(&self.volatile_subkey_count.to_le_bytes());
        buf[OFF_SUBKEYS_LIST..OFF_SUBKEYS_LIST + 4]
            .copy_from_slice(&self.subkeys_list_offset.to_le_bytes());
        buf[OFF_VOL_SUBKEYS_LIST..OFF_VOL_SUBKEYS_LIST + 4]
            .copy_from_slice(&self.volatile_subkeys_list_offset.to_le_bytes());
        buf[OFF_VALUE_COUNT..OFF_VALUE_COUNT + 4].copy_from_slice(&self.value_count.to_le_bytes());
        buf[OFF_VALUES_LIST..OFF_VALUES_LIST + 4]
            .copy_from_slice(&self.values_list_offset.to_le_bytes());
        buf[OFF_SECURITY..OFF_SECURITY + 4].copy_from_slice(&self.security_offset.to_le_bytes());
        buf[OFF_CLASS_NAME..OFF_CLASS_NAME + 4]
            .copy_from_slice(&self.class_name_offset.to_le_bytes());
        buf[OFF_LARGEST_SUBKEY_NAME..OFF_LARGEST_SUBKEY_NAME + 4]
            .copy_from_slice(&self.largest_subkey_name_len.to_le_bytes());
        buf[OFF_LARGEST_SUBKEY_CLASS..OFF_LARGEST_SUBKEY_CLASS + 4]
            .copy_from_slice(&self.largest_subkey_class_len.to_le_bytes());
        buf[OFF_LARGEST_VALUE_NAME..OFF_LARGEST_VALUE_NAME + 4]
            .copy_from_slice(&self.largest_value_name_len.to_le_bytes());
        buf[OFF_LARGEST_VALUE_DATA..OFF_LARGEST_VALUE_DATA + 4]
            .copy_from_slice(&self.largest_value_data_len.to_le_bytes());
        buf[OFF_WORK_VAR..OFF_WORK_VAR + 4].copy_from_slice(&self.work_var.to_le_bytes());
        buf[OFF_KEY_NAME_LEN..OFF_KEY_NAME_LEN + 2]
            .copy_from_slice(&(self.name.len() as u16).to_le_bytes());
        buf[OFF_CLASS_NAME_LEN..OFF_CLASS_NAME_LEN + 2]
            .copy_from_slice(&self.class_name_len.to_le_bytes());
        buf[NK_HEADER_SIZE..].copy_from_slice(&self.name);
        buf
    }

    /// True when the name is ASCII-encoded (KEY_COMP_NAME set).
    pub fn name_is_ascii(&self) -> bool {
        self.flags & KEY_COMP_NAME != 0
    }

    /// Build a root key node with an ASCII name and the given security
    /// cell offset and timestamp. All link fields start empty.
    ///
    /// Flags are KEY_COMP_NAME only. Suhanov's spec shows KEY_HIVE_ENTRY |
    /// KEY_NO_DELETE on a root, but the offreg reference hives in
    /// tests/corpus/synthetic show a saved standalone hive's root carrying
    /// just KEY_COMP_NAME (0x20); the kernel sets KEY_HIVE_ENTRY when it
    /// mounts a hive, not at save time. Hard Rule 4: match offreg, not docs.
    pub fn new_root(name: &str, security_offset: u32, last_written: u64) -> KeyNode {
        KeyNode {
            flags: KEY_COMP_NAME,
            last_written,
            access_bits: 0,
            parent: OFFSET_NONE,
            subkey_count: 0,
            volatile_subkey_count: 0,
            subkeys_list_offset: OFFSET_NONE,
            volatile_subkeys_list_offset: OFFSET_NONE,
            value_count: 0,
            values_list_offset: OFFSET_NONE,
            security_offset,
            class_name_offset: OFFSET_NONE,
            largest_subkey_name_len: 0,
            largest_subkey_class_len: 0,
            largest_value_name_len: 0,
            largest_value_data_len: 0,
            work_var: 0,
            class_name_len: 0,
            name: name.as_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::cell::{encode_cell, Cell};

    #[test]
    fn root_round_trips() {
        let root = KeyNode::new_root("ROOT", 0x78, 0x01dc_0000_0000_0000);
        let payload = root.to_payload();
        let parsed = KeyNode::parse(&payload).expect("parse");
        assert_eq!(parsed, root);
        assert_eq!(parsed.name, b"ROOT");
        assert!(parsed.name_is_ascii());
        // offreg saves a standalone root with KEY_COMP_NAME only (see new_root).
        assert_eq!(parsed.flags, KEY_COMP_NAME);
        assert_eq!(parsed.security_offset, 0x78);
        assert_eq!(parsed.subkey_count, 0);
        assert_eq!(parsed.value_count, 0);
    }

    #[test]
    fn round_trips_through_a_cell() {
        // Wrapping in a cell adds padding; parsing the cell payload (which
        // is longer than the record) must still recover the node, because
        // the name length bounds the record.
        let root = KeyNode::new_root("ROOT", 0x78, 7);
        let cell_bytes = encode_cell(&root.to_payload(), true);
        let cell = Cell::parse_at(&cell_bytes, 0).expect("frame cell");
        assert!(cell.allocated);
        let parsed = KeyNode::parse(cell.data).expect("parse from padded payload");
        assert_eq!(parsed, root);
    }

    #[test]
    fn rejects_short_payload() {
        let buf = [0u8; 10];
        assert!(matches!(
            KeyNode::parse(&buf),
            Err(FormatError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn rejects_bad_signature() {
        let root = KeyNode::new_root("ROOT", 0x78, 7);
        let mut payload = root.to_payload();
        payload[0..2].copy_from_slice(b"vk");
        assert!(matches!(
            KeyNode::parse(&payload),
            Err(FormatError::BadSignature { structure: "nk", .. })
        ));
    }

    #[test]
    fn rejects_name_past_end() {
        let root = KeyNode::new_root("ROOT", 0x78, 7);
        let mut payload = root.to_payload();
        // Claim a 4000-byte name in a payload that does not have it.
        payload[OFF_KEY_NAME_LEN..OFF_KEY_NAME_LEN + 2]
            .copy_from_slice(&4000u16.to_le_bytes());
        assert!(matches!(
            KeyNode::parse(&payload),
            Err(FormatError::OutOfBounds { structure: "nk name", .. })
        ));
    }
}
