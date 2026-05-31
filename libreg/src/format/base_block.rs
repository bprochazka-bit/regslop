//! The hive base block (signature "regf").
//!
//! The base block is the first 4096 bytes of a hive file. It records the
//! format version, the primary and secondary sequence numbers used to
//! detect an interrupted write, the offset of the root cell, the total
//! size of the hive bins data, and a checksum over the leading 508 bytes.
//!
//! Layout (offsets are byte offsets into the base block), per Maxim
//! Suhanov's "Windows registry file format specification" and confirmed
//! against offreg-produced hives:
//!
//! ```text
//!   0x000  4   signature "regf"
//!   0x004  4   primary sequence number
//!   0x008  4   secondary sequence number
//!   0x00C  8   last written timestamp (Windows FILETIME)
//!   0x014  4   major version
//!   0x018  4   minor version
//!   0x01C  4   file type
//!   0x020  4   file format
//!   0x024  4   root cell offset
//!   0x028  4   hive bins data size
//!   0x02C  4   clustering factor
//!   0x030 64   file name (UTF-16LE)
//!   0x070 396  reserved (GUIDs, flags, log fields; opaque to v0.1)
//!   0x1FC  4   checksum (XOR of the 127 dwords at 0x000..0x1FC)
//!   0x200 3584 reserved tail (boot fields; opaque to v0.1)
//! ```
//!
//! We model the fields that the higher layers need and keep the two
//! reserved regions as raw bytes so that serialization reproduces the
//! input exactly. This is what makes the step 1 byte-equal round trip
//! hold even though we do not interpret every field.

use super::{read_u32, read_u64, FormatError};

/// Total size of the base block in bytes.
pub const BASE_BLOCK_SIZE: usize = 4096;

/// The "regf" magic that opens every hive.
pub const REGF_SIGNATURE: [u8; 4] = *b"regf";

/// Byte offset of the checksum dword.
pub const CHECKSUM_OFFSET: usize = 0x1fc;

/// Number of dwords covered by the checksum (offsets 0x000..0x1FC).
const CHECKSUM_DWORDS: usize = CHECKSUM_OFFSET / 4; // 127

// Field offsets.
const OFF_SIGNATURE: usize = 0x000;
const OFF_PRIMARY_SEQ: usize = 0x004;
const OFF_SECONDARY_SEQ: usize = 0x008;
const OFF_LAST_WRITTEN: usize = 0x00c;
const OFF_MAJOR: usize = 0x014;
const OFF_MINOR: usize = 0x018;
const OFF_FILE_TYPE: usize = 0x01c;
const OFF_FILE_FORMAT: usize = 0x020;
const OFF_ROOT_CELL: usize = 0x024;
const OFF_HBINS_SIZE: usize = 0x028;
const OFF_CLUSTERING: usize = 0x02c;
const OFF_FILE_NAME: usize = 0x030;
const OFF_RESERVED_MID: usize = 0x070;

const FILE_NAME_LEN: usize = 64;
const RESERVED_MID_LEN: usize = CHECKSUM_OFFSET - OFF_RESERVED_MID; // 396
const RESERVED_TAIL_LEN: usize = BASE_BLOCK_SIZE - 0x200; // 3584

/// A parsed hive base block.
///
/// The struct owns every byte of the original 4096-byte block: the named
/// fields plus the two opaque reserved regions. Re-serializing yields the
/// exact input bytes when nothing has been mutated.
#[derive(Clone)]
pub struct BaseBlock {
    /// Primary sequence number. Equals `secondary_seq` on a clean hive.
    pub primary_seq: u32,
    /// Secondary sequence number, bumped after a successful write.
    pub secondary_seq: u32,
    /// Last written timestamp as a Windows FILETIME (100 ns ticks since 1601).
    pub last_written: u64,
    /// Major format version (1 for all hives libreg handles).
    pub major_version: u32,
    /// Minor format version (3, 4, 5, or 6 in practice).
    pub minor_version: u32,
    /// File type (0 = primary hive).
    pub file_type: u32,
    /// File format (1 = direct memory load).
    pub file_format: u32,
    /// Byte offset of the root cell within the hive bins data.
    pub root_cell_offset: u32,
    /// Total size of the hive bins data in bytes (a multiple of 4096).
    pub hbins_size: u32,
    /// Clustering factor (always 1 for the hives libreg targets).
    pub clustering_factor: u32,
    /// Raw UTF-16LE file name field (64 bytes, often a partial path).
    file_name: [u8; FILE_NAME_LEN],
    /// Reserved bytes 0x070..0x1FC (GUIDs, flags, log fields).
    reserved_mid: [u8; RESERVED_MID_LEN],
    /// The checksum value as stored on disk.
    stored_checksum: u32,
    /// Reserved tail 0x200..0x1000 (boot fields).
    reserved_tail: [u8; RESERVED_TAIL_LEN],
}

impl BaseBlock {
    /// Build a base block for a freshly created hive.
    ///
    /// Sequence numbers start equal (a clean hive), version is 1.5, the
    /// file is a primary hive (`file_type` 0) loaded directly into memory
    /// (`file_format` 1), and the clustering factor is 1. The reserved
    /// regions and file name are zeroed. The checksum is computed.
    pub fn create(root_cell_offset: u32, hbins_size: u32, last_written: u64) -> BaseBlock {
        let mut bb = BaseBlock {
            primary_seq: 1,
            secondary_seq: 1,
            last_written,
            major_version: 1,
            minor_version: 5,
            file_type: 0,
            file_format: 1,
            root_cell_offset,
            hbins_size,
            clustering_factor: 1,
            file_name: [0u8; FILE_NAME_LEN],
            reserved_mid: [0u8; RESERVED_MID_LEN],
            stored_checksum: 0,
            reserved_tail: [0u8; RESERVED_TAIL_LEN],
        };
        bb.recompute_checksum();
        bb
    }

    /// Parse a base block from the leading bytes of a hive.
    ///
    /// `buf` must be at least [`BASE_BLOCK_SIZE`] bytes; any trailing bytes
    /// (the hive bins data) are ignored here.
    pub fn parse(buf: &[u8]) -> Result<BaseBlock, FormatError> {
        if buf.len() < BASE_BLOCK_SIZE {
            return Err(FormatError::Truncated {
                expected: BASE_BLOCK_SIZE,
                found: buf.len(),
            });
        }

        let signature: [u8; 4] = buf[OFF_SIGNATURE..OFF_SIGNATURE + 4]
            .try_into()
            .expect("slice is 4 bytes");
        if signature != REGF_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "base block",
                found: signature,
            });
        }

        let mut file_name = [0u8; FILE_NAME_LEN];
        file_name.copy_from_slice(&buf[OFF_FILE_NAME..OFF_FILE_NAME + FILE_NAME_LEN]);

        let mut reserved_mid = [0u8; RESERVED_MID_LEN];
        reserved_mid.copy_from_slice(&buf[OFF_RESERVED_MID..OFF_RESERVED_MID + RESERVED_MID_LEN]);

        let mut reserved_tail = [0u8; RESERVED_TAIL_LEN];
        reserved_tail.copy_from_slice(&buf[0x200..0x200 + RESERVED_TAIL_LEN]);

        Ok(BaseBlock {
            primary_seq: read_u32(buf, OFF_PRIMARY_SEQ),
            secondary_seq: read_u32(buf, OFF_SECONDARY_SEQ),
            last_written: read_u64(buf, OFF_LAST_WRITTEN),
            major_version: read_u32(buf, OFF_MAJOR),
            minor_version: read_u32(buf, OFF_MINOR),
            file_type: read_u32(buf, OFF_FILE_TYPE),
            file_format: read_u32(buf, OFF_FILE_FORMAT),
            root_cell_offset: read_u32(buf, OFF_ROOT_CELL),
            hbins_size: read_u32(buf, OFF_HBINS_SIZE),
            clustering_factor: read_u32(buf, OFF_CLUSTERING),
            file_name,
            reserved_mid,
            stored_checksum: read_u32(buf, CHECKSUM_OFFSET),
            reserved_tail,
        })
    }

    /// Serialize the base block into a fresh 4096-byte buffer.
    ///
    /// The stored checksum is written verbatim (see [`stored_checksum`]).
    /// Callers that have mutated header fields should call
    /// [`recompute_checksum`] first so the on-disk value stays consistent.
    ///
    /// [`stored_checksum`]: BaseBlock::stored_checksum
    /// [`recompute_checksum`]: BaseBlock::recompute_checksum
    pub fn to_bytes(&self) -> [u8; BASE_BLOCK_SIZE] {
        let mut buf = [0u8; BASE_BLOCK_SIZE];
        buf[OFF_SIGNATURE..OFF_SIGNATURE + 4].copy_from_slice(&REGF_SIGNATURE);
        buf[OFF_PRIMARY_SEQ..OFF_PRIMARY_SEQ + 4].copy_from_slice(&self.primary_seq.to_le_bytes());
        buf[OFF_SECONDARY_SEQ..OFF_SECONDARY_SEQ + 4]
            .copy_from_slice(&self.secondary_seq.to_le_bytes());
        buf[OFF_LAST_WRITTEN..OFF_LAST_WRITTEN + 8]
            .copy_from_slice(&self.last_written.to_le_bytes());
        buf[OFF_MAJOR..OFF_MAJOR + 4].copy_from_slice(&self.major_version.to_le_bytes());
        buf[OFF_MINOR..OFF_MINOR + 4].copy_from_slice(&self.minor_version.to_le_bytes());
        buf[OFF_FILE_TYPE..OFF_FILE_TYPE + 4].copy_from_slice(&self.file_type.to_le_bytes());
        buf[OFF_FILE_FORMAT..OFF_FILE_FORMAT + 4].copy_from_slice(&self.file_format.to_le_bytes());
        buf[OFF_ROOT_CELL..OFF_ROOT_CELL + 4]
            .copy_from_slice(&self.root_cell_offset.to_le_bytes());
        buf[OFF_HBINS_SIZE..OFF_HBINS_SIZE + 4].copy_from_slice(&self.hbins_size.to_le_bytes());
        buf[OFF_CLUSTERING..OFF_CLUSTERING + 4]
            .copy_from_slice(&self.clustering_factor.to_le_bytes());
        buf[OFF_FILE_NAME..OFF_FILE_NAME + FILE_NAME_LEN].copy_from_slice(&self.file_name);
        buf[OFF_RESERVED_MID..OFF_RESERVED_MID + RESERVED_MID_LEN]
            .copy_from_slice(&self.reserved_mid);
        buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4]
            .copy_from_slice(&self.stored_checksum.to_le_bytes());
        buf[0x200..0x200 + RESERVED_TAIL_LEN].copy_from_slice(&self.reserved_tail);
        buf
    }

    /// The checksum value currently stored in the block.
    pub fn stored_checksum(&self) -> u32 {
        self.stored_checksum
    }

    /// Compute the checksum the block *should* carry given its other fields.
    ///
    /// The algorithm matches offreg and the Windows kernel: XOR the 127
    /// little-endian dwords at offsets 0x000..0x1FC. A result of 0 is
    /// stored as 1 and a result of 0xFFFFFFFF as 0xFFFFFFFE, because those
    /// two values are reserved to mean "no checksum".
    pub fn computed_checksum(&self) -> u32 {
        let bytes = self.to_bytes();
        compute_checksum(&bytes)
    }

    /// Returns true when the stored checksum matches the computed one.
    pub fn checksum_valid(&self) -> bool {
        self.stored_checksum == self.computed_checksum()
    }

    /// Recompute and store the checksum. Call after mutating header fields.
    pub fn recompute_checksum(&mut self) {
        self.stored_checksum = self.computed_checksum();
    }

    /// True when primary and secondary sequence numbers agree, meaning the
    /// last write completed and no log replay is required.
    pub fn is_clean(&self) -> bool {
        self.primary_seq == self.secondary_seq
    }
}

impl core::fmt::Debug for BaseBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BaseBlock")
            .field("primary_seq", &self.primary_seq)
            .field("secondary_seq", &self.secondary_seq)
            .field("last_written", &self.last_written)
            .field(
                "version",
                &format_args!("{}.{}", self.major_version, self.minor_version),
            )
            .field("file_type", &self.file_type)
            .field("file_format", &self.file_format)
            .field("root_cell_offset", &format_args!("{:#x}", self.root_cell_offset))
            .field("hbins_size", &self.hbins_size)
            .field("clustering_factor", &self.clustering_factor)
            .field("stored_checksum", &format_args!("{:#010x}", self.stored_checksum))
            .finish_non_exhaustive()
    }
}

/// Compute the base block checksum over a full 4096-byte block.
///
/// Only the first 508 bytes (127 dwords) participate. See
/// [`BaseBlock::computed_checksum`] for the reserved-value rules.
pub fn compute_checksum(buf: &[u8]) -> u32 {
    debug_assert!(buf.len() >= CHECKSUM_OFFSET);
    let mut acc: u32 = 0;
    for i in 0..CHECKSUM_DWORDS {
        acc ^= read_u32(buf, i * 4);
    }
    match acc {
        0xffff_ffff => 0xffff_fffe,
        0 => 1,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but well-formed base block buffer for a hive whose
    /// hive bins data is `hbins_size` bytes long.
    fn synthetic(hbins_size: u32) -> [u8; BASE_BLOCK_SIZE] {
        let mut buf = [0u8; BASE_BLOCK_SIZE];
        buf[0..4].copy_from_slice(&REGF_SIGNATURE);
        buf[OFF_PRIMARY_SEQ..OFF_PRIMARY_SEQ + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_SECONDARY_SEQ..OFF_SECONDARY_SEQ + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_MAJOR..OFF_MAJOR + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_MINOR..OFF_MINOR + 4].copy_from_slice(&5u32.to_le_bytes());
        buf[OFF_FILE_TYPE..OFF_FILE_TYPE + 4].copy_from_slice(&0u32.to_le_bytes());
        buf[OFF_FILE_FORMAT..OFF_FILE_FORMAT + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[OFF_ROOT_CELL..OFF_ROOT_CELL + 4].copy_from_slice(&0x20u32.to_le_bytes());
        buf[OFF_HBINS_SIZE..OFF_HBINS_SIZE + 4].copy_from_slice(&hbins_size.to_le_bytes());
        buf[OFF_CLUSTERING..OFF_CLUSTERING + 4].copy_from_slice(&1u32.to_le_bytes());
        let checksum = compute_checksum(&buf);
        buf[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
        buf
    }

    #[test]
    fn parses_known_fields() {
        let buf = synthetic(0x1000);
        let bb = BaseBlock::parse(&buf).expect("parse");
        assert_eq!(bb.primary_seq, 1);
        assert_eq!(bb.secondary_seq, 1);
        assert_eq!(bb.major_version, 1);
        assert_eq!(bb.minor_version, 5);
        assert_eq!(bb.file_type, 0);
        assert_eq!(bb.file_format, 1);
        assert_eq!(bb.root_cell_offset, 0x20);
        assert_eq!(bb.hbins_size, 0x1000);
        assert_eq!(bb.clustering_factor, 1);
        assert!(bb.is_clean());
        assert!(bb.checksum_valid());
    }

    #[test]
    fn round_trip_is_byte_exact() {
        let buf = synthetic(0x4000);
        let bb = BaseBlock::parse(&buf).expect("parse");
        let out = bb.to_bytes();
        assert_eq!(&buf[..], &out[..], "serialize must reproduce input bytes");
    }

    #[test]
    fn rejects_short_buffer() {
        let buf = [0u8; 128];
        match BaseBlock::parse(&buf) {
            Err(FormatError::Truncated { expected, found }) => {
                assert_eq!(expected, BASE_BLOCK_SIZE);
                assert_eq!(found, 128);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_signature() {
        let mut buf = synthetic(0x1000);
        buf[0..4].copy_from_slice(b"junk");
        match BaseBlock::parse(&buf) {
            Err(FormatError::BadSignature { structure, found }) => {
                assert_eq!(structure, "base block");
                assert_eq!(&found, b"junk");
            }
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn checksum_special_cases() {
        // All-zero leading region XORs to 0, which must be stored as 1.
        let buf = [0u8; BASE_BLOCK_SIZE];
        assert_eq!(compute_checksum(&buf), 1);

        // A single dword of 0xFFFFFFFF XORs to 0xFFFFFFFF, stored as
        // 0xFFFFFFFE.
        let mut buf = [0u8; BASE_BLOCK_SIZE];
        buf[0..4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert_eq!(compute_checksum(&buf), 0xffff_fffe);
    }

    #[test]
    fn recompute_after_mutation_keeps_block_valid() {
        let mut bb = BaseBlock::parse(&synthetic(0x1000)).expect("parse");
        // Bump both sequence numbers (keeping the hive clean) and the
        // timestamp. Note that equal changes to primary and secondary seq
        // cancel in the XOR checksum, so the timestamp change is what makes
        // the stored checksum go stale here.
        bb.primary_seq = 42;
        bb.secondary_seq = 42;
        bb.last_written = 0x01dc_0000_0000_0000;
        assert!(!bb.checksum_valid(), "stale checksum after mutation");
        bb.recompute_checksum();
        assert!(bb.checksum_valid(), "checksum valid after recompute");
        // And the recomputed block still round-trips.
        let reparsed = BaseBlock::parse(&bb.to_bytes()).expect("reparse");
        assert_eq!(reparsed.primary_seq, 42);
        assert_eq!(reparsed.last_written, 0x01dc_0000_0000_0000);
        assert!(reparsed.checksum_valid());
    }

    /// Generative round-trip check: many pseudo-random base blocks (varied
    /// reserved regions and fields) must serialize back to identical bytes.
    /// This stands in for a proptest-style property until we add a
    /// dependency; the deterministic LCG keeps it reproducible and runnable
    /// on big-endian targets.
    #[test]
    fn round_trip_property_many_inputs() {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            // SplitMix64-ish step; deterministic, no host RNG.
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)) as u8
        };

        for _ in 0..256 {
            let mut buf = [0u8; BASE_BLOCK_SIZE];
            for b in buf.iter_mut() {
                *b = next();
            }
            // Keep the signature valid so parse succeeds; every other byte,
            // including the stored checksum, is arbitrary and must survive.
            buf[0..4].copy_from_slice(&REGF_SIGNATURE);

            let bb = BaseBlock::parse(&buf).expect("parse arbitrary block");
            let out = bb.to_bytes();
            assert_eq!(&buf[..], &out[..], "round trip must be byte exact");
        }
    }
}
