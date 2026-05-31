//! Hive bins ("hbin") and the chain walk over them.
//!
//! The hive bins data follows the 4096-byte base block and is tiled by
//! hive bins. Each bin starts with a 32-byte header:
//!
//! ```text
//!   0x00  4   signature "hbin"
//!   0x04  4   offset of this bin from the start of the hive bins data
//!   0x08  4   size of this bin in bytes (a multiple of 4096)
//!   0x0C  8   reserved
//!   0x14  8   timestamp (only meaningful in the first bin)
//!   0x1C  4   spare / MemAlloc
//!   0x20      first cell
//! ```
//!
//! Cells fill the bin from offset 0x20 up to its declared size, back to
//! back, none crossing the bin boundary (CONTRACTS invariants 9 and 10).
//! This module walks the bin chain and the cells within each bin without
//! allocating (Hard Rule 2): everything is an iterator over borrowed
//! bytes.

use super::cell::{Cell, CELL_SIZE_FIELD};
use super::{read_u32, FormatError};

/// Bin sizes are a multiple of this.
pub const HBIN_ALIGN: u32 = 4096;

/// Size of the bin header.
pub const HBIN_HEADER_SIZE: usize = 0x20;

/// The "hbin" magic that opens every hive bin.
pub const HBIN_SIGNATURE: [u8; 4] = *b"hbin";

const OFF_SIGNATURE: usize = 0x00;
const OFF_FILE_OFFSET: usize = 0x04;
const OFF_SIZE: usize = 0x08;

/// A single parsed hive bin, borrowing its bytes.
#[derive(Debug, Clone, Copy)]
pub struct Hbin<'a> {
    /// The bin's own offset field (relative to the start of the hive bins
    /// data). For a well-formed hive this equals the walker's position.
    pub declared_offset: u32,
    /// Bin size in bytes, including the 32-byte header.
    pub size: u32,
    /// The full bin bytes (`size` bytes).
    bytes: &'a [u8],
}

impl<'a> Hbin<'a> {
    /// Parse a bin header at the start of `bytes` and frame the bin.
    ///
    /// `bytes` must hold at least the declared bin size. `position` is the
    /// bin's offset within the hive bins data and is used only for error
    /// reporting.
    fn parse(bytes: &'a [u8], position: usize) -> Result<Hbin<'a>, FormatError> {
        if bytes.len() < HBIN_HEADER_SIZE {
            return Err(FormatError::OutOfBounds {
                structure: "hbin header",
                offset: position,
                need: HBIN_HEADER_SIZE,
                available: bytes.len(),
            });
        }

        let signature: [u8; 4] = bytes[OFF_SIGNATURE..OFF_SIGNATURE + 4]
            .try_into()
            .expect("slice is 4 bytes");
        if signature != HBIN_SIGNATURE {
            return Err(FormatError::BadSignature {
                structure: "hbin",
                found: signature,
            });
        }

        let size = read_u32(bytes, OFF_SIZE);
        if size == 0 || !size.is_multiple_of(HBIN_ALIGN) {
            return Err(FormatError::Unaligned {
                structure: "hbin",
                value: size,
                align: HBIN_ALIGN,
            });
        }
        if (size as usize) > bytes.len() {
            return Err(FormatError::OutOfBounds {
                structure: "hbin",
                offset: position,
                need: size as usize,
                available: bytes.len(),
            });
        }

        Ok(Hbin {
            declared_offset: read_u32(bytes, OFF_FILE_OFFSET),
            size,
            bytes: &bytes[..size as usize],
        })
    }

    /// Iterate the cells in this bin, in on-disk order.
    pub fn cells(&self) -> CellIter<'a> {
        CellIter {
            // Cell offsets are reported relative to the hive bins data, so
            // the base offset of this bin's payload is its declared offset
            // plus the header.
            base: self.declared_offset as usize + HBIN_HEADER_SIZE,
            bytes: self.bytes,
            pos: HBIN_HEADER_SIZE,
        }
    }
}

/// Iterator over the cells within one bin.
pub struct CellIter<'a> {
    /// Offset of `bytes[HBIN_HEADER_SIZE]` within the hive bins data, used
    /// to report absolute cell offsets.
    base: usize,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for CellIter<'a> {
    type Item = Result<Cell<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.bytes.len() {
            return None;
        }
        // A trailing gap smaller than a size field cannot hold a cell; a
        // well-formed bin never leaves one, so treat it as corruption.
        if self.pos + CELL_SIZE_FIELD > self.bytes.len() {
            let err = FormatError::OutOfBounds {
                structure: "cell size",
                offset: self.base + (self.pos - HBIN_HEADER_SIZE),
                need: CELL_SIZE_FIELD,
                available: self.bytes.len() - self.pos,
            };
            self.pos = self.bytes.len();
            return Some(Err(err));
        }

        match Cell::parse_at(self.bytes, self.pos) {
            Ok(cell) => {
                // parse_at already guaranteed the cell fits in `self.bytes`,
                // i.e. within this bin, so it cannot cross the boundary.
                self.pos += cell.size as usize;
                Some(Ok(cell))
            }
            Err(e) => {
                self.pos = self.bytes.len();
                Some(Err(e))
            }
        }
    }
}

/// The hive bins data: everything in the file after the base block.
#[derive(Debug, Clone, Copy)]
pub struct HiveBins<'a> {
    data: &'a [u8],
}

impl<'a> HiveBins<'a> {
    /// Wrap the hive bins data slice (file bytes after the base block,
    /// `base_block.hbins_size` bytes long).
    pub fn new(data: &'a [u8]) -> HiveBins<'a> {
        HiveBins { data }
    }

    /// Walk the bin chain.
    pub fn hbins(&self) -> HbinIter<'a> {
        HbinIter {
            data: self.data,
            pos: 0,
        }
    }
}

/// Iterator over the hive bins in the chain.
pub struct HbinIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for HbinIter<'a> {
    type Item = Result<Hbin<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }
        match Hbin::parse(&self.data[self.pos..], self.pos) {
            Ok(hbin) => {
                self.pos += hbin.size as usize;
                Some(Ok(hbin))
            }
            Err(e) => {
                // Stop after the first malformed bin; the chain is broken.
                self.pos = self.data.len();
                Some(Err(e))
            }
        }
    }
}

/// Summary of a full hive bins walk (step 2's "count cells" result).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CellStats {
    /// Number of hive bins walked.
    pub hbin_count: usize,
    /// Number of allocated cells.
    pub allocated_cells: usize,
    /// Number of free cells.
    pub free_cells: usize,
    /// Total bytes accounted for by all cells (allocated and free).
    pub total_cell_bytes: u64,
}

impl CellStats {
    /// Total cells, allocated plus free.
    pub fn total_cells(&self) -> usize {
        self.allocated_cells + self.free_cells
    }
}

/// Walk every bin and every cell, returning counts.
///
/// This also enforces invariant 9 (the cell sizes in a bin sum to the bin
/// size minus its header): a bin whose cells do not tile it exactly yields
/// an error. Errors from the bin or cell iterators propagate.
pub fn walk(data: &[u8]) -> Result<CellStats, FormatError> {
    let hive = HiveBins::new(data);
    let mut stats = CellStats::default();

    for hbin in hive.hbins() {
        let hbin = hbin?;
        stats.hbin_count += 1;

        let mut cell_bytes_in_bin: u64 = 0;
        for cell in hbin.cells() {
            let cell = cell?;
            if cell.allocated {
                stats.allocated_cells += 1;
            } else {
                stats.free_cells += 1;
            }
            stats.total_cell_bytes += cell.size as u64;
            cell_bytes_in_bin += cell.size as u64;
        }

        // Invariant 9: cells exactly fill the bin payload.
        let payload = hbin.size as u64 - HBIN_HEADER_SIZE as u64;
        if cell_bytes_in_bin != payload {
            return Err(FormatError::OutOfBounds {
                structure: "hbin cells (sum != payload)",
                offset: hbin.declared_offset as usize + HBIN_HEADER_SIZE,
                need: payload as usize,
                available: cell_bytes_in_bin as usize,
            });
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one hive bin of `size` bytes (a multiple of 4096) at the
    /// given declared offset, filled with the supplied cells. Each
    /// `(allocated, size)` pair becomes a cell; the sizes must sum to
    /// `size - HBIN_HEADER_SIZE`.
    fn build_hbin(declared_offset: u32, size: u32, cells: &[(bool, u32)]) -> Vec<u8> {
        let mut buf = vec![0u8; size as usize];
        buf[0..4].copy_from_slice(&HBIN_SIGNATURE);
        buf[OFF_FILE_OFFSET..OFF_FILE_OFFSET + 4].copy_from_slice(&declared_offset.to_le_bytes());
        buf[OFF_SIZE..OFF_SIZE + 4].copy_from_slice(&size.to_le_bytes());

        let mut pos = HBIN_HEADER_SIZE;
        for &(allocated, csize) in cells {
            let raw: i32 = if allocated {
                -(csize as i32)
            } else {
                csize as i32
            };
            buf[pos..pos + 4].copy_from_slice(&raw.to_le_bytes());
            pos += csize as usize;
        }
        assert_eq!(pos, size as usize, "test cells must tile the bin exactly");
        buf
    }

    #[test]
    fn walks_single_bin() {
        // 4096-byte bin: one 32-byte allocated cell, rest one free cell.
        let free = 4096 - HBIN_HEADER_SIZE as u32 - 32;
        let bin = build_hbin(0, 4096, &[(true, 32), (false, free)]);
        let stats = walk(&bin).expect("walk");
        assert_eq!(stats.hbin_count, 1);
        assert_eq!(stats.allocated_cells, 1);
        assert_eq!(stats.free_cells, 1);
        assert_eq!(stats.total_cells(), 2);
        assert_eq!(stats.total_cell_bytes, 4096 - HBIN_HEADER_SIZE as u64);
    }

    #[test]
    fn walks_multiple_bins() {
        let free0 = 4096 - HBIN_HEADER_SIZE as u32 - 64;
        let mut bin0 = build_hbin(0, 4096, &[(true, 32), (true, 32), (false, free0)]);
        // Second bin is 8192 bytes, declared offset 4096.
        let free1 = 8192 - HBIN_HEADER_SIZE as u32 - 16;
        let bin1 = build_hbin(4096, 8192, &[(true, 16), (false, free1)]);
        bin0.extend_from_slice(&bin1);

        let stats = walk(&bin0).expect("walk");
        assert_eq!(stats.hbin_count, 2);
        assert_eq!(stats.allocated_cells, 3);
        assert_eq!(stats.free_cells, 2);
        assert_eq!(stats.total_cells(), 5);
    }

    #[test]
    fn cell_offsets_use_declared_offset() {
        // A bin whose declared offset is nonzero must report cell offsets
        // relative to the hive bins data, not the bin start.
        let free = 8192 - HBIN_HEADER_SIZE as u32 - 32;
        let bin = build_hbin(4096, 8192, &[(true, 32), (false, free)]);
        let hive = HiveBins::new(&bin);
        let hbin = hive.hbins().next().unwrap().unwrap();
        assert_eq!(hbin.declared_offset, 4096);
        let first = hbin.cells().next().unwrap().unwrap();
        assert!(first.allocated);
        assert_eq!(first.size, 32);
    }

    #[test]
    fn rejects_bad_hbin_signature() {
        let mut bin = build_hbin(0, 4096, &[(false, 4096 - HBIN_HEADER_SIZE as u32)]);
        bin[0..4].copy_from_slice(b"junk");
        match walk(&bin) {
            Err(FormatError::BadSignature { structure, .. }) => assert_eq!(structure, "hbin"),
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unaligned_hbin_size() {
        let mut bin = build_hbin(0, 4096, &[(false, 4096 - HBIN_HEADER_SIZE as u32)]);
        // Corrupt the size to a non-multiple of 4096.
        bin[OFF_SIZE..OFF_SIZE + 4].copy_from_slice(&5000u32.to_le_bytes());
        match walk(&bin) {
            Err(FormatError::Unaligned { structure, align, .. }) => {
                assert_eq!(structure, "hbin");
                assert_eq!(align, HBIN_ALIGN);
            }
            other => panic!("expected Unaligned, got {other:?}"),
        }
    }

    #[test]
    fn rejects_zero_cell_size() {
        // Hand-build a bin with a zero-size cell at the first slot.
        let mut bin = vec![0u8; 4096];
        bin[0..4].copy_from_slice(&HBIN_SIGNATURE);
        bin[OFF_SIZE..OFF_SIZE + 4].copy_from_slice(&4096u32.to_le_bytes());
        // cell size field left as zero.
        match walk(&bin) {
            Err(FormatError::ZeroCellSize { offset }) => {
                assert_eq!(offset, HBIN_HEADER_SIZE);
            }
            other => panic!("expected ZeroCellSize, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bin_shorter_than_declared_size() {
        // The bin header claims 8192 bytes but only 4096 are present.
        let mut bin = build_hbin(0, 4096, &[(false, 4096 - HBIN_HEADER_SIZE as u32)]);
        bin[OFF_SIZE..OFF_SIZE + 4].copy_from_slice(&8192u32.to_le_bytes());
        match walk(&bin) {
            Err(FormatError::OutOfBounds { structure, .. }) => assert_eq!(structure, "hbin"),
            other => panic!("expected OutOfBounds, got {other:?}"),
        }
    }
}
