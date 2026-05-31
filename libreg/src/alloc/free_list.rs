//! Free-space management within the hive bins data (Layer 1).
//!
//! The free list is implicit: a cell with a positive size field is free
//! (invariant 6), so the allocator finds space by scanning the bin chain
//! rather than holding a separate boxed structure. Cell positions are byte
//! indices into the hive bins data; for a well-formed image a cell's index
//! equals its on-disk offset. These functions never allocate (Hard Rule 2);
//! they only read and rewrite size fields in place.

use crate::format::cell::CELL_ALIGN;
use crate::format::hbin::HBIN_HEADER_SIZE;
use crate::format::{read_i32, read_u32};

/// Smallest possible cell: the 4-byte size field padded to 8. Because both
/// requests and free cells are multiples of 8, a split never leaves a
/// fragment smaller than this (it leaves either 0 or at least 8 bytes).
const MIN_CELL: u32 = CELL_ALIGN;

const OFF_HBIN_SIZE: usize = 8;

/// First-fit search: the lowest-offset free cell whose size is at least
/// `need`. Returns `(offset, size)`, or `None` when nothing fits. Scanning
/// lowest-offset-first is what makes the byte output reproducible
/// (Hard Rule 5).
pub(super) fn find_free(bins: &[u8], need: u32) -> Option<(usize, u32)> {
    let mut p = 0usize;
    while p + HBIN_HEADER_SIZE <= bins.len() {
        let hsize = read_u32(bins, p + OFF_HBIN_SIZE) as usize;
        let bin_end = p + hsize;
        let mut c = p + HBIN_HEADER_SIZE;
        while c < bin_end {
            let raw = read_i32(bins, c);
            let size = raw.unsigned_abs();
            // A zero size would never advance the scan; a well-formed image
            // never holds one, so stop rather than spin.
            if size == 0 {
                break;
            }
            if raw > 0 && size >= need {
                return Some((c, size));
            }
            c += size as usize;
        }
        p = bin_end;
    }
    None
}

/// Mark the free cell at `off` (its current size is `free_size`) as
/// allocated, taking `need` bytes. If the leftover is a whole cell the tail
/// stays free and the head is the allocation; otherwise the whole cell is
/// taken (internal slack). The allocated content is zeroed so equal
/// operation sequences yield equal bytes (Hard Rule 5).
pub(super) fn place(bins: &mut [u8], off: usize, free_size: u32, need: u32) {
    let remainder = free_size - need;
    let alloc_size = if remainder >= MIN_CELL {
        set_size(bins, off + need as usize, remainder as i32);
        need
    } else {
        free_size
    };
    set_size(bins, off, -(alloc_size as i32));
    bins[off + 4..off + alloc_size as usize].fill(0);
}

/// Free the allocated cell at `off`, coalescing with an immediately
/// adjacent free cell on either side within the same hbin. Cells never
/// merge across an hbin boundary (invariant 10).
pub(super) fn free(bins: &mut [u8], off: usize) {
    let size = read_i32(bins, off).unsigned_abs() as usize;
    set_size(bins, off, size as i32); // flip to free

    let (bin_start, bin_size) = bin_of(bins, off);
    let bin_end = bin_start + bin_size;

    // Forward: absorb the next cell if it is free.
    let mut merged = size;
    let next = off + merged;
    if next < bin_end && read_i32(bins, next) > 0 {
        merged += read_i32(bins, next).unsigned_abs() as usize;
        set_size(bins, off, merged as i32);
    }

    // Backward: find the cell whose end touches `off`; if it is free, let
    // it absorb the (already forward-merged) cell at `off`.
    let payload_start = bin_start + HBIN_HEADER_SIZE;
    if off > payload_start {
        let mut c = payload_start;
        while c < off {
            let csize = read_i32(bins, c).unsigned_abs() as usize;
            if csize == 0 {
                break;
            }
            if c + csize == off {
                if read_i32(bins, c) > 0 {
                    set_size(bins, c, (csize + merged) as i32);
                }
                break;
            }
            c += csize;
        }
    }
}

/// Write a signed cell size field at `off`.
fn set_size(bins: &mut [u8], off: usize, signed: i32) {
    bins[off..off + 4].copy_from_slice(&signed.to_le_bytes());
}

/// Locate the hbin containing `off`, returning `(bin_start, bin_size)`.
fn bin_of(bins: &[u8], off: usize) -> (usize, usize) {
    let mut p = 0usize;
    while p + HBIN_HEADER_SIZE <= bins.len() {
        let hsize = read_u32(bins, p + OFF_HBIN_SIZE) as usize;
        if off >= p && off < p + hsize {
            return (p, hsize);
        }
        p += hsize;
    }
    unreachable!("offset {off} lies outside every hbin")
}
