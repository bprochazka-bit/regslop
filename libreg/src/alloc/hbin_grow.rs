//! Growing the hive bins data by appending a new hive bin (Layer 1).
//!
//! When no existing free cell can satisfy a request, the allocator adds a
//! fresh hbin to the end of the bins data. This module owns that one job
//! and keeps the new bin well-formed so the rest of Layer 1 can treat it
//! like any other.

use crate::format::hbin::{HBIN_ALIGN, HBIN_HEADER_SIZE, HBIN_SIGNATURE};

/// Append a new hbin large enough to hold a single free cell of at least
/// `need` bytes, and return that free cell's offset (its index in `bins`,
/// which for a well-formed image equals its on-disk offset).
///
/// The new bin is a whole multiple of [`HBIN_ALIGN`] (invariant 5), its
/// declared offset equals its position in the chain, and its payload is a
/// single free cell that tiles the bin exactly (invariant 9). Growing
/// extends the `Vec`, but it runs only when the existing bins are full, so
/// it is not one of the hot paths Hard Rule 2 governs.
pub(super) fn grow_for(bins: &mut Vec<u8>, need: u32) -> usize {
    let declared_offset = bins.len() as u32;
    let min_total = HBIN_HEADER_SIZE as u32 + need;
    let bin_size = min_total.next_multiple_of(HBIN_ALIGN);

    // Header: signature, this bin's offset, its size, then zeroed reserved
    // and timestamp fields.
    bins.extend_from_slice(&HBIN_SIGNATURE);
    bins.extend_from_slice(&declared_offset.to_le_bytes());
    bins.extend_from_slice(&bin_size.to_le_bytes());
    bins.extend_from_slice(&[0u8; HBIN_HEADER_SIZE - 12]);

    // One free cell (positive size) filling the remainder of the bin.
    let free_offset = declared_offset as usize + HBIN_HEADER_SIZE;
    let free_size = bin_size - HBIN_HEADER_SIZE as u32;
    bins.extend_from_slice(&free_size.to_le_bytes());
    bins.resize(declared_offset as usize + bin_size as usize, 0);

    free_offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::hbin::walk;

    #[test]
    fn grows_one_aligned_bin_that_walks() {
        let mut bins = Vec::new();
        let off = grow_for(&mut bins, HBIN_ALIGN - HBIN_HEADER_SIZE as u32);
        assert_eq!(bins.len(), HBIN_ALIGN as usize);
        assert_eq!(off, HBIN_HEADER_SIZE);
        let stats = walk(&bins).expect("walk");
        assert_eq!(stats.hbin_count, 1);
        assert_eq!(stats.free_cells, 1);
        assert_eq!(stats.allocated_cells, 0);
    }

    #[test]
    fn oversize_request_rounds_up_to_multiple_bins() {
        let mut bins = Vec::new();
        // Need more than one block of payload; the bin rounds up to 8192.
        let off = grow_for(&mut bins, 5000);
        assert_eq!(bins.len(), 2 * HBIN_ALIGN as usize);
        assert_eq!(off, HBIN_HEADER_SIZE);
        walk(&bins).expect("walk");
    }

    #[test]
    fn second_grow_chains_after_the_first() {
        let mut bins = Vec::new();
        grow_for(&mut bins, 64);
        let off2 = grow_for(&mut bins, 64);
        assert_eq!(off2, HBIN_ALIGN as usize + HBIN_HEADER_SIZE);
        let stats = walk(&bins).expect("walk");
        assert_eq!(stats.hbin_count, 2);
    }
}
