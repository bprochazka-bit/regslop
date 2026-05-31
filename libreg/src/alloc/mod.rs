//! Layer 1: the cell allocator.
//!
//! Layer 1 owns free space inside the hive bins data. It knows about hbin
//! boundaries but does not interpret cell contents: it hands out and
//! reclaims byte ranges, and the logical layer above decides what nk/vk/lf
//! record goes inside. The allocation policy is deterministic first-fit
//! (Hard Rule 5): the same sequence of operations on the same starting
//! image always produces identical bytes, which is what makes `bytewise`
//! differential testing possible.
//!
//! Free-cell scanning and coalescing live in [`free_list`]; appending a new
//! hbin lives in [`hbin_grow`]. Neither allocates per operation (Hard Rule
//! 2); the only heap growth is extending the backing `Vec` when a new hbin
//! is appended, which is not a hot path.

pub mod free_list;
pub mod hbin_grow;

use crate::format::base_block::{BaseBlock, BASE_BLOCK_SIZE};
use crate::format::cell::cell_size_for;
use crate::format::hbin::{HBIN_ALIGN, HBIN_HEADER_SIZE};
use crate::format::read_i32;

/// An in-memory hive image that the allocator manages.
///
/// `bins` is the hive bins data only (the file bytes after the base block):
/// a chain of well-formed hbins. The base block is regenerated from this
/// data on [`to_hive_file`](HiveImage::to_hive_file), since it is fully
/// determined by the bins size and the root offset.
pub struct HiveImage {
    bins: Vec<u8>,
}

impl HiveImage {
    /// Wrap existing hive bins data (the file bytes after the base block).
    /// The caller guarantees it is a well-formed hbin chain.
    pub fn from_bins(bins: Vec<u8>) -> HiveImage {
        HiveImage { bins }
    }

    /// Start a fresh image holding one empty 4096-byte hbin (a header plus a
    /// single free cell). The first allocation carves space out of it.
    pub fn new_empty() -> HiveImage {
        let mut bins = Vec::new();
        hbin_grow::grow_for(&mut bins, HBIN_ALIGN - HBIN_HEADER_SIZE as u32);
        HiveImage { bins }
    }

    /// Allocate a cell whose content holds at least `payload_len` bytes and
    /// return its offset (relative to the hive bins data; the offset points
    /// at the 4-byte size field, matching every on-disk link). The content
    /// is zeroed; fill it through [`content_mut`](HiveImage::content_mut).
    /// Grows the image by a new hbin when nothing currently fits.
    pub fn alloc(&mut self, payload_len: usize) -> u32 {
        let need = cell_size_for(payload_len) as u32;
        let (off, free_size) = match free_list::find_free(&self.bins, need) {
            Some(hit) => hit,
            None => {
                let off = hbin_grow::grow_for(&mut self.bins, need);
                (off, read_i32(&self.bins, off) as u32)
            }
        };
        free_list::place(&mut self.bins, off, free_size, need);
        off as u32
    }

    /// Free the cell at `offset`, coalescing with adjacent free space.
    pub fn free(&mut self, offset: u32) {
        free_list::free(&mut self.bins, offset as usize);
    }

    /// Borrow the content bytes of the allocated cell at `offset`.
    pub fn content(&self, offset: u32) -> &[u8] {
        let (start, end) = self.content_range(offset);
        &self.bins[start..end]
    }

    /// Mutably borrow the content bytes of the allocated cell at `offset`.
    pub fn content_mut(&mut self, offset: u32) -> &mut [u8] {
        let (start, end) = self.content_range(offset);
        &mut self.bins[start..end]
    }

    fn content_range(&self, offset: u32) -> (usize, usize) {
        let off = offset as usize;
        let size = read_i32(&self.bins, off).unsigned_abs() as usize;
        (off + 4, off + size)
    }

    /// The hive bins data managed by this image.
    pub fn bins(&self) -> &[u8] {
        &self.bins
    }

    /// Total size of the hive bins data, the value the base block records at
    /// offset 40 (invariant 4).
    pub fn bins_size(&self) -> u32 {
        self.bins.len() as u32
    }

    /// Assemble a complete hive file: a base block pointing at `root_offset`
    /// and covering the bins data, followed by the bins data itself.
    pub fn to_hive_file(&self, root_offset: u32, last_written: u64) -> Vec<u8> {
        let bb = BaseBlock::create(root_offset, self.bins.len() as u32, last_written);
        let mut file = Vec::with_capacity(BASE_BLOCK_SIZE + self.bins.len());
        file.extend_from_slice(&bb.to_bytes());
        file.extend_from_slice(&self.bins);
        file
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::hbin::walk;

    /// Deterministic SplitMix64, mirroring the base_block property test, so
    /// the allocator property test needs no external rng dependency and is
    /// reproducible across runs and targets.
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[test]
    fn alloc_in_empty_bin_walks_clean() {
        let mut img = HiveImage::new_empty();
        let off = img.alloc(50);
        assert_eq!(
            off as usize, HBIN_HEADER_SIZE,
            "first cell sits after header"
        );
        // The allocated cell plus the trailing free remainder tile the bin.
        let stats = walk(img.bins()).expect("walk");
        assert_eq!(stats.hbin_count, 1);
        assert_eq!(stats.allocated_cells, 1);
        assert_eq!(stats.free_cells, 1);
    }

    #[test]
    fn content_is_zeroed_and_writable() {
        let mut img = HiveImage::new_empty();
        let off = img.alloc(16);
        assert!(img.content(off).iter().all(|&b| b == 0));
        img.content_mut(off)[0..4].copy_from_slice(b"nk\0\0");
        assert_eq!(&img.content(off)[0..2], b"nk");
    }

    #[test]
    fn many_allocs_keep_invariant_9() {
        let mut img = HiveImage::new_empty();
        for i in 0..20 {
            let off = img.alloc(8 + i * 3);
            // Tag the cell so we can later confirm no neighbour corrupts it.
            img.content_mut(off)[0] = i as u8;
        }
        walk(img.bins()).expect("walk stays green after many allocs");
    }

    #[test]
    fn free_coalesces_with_both_neighbours() {
        let mut img = HiveImage::new_empty();
        let a = img.alloc(40);
        let b = img.alloc(40);
        let c = img.alloc(40);
        // The bin starts with one trailing free cell after the three allocs.
        let before = walk(img.bins()).expect("walk").free_cells;
        // Freeing b leaves an isolated free cell between a and c.
        img.free(b);
        assert_eq!(walk(img.bins()).expect("walk").free_cells, before + 1);
        // Freeing a merges with b (backward neighbour of the trailing gap is
        // c, which is still allocated), so a+b become one free cell: count
        // returns to `before + 1` rather than `+ 2`.
        img.free(a);
        assert_eq!(
            walk(img.bins()).expect("walk").free_cells,
            before + 1,
            "a coalesces with the freed b"
        );
        // Freeing c now merges the whole region back into the trailing free
        // cell: one free cell, no allocations.
        img.free(c);
        let stats = walk(img.bins()).expect("walk");
        assert_eq!(stats.allocated_cells, 0);
        assert_eq!(stats.free_cells, 1, "everything coalesces back to one");
    }

    #[test]
    fn grows_to_a_second_bin_when_full() {
        let mut img = HiveImage::new_empty();
        // One bin holds ~4064 payload bytes; allocate past that.
        let mut total = 0;
        while total < 5000 {
            img.alloc(200);
            total += 200;
        }
        assert!(img.bins_size() >= 2 * HBIN_ALIGN, "image grew past one bin");
        let stats = walk(img.bins()).expect("walk");
        assert!(stats.hbin_count >= 2);
    }

    #[test]
    fn produces_a_loadable_hive_file() {
        let mut img = HiveImage::new_empty();
        let root = img.alloc(80);
        img.content_mut(root)[0..2].copy_from_slice(b"nk");
        let file = img.to_hive_file(root, 0x01dc_0000_0000_0000);
        let bb = BaseBlock::parse(&file).expect("base block parses");
        assert!(bb.checksum_valid());
        assert!(bb.is_clean());
        assert_eq!(bb.root_cell_offset, root);
        assert_eq!(bb.hbins_size, img.bins_size());
        // The bins still walk cleanly inside the assembled file.
        let data = &file[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + bb.hbins_size as usize];
        walk(data).expect("walk inside file");
    }

    #[test]
    fn deterministic_same_sequence_same_bytes() {
        fn run() -> Vec<u8> {
            let mut img = HiveImage::new_empty();
            let mut rng = SplitMix64(0x1234_5678);
            let mut live: Vec<u32> = Vec::new();
            for _ in 0..200 {
                if live.is_empty() || rng.below(100) < 60 {
                    let off = img.alloc(1 + rng.below(180) as usize);
                    live.push(off);
                } else {
                    let idx = rng.below(live.len() as u64) as usize;
                    img.free(live.swap_remove(idx));
                }
            }
            img.bins().to_vec()
        }
        assert_eq!(run(), run(), "Hard Rule 5: reproducible byte output");
    }

    #[test]
    fn property_random_ops_preserve_invariants() {
        let mut img = HiveImage::new_empty();
        let mut rng = SplitMix64(0xC0FF_EE42);
        // Each live cell carries a tag byte; a corrupting overlap would make
        // the tag mismatch, catching bugs invariant 9 alone would miss.
        let mut live: Vec<(u32, u8)> = Vec::new();
        let mut tag: u8 = 1;

        for _ in 0..400 {
            let do_alloc = live.is_empty() || rng.below(100) < 60;
            if do_alloc {
                let off = img.alloc(1 + rng.below(220) as usize);
                img.content_mut(off)[0] = tag;
                live.push((off, tag));
                tag = tag.wrapping_add(1);
            } else {
                let idx = rng.below(live.len() as u64) as usize;
                let (off, _) = live.swap_remove(idx);
                img.free(off);
            }

            // Invariant 9 and bin tiling, after every single operation.
            walk(img.bins()).expect("walk after each op");
            // No live cell was clobbered by an alloc/free elsewhere.
            for &(off, t) in &live {
                assert_eq!(img.content(off)[0], t, "cell {off:#x} tag survived");
            }
        }
    }
}
