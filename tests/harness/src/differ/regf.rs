//! Minimal regf (registry hive) byte parser: enough for the byte-level
//! structural invariants the harness checks against real hive files (the
//! offreg-generated corpus under tests/corpus/synthetic). Offsets follow
//! docs/hive-format.md.
//!
//! This is deliberately NOT a full logical parser. It reads the base block and
//! walks the hbin/cell structure (invariants 1 to 6, 9, 10). The logical graph
//! (nk/vk/sk tree, subkey-list promotion, sk refcounts: invariants 7, 8, 11 to
//! 16) is out of scope here and stays reported as Skipped by the caller. When
//! libreg can emit real hive bytes the same parser backs the differential
//! roundtrip.

pub const BASE_BLOCK_LEN: usize = 4096;
pub const HBIN_HEADER_LEN: usize = 32;

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Little-endian u16 at byte offset `off`.
pub fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

pub struct BaseBlock {
    pub magic_ok: bool,
    pub primary_seq: u32,
    pub secondary_seq: u32,
    // Parsed for a faithful base block; consumed by the logical-tree invariants
    // (inv7 walks from root_cell_offset) and version reporting, which are not
    // implemented for the static byte check yet.
    #[allow(dead_code)]
    pub minor_version: u32,
    #[allow(dead_code)]
    pub root_cell_offset: u32,
    pub hive_bins_data_size: u32,
    pub stored_checksum: u32,
    pub computed_checksum: u32,
}

pub fn parse_base_block(b: &[u8]) -> Option<BaseBlock> {
    if b.len() < BASE_BLOCK_LEN {
        return None;
    }
    Some(BaseBlock {
        magic_ok: &b[0..4] == b"regf",
        primary_seq: u32_at(b, 4),
        secondary_seq: u32_at(b, 8),
        minor_version: u32_at(b, 24),
        root_cell_offset: u32_at(b, 36),
        hive_bins_data_size: u32_at(b, 40),
        stored_checksum: u32_at(b, 508),
        computed_checksum: compute_checksum(b),
    })
}

/// Base-block checksum: XOR of the first 127 little-endian u32 (bytes 0 through
/// 507), with offreg's two quirks (0 stored as 1, 0xFFFFFFFF stored as
/// 0xFFFFFFFE). See docs/hive-format.md and CONTRACTS invariant 3.
pub fn compute_checksum(b: &[u8]) -> u32 {
    let mut x = 0u32;
    for i in 0..127 {
        x ^= u32_at(b, i * 4);
    }
    match x {
        0x0000_0000 => 0x0000_0001,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        v => v,
    }
}

/// One cell located by the walk. `content_start` is a FILE offset (so callers
/// can index the hive bytes directly); `content` spans `abs(size) - 4` bytes,
/// the first two of which are the cell's 2-byte type signature for an allocated
/// cell with a typed payload (nk, vk, sk, lf, lh, li, ri, db).
pub struct Cell {
    pub content_start: usize,
    pub content_len: usize,
    pub allocated: bool,
}

/// Findings from walking the whole hbin/cell structure. Each vec holds the
/// human-readable violations for one invariant; empty means the invariant held.
#[derive(Default)]
pub struct Walk {
    /// inv5: hbin magic and 4096 alignment.
    pub hbin_violations: Vec<String>,
    /// inv6: a cell whose size is zero or not a multiple of 8.
    pub cell_size_violations: Vec<String>,
    /// inv9: per-hbin sum of cell sizes != hbin size - 32.
    pub cell_sum_violations: Vec<String>,
    /// inv10: a cell that crosses an hbin boundary.
    pub boundary_violations: Vec<String>,
    /// Total bytes the walk consumed: the actual total of all hbins (inv4).
    pub total_hbin_bytes: usize,
    /// Every cell the walk located, allocated and free (inv11, inv16 read the
    /// allocated, signed ones).
    pub cells: Vec<Cell>,
}

/// Walk the hbin chain after the base block, collecting per-invariant
/// violations. The walk stops at the first structurally fatal error in an hbin
/// (bad magic, bad size, overrun) because nothing after it can be trusted; the
/// violation is recorded so the caller fails the relevant invariant.
pub fn walk_hbins(bytes: &[u8]) -> Walk {
    let mut w = Walk::default();
    if bytes.len() <= BASE_BLOCK_LEN {
        return w;
    }
    let bins = &bytes[BASE_BLOCK_LEN..];
    let mut pos = 0usize;
    while pos + HBIN_HEADER_LEN <= bins.len() {
        let magic_ok = &bins[pos..pos + 4] == b"hbin";
        let size = u32_at(bins, pos + 8) as usize;
        if !magic_ok {
            w.hbin_violations.push(format!("hbin at +{pos:#x}: signature is not 'hbin'"));
            break;
        }
        if size == 0 || size % 4096 != 0 {
            w.hbin_violations
                .push(format!("hbin at +{pos:#x}: size {size} is not a positive multiple of 4096"));
            break;
        }
        if pos + size > bins.len() {
            w.hbin_violations
                .push(format!("hbin at +{pos:#x}: size {size} overruns the bins area"));
            break;
        }
        let hbin_end = pos + size;
        let mut cpos = pos + HBIN_HEADER_LEN;
        let mut sum = 0usize;
        while cpos < hbin_end {
            if cpos + 4 > hbin_end {
                w.boundary_violations
                    .push(format!("cell at +{cpos:#x}: 4-byte size field crosses hbin boundary"));
                break;
            }
            let raw = i32::from_le_bytes([
                bins[cpos],
                bins[cpos + 1],
                bins[cpos + 2],
                bins[cpos + 3],
            ]);
            let cell_size = raw.unsigned_abs() as usize;
            if cell_size == 0 {
                w.cell_size_violations.push(format!("cell at +{cpos:#x}: size is 0"));
                break;
            }
            if cell_size % 8 != 0 {
                w.cell_size_violations
                    .push(format!("cell at +{cpos:#x}: size {cell_size} is not a multiple of 8"));
                break;
            }
            if cpos + cell_size > hbin_end {
                w.boundary_violations
                    .push(format!("cell at +{cpos:#x}: size {cell_size} crosses hbin boundary"));
                break;
            }
            w.cells.push(Cell {
                content_start: BASE_BLOCK_LEN + cpos + 4,
                content_len: cell_size - 4,
                allocated: raw < 0,
            });
            sum += cell_size;
            cpos += cell_size;
        }
        if sum != size - HBIN_HEADER_LEN {
            w.cell_sum_violations.push(format!(
                "hbin at +{pos:#x}: cell sizes sum to {sum}, expected {} (size - 32)",
                size - HBIN_HEADER_LEN
            ));
        }
        pos += size;
        w.total_hbin_bytes = pos;
    }
    w
}
