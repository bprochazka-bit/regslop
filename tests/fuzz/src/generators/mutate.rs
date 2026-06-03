//! Structure-aware hive byte mutator.
//!
//! Hard rule 5 (CLAUDE-fuzz.md): "A pure random byte flipper produces garbage
//! that fails the base block check immediately. Use a structure-aware mutator
//! that knows about cell types, offsets, and the hbin chain."
//!
//! Offsets mirror the harness's own parser (`tests/harness/src/differ/regf.rs`)
//! so a mutation that, say, corrupts an nk name length lands on the exact field
//! the structural invariants read. `FixChecksum` recomputes the base-block
//! checksum the same way the harness does, so a mutation can stay past the
//! checksum gate and probe the logical layer instead of being rejected at the
//! door.
//!
//! Mutations are described, not applied in place: `plan` returns a `Vec<Mutation>`
//! and `apply_all` folds them over a pristine copy. That makes the set trivially
//! reversible (re-apply a subset to the original), which is what the hive_fuzz
//! minimizer uses to find the smallest set of mutations that still triggers a
//! bug.

use crate::rng::Rng;

pub const BASE_BLOCK_LEN: usize = 4096;
pub const HBIN_HEADER_LEN: usize = 32;
const CHECKSUM_OFF: usize = 508;

/// One structural mutation, as a description applied later by `apply_all`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Overwrite one byte.
    SetByte { off: usize, val: u8 },
    /// XOR a byte with a mask (single bit flip when the mask is a power of two).
    XorByte { off: usize, mask: u8 },
    /// Overwrite a little-endian u16.
    SetU16 { off: usize, val: u16 },
    /// Overwrite a little-endian u32.
    SetU32 { off: usize, val: u32 },
    /// Truncate the file to `len` bytes (drops the tail).
    Truncate { len: usize },
    /// Recompute and store the base-block checksum. Place last to seal a mutated
    /// header so it survives the checksum invariant.
    FixChecksum,
}

impl Mutation {
    pub fn label(&self) -> &'static str {
        match self {
            Mutation::SetByte { .. } => "set_byte",
            Mutation::XorByte { .. } => "xor_byte",
            Mutation::SetU16 { .. } => "set_u16",
            Mutation::SetU32 { .. } => "set_u32",
            Mutation::Truncate { .. } => "truncate",
            Mutation::FixChecksum => "fix_checksum",
        }
    }
}

/// Apply a mutation set to a pristine copy of `original`, in order. Out-of-range
/// edits are skipped (never panic): a mutation set computed against one hive and
/// replayed against a shorter truncated form must degrade gracefully.
pub fn apply_all(original: &[u8], muts: &[Mutation]) -> Vec<u8> {
    let mut b = original.to_vec();
    for m in muts {
        match *m {
            Mutation::SetByte { off, val } => {
                if off < b.len() {
                    b[off] = val;
                }
            }
            Mutation::XorByte { off, mask } => {
                if off < b.len() {
                    b[off] ^= mask;
                }
            }
            Mutation::SetU16 { off, val } => {
                if off + 2 <= b.len() {
                    b[off..off + 2].copy_from_slice(&val.to_le_bytes());
                }
            }
            Mutation::SetU32 { off, val } => {
                if off + 4 <= b.len() {
                    b[off..off + 4].copy_from_slice(&val.to_le_bytes());
                }
            }
            Mutation::Truncate { len } => {
                if len < b.len() {
                    b.truncate(len);
                }
            }
            Mutation::FixChecksum => {
                if b.len() >= BASE_BLOCK_LEN {
                    let c = compute_checksum(&b);
                    b[CHECKSUM_OFF..CHECKSUM_OFF + 4].copy_from_slice(&c.to_le_bytes());
                }
            }
        }
    }
    b
}

/// Base-block checksum, matching `regf::compute_checksum` in the harness: XOR of
/// the first 127 little-endian u32, with offreg's 0 -> 1 and
/// 0xFFFFFFFF -> 0xFFFFFFFE quirks.
pub fn compute_checksum(b: &[u8]) -> u32 {
    let mut x = 0u32;
    for i in 0..127 {
        x ^= u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
    }
    match x {
        0x0000_0000 => 0x0000_0001,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        v => v,
    }
}

/// Locations the planner targets, discovered by a defensive hbin/cell walk.
struct Layout {
    /// File offset of each hbin's `size` field (`+8` into the hbin header).
    hbin_size_fields: Vec<usize>,
    /// File offset of each hbin magic.
    hbin_magics: Vec<usize>,
    /// File offset of each allocated cell's 4-byte size field.
    cell_size_fields: Vec<usize>,
    /// File offset of each nk cell's name-length u16 field (content_start + 72).
    nk_name_lens: Vec<usize>,
}

fn walk(bytes: &[u8]) -> Layout {
    let mut l = Layout {
        hbin_size_fields: Vec::new(),
        hbin_magics: Vec::new(),
        cell_size_fields: Vec::new(),
        nk_name_lens: Vec::new(),
    };
    if bytes.len() <= BASE_BLOCK_LEN {
        return l;
    }
    let bins = &bytes[BASE_BLOCK_LEN..];
    let mut pos = 0usize;
    while pos + HBIN_HEADER_LEN <= bins.len() {
        if &bins[pos..pos + 4] != b"hbin" {
            break;
        }
        l.hbin_magics.push(BASE_BLOCK_LEN + pos);
        l.hbin_size_fields.push(BASE_BLOCK_LEN + pos + 8);
        let size = u32::from_le_bytes([bins[pos + 8], bins[pos + 9], bins[pos + 10], bins[pos + 11]])
            as usize;
        if size == 0 || size % 4096 != 0 || pos + size > bins.len() {
            break;
        }
        let hbin_end = pos + size;
        let mut cpos = pos + HBIN_HEADER_LEN;
        while cpos + 4 <= hbin_end {
            let raw = i32::from_le_bytes([bins[cpos], bins[cpos + 1], bins[cpos + 2], bins[cpos + 3]]);
            let cell_size = raw.unsigned_abs() as usize;
            if cell_size == 0 || cell_size % 8 != 0 || cpos + cell_size > hbin_end {
                break;
            }
            l.cell_size_fields.push(BASE_BLOCK_LEN + cpos);
            let content_start = BASE_BLOCK_LEN + cpos + 4;
            let content_len = cell_size - 4;
            // Allocated nk cell with room for the name header.
            if raw < 0 && content_len >= 76 && &bytes[content_start..content_start + 2] == b"nk" {
                l.nk_name_lens.push(content_start + 72);
            }
            cpos += cell_size;
        }
        pos += size;
    }
    l
}

/// Build a structure-aware mutation set of `n` mutations against `original`,
/// chosen deterministically from `rng`. Each mutation targets a real structural
/// field; the catalog matches the "Hive Mutator Design" list in CLAUDE-fuzz.md.
pub fn plan(original: &[u8], rng: &mut Rng, n: usize) -> Vec<Mutation> {
    let l = walk(original);
    let mut muts = Vec::with_capacity(n + 1);
    // Whether the planner has perturbed the base-block header, in which case a
    // trailing FixChecksum lets the mutation reach past invariant 3.
    let mut touched_header = false;

    for _ in 0..n {
        match rng.below(8) {
            // 0: base block primary sequence != secondary (dirty hive). Header
            // edit, so it pairs with a checksum fix to probe recovery rather
            // than be rejected as corrupt.
            0 => {
                muts.push(Mutation::SetU32 { off: 4, val: rng.next_u64() as u32 });
                touched_header = true;
            }
            // 1: corrupt base block magic 'regf'.
            1 => {
                muts.push(Mutation::XorByte { off: rng.below(4) as usize, mask: 0xFF });
                touched_header = true;
            }
            // 2: bogus stored checksum (no fix), exercising invariant 3.
            2 => {
                muts.push(Mutation::SetU32 { off: CHECKSUM_OFF, val: rng.next_u64() as u32 });
            }
            // 3: flip a bit in an nk name length (overrun / odd-length probe).
            3 if !l.nk_name_lens.is_empty() => {
                let off = *rng.choice(&l.nk_name_lens);
                let bit = 1u8 << (rng.below(8) as u8);
                muts.push(Mutation::XorByte { off, mask: bit });
            }
            // 4: truncate an hbin to a non-4096 multiple (invariant 5).
            4 if !l.hbin_size_fields.is_empty() => {
                let off = *rng.choice(&l.hbin_size_fields);
                muts.push(Mutation::SetU32 { off, val: 4096 + 8 });
            }
            // 5: zero a cell size (invariant 6).
            5 if !l.cell_size_fields.is_empty() => {
                let off = *rng.choice(&l.cell_size_fields);
                muts.push(Mutation::SetU32 { off, val: 0 });
            }
            // 6: corrupt an hbin magic.
            6 if !l.hbin_magics.is_empty() => {
                let off = *rng.choice(&l.hbin_magics);
                muts.push(Mutation::XorByte { off, mask: 0xFF });
            }
            // 7: truncate the file mid-structure.
            _ => {
                let len = if original.len() > BASE_BLOCK_LEN {
                    BASE_BLOCK_LEN + rng.below((original.len() - BASE_BLOCK_LEN) as u64) as usize
                } else {
                    rng.below(original.len().max(1) as u64) as usize
                };
                muts.push(Mutation::Truncate { len });
            }
        }
    }

    if touched_header && rng.chance(1, 2) {
        muts.push(Mutation::FixChecksum);
    }
    muts
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal regf-shaped buffer: a 4096-byte base block with valid magic and
    /// a self-consistent checksum, plus one 4096-byte hbin holding one allocated
    /// nk cell. Enough for the walk and checksum tests.
    fn synthetic_hive() -> Vec<u8> {
        let mut b = vec![0u8; BASE_BLOCK_LEN + 4096];
        b[0..4].copy_from_slice(b"regf");
        b[4..8].copy_from_slice(&1u32.to_le_bytes()); // primary seq
        b[8..12].copy_from_slice(&1u32.to_le_bytes()); // secondary seq
        b[40..44].copy_from_slice(&4096u32.to_le_bytes()); // hive bins data size
        // hbin header at 4096.
        b[4096..4100].copy_from_slice(b"hbin");
        b[4096 + 8..4096 + 12].copy_from_slice(&4096u32.to_le_bytes()); // hbin size
        // One allocated cell filling the rest of the hbin: size = 4096 - 32.
        let cell_size = (4096 - HBIN_HEADER_LEN) as i32;
        let cpos = 4096 + HBIN_HEADER_LEN;
        b[cpos..cpos + 4].copy_from_slice(&(-cell_size).to_le_bytes());
        b[cpos + 4..cpos + 6].copy_from_slice(b"nk"); // signature
        // name length at content_start + 72 = cpos+4+72.
        b[cpos + 4 + 72..cpos + 4 + 74].copy_from_slice(&4u16.to_le_bytes());
        // seal the checksum
        let c = compute_checksum(&b);
        b[CHECKSUM_OFF..CHECKSUM_OFF + 4].copy_from_slice(&c.to_le_bytes());
        b
    }

    #[test]
    fn checksum_matches_after_fix() {
        let mut b = synthetic_hive();
        // Perturb a header dword, then FixChecksum and confirm self-consistency.
        b[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let fixed = apply_all(&b, &[Mutation::FixChecksum]);
        let stored = u32::from_le_bytes([
            fixed[CHECKSUM_OFF], fixed[CHECKSUM_OFF + 1], fixed[CHECKSUM_OFF + 2], fixed[CHECKSUM_OFF + 3],
        ]);
        assert_eq!(stored, compute_checksum(&fixed));
    }

    #[test]
    fn walk_finds_hbin_and_nk() {
        let b = synthetic_hive();
        let l = walk(&b);
        assert_eq!(l.hbin_magics, vec![4096]);
        assert_eq!(l.hbin_size_fields, vec![4096 + 8]);
        assert_eq!(l.cell_size_fields, vec![4096 + HBIN_HEADER_LEN]);
        assert_eq!(l.nk_name_lens, vec![4096 + HBIN_HEADER_LEN + 4 + 72]);
    }

    #[test]
    fn apply_all_is_deterministic_and_pure() {
        let b = synthetic_hive();
        let mut r1 = Rng::new(0x1234);
        let mut r2 = Rng::new(0x1234);
        let p1 = plan(&b, &mut r1, 12);
        let p2 = plan(&b, &mut r2, 12);
        assert_eq!(p1, p2);
        let m1 = apply_all(&b, &p1);
        let m2 = apply_all(&b, &p2);
        assert_eq!(m1, m2);
        // Purity: original untouched.
        assert_eq!(b, synthetic_hive());
    }

    #[test]
    fn out_of_range_mutations_do_not_panic() {
        let b = synthetic_hive();
        let muts = vec![
            Mutation::SetByte { off: 1 << 30, val: 1 },
            Mutation::SetU32 { off: b.len() - 1, val: 0 }, // straddles end
            Mutation::Truncate { len: 10 },
            Mutation::FixChecksum, // now too short for a base block
            Mutation::XorByte { off: 5, mask: 0xFF },
        ];
        let out = apply_all(&b, &muts);
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn planner_targets_real_fields() {
        let b = synthetic_hive();
        let mut r = Rng::new(7);
        let plan = plan(&b, &mut r, 200);
        // Every non-truncate, non-checksum edit must land inside the buffer.
        for m in &plan {
            match *m {
                Mutation::SetU32 { off, .. } => assert!(off + 4 <= b.len()),
                Mutation::XorByte { off, .. } | Mutation::SetByte { off, .. } => {
                    assert!(off < b.len())
                }
                Mutation::SetU16 { off, .. } => assert!(off + 2 <= b.len()),
                _ => {}
            }
        }
    }
}
