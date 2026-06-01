//! On-disk structure inspection: the hive format that Windows regedit hides.
//!
//! This reads a hive file and reports its base block fields, cell statistics,
//! and a cell map (offset, size, allocated/free, and the 2-letter signature of
//! known cell types: nk, vk, sk, lf, lh, li, ri, db). It is built entirely on
//! libreg's public `format` layer, so it sees the real bytes, including hives
//! that offreg wrote. This powers the regedit structure inspector, a view the
//! Windows registry editor does not offer.

use crate::error::{CliError, CliResult};
use libreg::format::base_block::{BaseBlock, BASE_BLOCK_SIZE};
use libreg::format::hbin::{HiveBins, HBIN_HEADER_SIZE};
use std::path::Path;

/// Base block facts.
#[derive(Debug, Clone)]
pub struct BaseInfo {
    pub magic_ok: bool,
    pub primary_seq: u32,
    pub secondary_seq: u32,
    pub clean: bool,
    pub major_version: u32,
    pub minor_version: u32,
    pub root_offset: u32,
    pub hbins_size: u32,
    pub checksum_valid: bool,
    pub file_size: u64,
}

/// Aggregate cell statistics across all bins.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub hbins: usize,
    pub allocated: usize,
    pub free: usize,
    pub total_cell_bytes: u64,
}

/// One cell in the cell map.
#[derive(Debug, Clone)]
pub struct CellInfo {
    /// Offset within the hive bins data (the value on-disk links use).
    pub offset: usize,
    pub size: u32,
    pub allocated: bool,
    /// 2-letter signature for a recognized allocated cell, else `None`.
    pub signature: Option<String>,
}

/// The full inspection result.
#[derive(Debug, Clone)]
pub struct HiveStructure {
    pub base: BaseInfo,
    pub stats: Stats,
    pub cells: Vec<CellInfo>,
    /// True when `cells` was capped (more cells exist than were collected).
    pub cells_truncated: bool,
    /// Any walk error encountered (the cell map stops at the first one).
    pub walk_error: Option<String>,
}

/// Cap on the number of cells returned, to bound the response size.
const CELL_CAP: usize = 4096;

/// Inspect the hive file at `path`.
pub fn inspect(path: &Path) -> CliResult<HiveStructure> {
    let file = std::fs::read(path)
        .map_err(|e| CliError::Io(format!("cannot read hive {}: {e}", path.display())))?;
    let bb = BaseBlock::parse(&file).map_err(|e| CliError::Hive(format!("bad base block: {e}")))?;

    let base = BaseInfo {
        magic_ok: true, // BaseBlock::parse already verified the regf magic.
        primary_seq: bb.primary_seq,
        secondary_seq: bb.secondary_seq,
        clean: bb.is_clean(),
        major_version: bb.major_version,
        minor_version: bb.minor_version,
        root_offset: bb.root_cell_offset,
        hbins_size: bb.hbins_size,
        checksum_valid: bb.checksum_valid(),
        file_size: file.len() as u64,
    };

    let end = (BASE_BLOCK_SIZE + bb.hbins_size as usize).min(file.len());
    let bins = &file[BASE_BLOCK_SIZE.min(file.len())..end];

    let mut stats = Stats::default();
    let mut cells = Vec::new();
    let mut truncated = false;
    let mut walk_error = None;

    'outer: for hbin in HiveBins::new(bins).hbins() {
        let hbin = match hbin {
            Ok(h) => h,
            Err(e) => {
                walk_error = Some(e.to_string());
                break;
            }
        };
        stats.hbins += 1;
        let mut pos = hbin.declared_offset as usize + HBIN_HEADER_SIZE;
        for cell in hbin.cells() {
            let cell = match cell {
                Ok(c) => c,
                Err(e) => {
                    walk_error = Some(e.to_string());
                    break 'outer;
                }
            };
            stats.total_cell_bytes += cell.size as u64;
            if cell.allocated {
                stats.allocated += 1;
            } else {
                stats.free += 1;
            }
            if cells.len() < CELL_CAP {
                cells.push(CellInfo {
                    offset: pos,
                    size: cell.size,
                    allocated: cell.allocated,
                    signature: signature_of(cell.allocated, cell.data),
                });
            } else {
                truncated = true;
            }
            pos += cell.size as usize;
        }
    }

    Ok(HiveStructure {
        base,
        stats,
        cells,
        cells_truncated: truncated,
        walk_error,
    })
}

/// The 2-letter signature of a recognized allocated cell, if its payload starts
/// with one of the known lowercase cell tags.
fn signature_of(allocated: bool, data: &[u8]) -> Option<String> {
    if !allocated || data.len() < 2 {
        return None;
    }
    let sig = [data[0], data[1]];
    const KNOWN: &[&[u8; 2]] = &[b"nk", b"vk", b"sk", b"lf", b"lh", b"li", b"ri", b"db"];
    if KNOWN.contains(&&sig) {
        Some(String::from_utf8_lossy(&sig).into_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    #[test]
    fn inspects_a_built_hive() {
        let dir = std::env::temp_dir().join(format!("libreg_struct_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.hiv");
        let mut s = Session::create(&path);
        s.hive_mut().create_key("Software\\App").unwrap();
        s.hive_mut()
            .set_value("Software\\App", "V", 1, &crate::value::build_sz("hi"))
            .unwrap();
        s.save().unwrap();

        let st = inspect(&path).unwrap();
        assert!(st.base.magic_ok && st.base.checksum_valid && st.base.clean);
        assert_eq!(st.base.major_version, 1);
        assert!(st.stats.hbins >= 1);
        assert!(st.stats.allocated >= 3, "root nk, sk, and created cells");
        // The root nk and at least one more nk are present in the cell map.
        let nk_count = st.cells.iter().filter(|c| c.signature.as_deref() == Some("nk")).count();
        assert!(nk_count >= 2, "root + Software + App nks, got {nk_count}");
        assert!(st.cells.iter().any(|c| c.signature.as_deref() == Some("sk")), "a security cell");
        assert!(st.walk_error.is_none(), "clean walk: {:?}", st.walk_error);

        std::fs::remove_dir_all(&dir).ok();
    }
}
