//! Cells: the allocation unit inside a hive bin.
//!
//! A cell begins with a signed 32-bit size:
//!
//! - negative size: the cell is **allocated**; its length is `-size`.
//! - positive size: the cell is **free**; its length is `size`.
//!
//! The length always includes the 4-byte size field itself and is a
//! multiple of 8. The bytes after the size field are the cell payload
//! (an nk/vk/sk/lf/... record for an allocated cell, stale bytes for a
//! free one). This module does not interpret the payload; it only frames
//! cells so the allocator (Layer 1) and record parsers can work above it.

use super::{read_i32, FormatError};

/// Cells are aligned to this many bytes.
pub const CELL_ALIGN: u32 = 8;

/// Size of the leading signed-size field.
pub const CELL_SIZE_FIELD: usize = 4;

/// A framed cell: its allocation state, total size, and payload bytes.
///
/// Borrows the underlying buffer; constructing one performs no allocation
/// (Hard Rule 2).
#[derive(Debug, Clone, Copy)]
pub struct Cell<'a> {
    /// True when the cell is allocated (its on-disk size was negative).
    pub allocated: bool,
    /// Total cell size in bytes, including the 4-byte size field. Always
    /// a positive multiple of 8.
    pub size: u32,
    /// Payload bytes following the size field (`size - 4` bytes long).
    pub data: &'a [u8],
}

impl<'a> Cell<'a> {
    /// Frame the cell that begins at `offset` within `buf`.
    ///
    /// `offset` is relative to the start of `buf`, which callers treat as
    /// the hive bins data; the error offsets use the same basis so they
    /// can be reported against the file directly.
    ///
    /// Returns an error if the size field is zero or if the cell would
    /// extend past the end of `buf`.
    pub fn parse_at(buf: &'a [u8], offset: usize) -> Result<Cell<'a>, FormatError> {
        if offset + CELL_SIZE_FIELD > buf.len() {
            return Err(FormatError::OutOfBounds {
                structure: "cell size",
                offset,
                need: CELL_SIZE_FIELD,
                available: buf.len().saturating_sub(offset),
            });
        }

        let raw = read_i32(buf, offset);
        if raw == 0 {
            return Err(FormatError::ZeroCellSize { offset });
        }

        let allocated = raw < 0;
        // `raw == i32::MIN` would overflow unary negation; widen to i64 to
        // take the magnitude safely, then range-check into u32.
        let magnitude = (raw as i64).unsigned_abs();
        if magnitude > u32::MAX as u64 {
            return Err(FormatError::OutOfBounds {
                structure: "cell",
                offset,
                need: magnitude as usize,
                available: buf.len().saturating_sub(offset),
            });
        }
        let size = magnitude as u32;

        let end = offset
            .checked_add(size as usize)
            .ok_or(FormatError::OutOfBounds {
                structure: "cell",
                offset,
                need: size as usize,
                available: buf.len().saturating_sub(offset),
            })?;
        if end > buf.len() {
            return Err(FormatError::OutOfBounds {
                structure: "cell",
                offset,
                need: size as usize,
                available: buf.len() - offset,
            });
        }

        Ok(Cell {
            allocated,
            size,
            data: &buf[offset + CELL_SIZE_FIELD..end],
        })
    }

    /// True when the cell size is a multiple of [`CELL_ALIGN`]. A
    /// well-formed hive only contains 8-aligned cells; the low-level
    /// framer does not reject misalignment so that callers can decide
    /// whether to treat it as corruption or a warning.
    pub fn is_aligned(&self) -> bool {
        self.size.is_multiple_of(CELL_ALIGN)
    }
}

/// Round `n` up to the next multiple of [`CELL_ALIGN`].
pub fn cell_size_for(payload_len: usize) -> usize {
    let raw = CELL_SIZE_FIELD + payload_len;
    raw.next_multiple_of(CELL_ALIGN as usize)
}

/// Encode a cell: a signed size field followed by `payload`, zero-padded
/// up to the next 8-byte boundary.
///
/// `allocated` selects the sign of the size field (negative = allocated).
/// This allocates a `Vec`; it is used on the hive-creation path, not in
/// the hot allocator paths that Hard Rule 2 governs.
pub fn encode_cell(payload: &[u8], allocated: bool) -> Vec<u8> {
    let size = cell_size_for(payload.len());
    let mut buf = vec![0u8; size];
    let signed: i32 = if allocated {
        -(size as i32)
    } else {
        size as i32
    };
    buf[0..CELL_SIZE_FIELD].copy_from_slice(&signed.to_le_bytes());
    buf[CELL_SIZE_FIELD..CELL_SIZE_FIELD + payload.len()].copy_from_slice(payload);
    buf
}
