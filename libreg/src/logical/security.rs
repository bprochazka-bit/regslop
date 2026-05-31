//! Security-cell (sk) ring management for the logical layer.
//!
//! sk cells form a doubly linked circular list (invariant 13). A freshly
//! created key gets its own sk carrying the ratified default descriptor;
//! deduplicating identical descriptors into one shared sk with a summed
//! refcount is step 10 and not done here, so every created key adds one sk
//! with refcount 1. Refcounts stay exact (invariant 14): each sk is pointed
//! at by exactly the one key that created it.

use crate::alloc::HiveImage;
use crate::format::sk::{SecurityCell, SK_HEADER_SIZE};
use crate::format::FormatError;

fn read_sk(image: &HiveImage, off: u32) -> Result<SecurityCell, FormatError> {
    SecurityCell::parse(image.content(off))
}

fn write_sk(image: &mut HiveImage, off: u32, sk: &SecurityCell) {
    let payload = sk.to_payload();
    image.content_mut(off)[..payload.len()].copy_from_slice(&payload);
}

/// Allocate a new sk cell carrying `descriptor` and splice it into the ring
/// immediately after `anchor_off`, returning the new cell's offset. The new
/// cell starts with refcount 1.
pub fn add_sk(
    image: &mut HiveImage,
    anchor_off: u32,
    descriptor: Vec<u8>,
) -> Result<u32, FormatError> {
    let new_off = image.alloc(SK_HEADER_SIZE + descriptor.len());

    let anchor = read_sk(image, anchor_off)?;
    let next_off = anchor.flink;

    // Insert N between the anchor P and its current successor Q (= P.flink).
    let new_sk = SecurityCell {
        flink: next_off,
        blink: anchor_off,
        refcount: 1,
        descriptor,
    };
    write_sk(image, new_off, &new_sk);

    if next_off == anchor_off {
        // Lone ring: the anchor is both neighbours of the new cell, so it
        // takes the new offset for both its links in a single write.
        let mut p = anchor;
        p.flink = new_off;
        p.blink = new_off;
        write_sk(image, anchor_off, &p);
    } else {
        let mut p = anchor;
        p.flink = new_off;
        write_sk(image, anchor_off, &p);

        let mut q = read_sk(image, next_off)?;
        q.blink = new_off;
        write_sk(image, next_off, &q);
    }

    Ok(new_off)
}
