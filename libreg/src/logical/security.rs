//! Security-cell (sk) ring management for the logical layer.
//!
//! sk cells form a doubly linked circular list (invariant 13) and are shared
//! by every key with an identical descriptor, with the reference count equal
//! to the number of referring keys (invariant 14). offreg deduplicates this
//! way: the offreg reference hives (tests/corpus/synthetic) show a root and
//! all its created children pointing at a single sk whose refcount rises with
//! each key (ref_multi.hiv: 6 children, refcount 7). [`ensure_sk`] matches
//! that: it reuses an existing descriptor-equal sk and only allocates a new
//! cell for a genuinely new descriptor.

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

/// Return the offset of an sk cell carrying `descriptor`, reusing an existing
/// descriptor-equal cell in the ring (bumping its refcount) or allocating and
/// linking a new one otherwise. `ring_member` is any cell already in the ring
/// (the root's sk is the natural choice).
pub fn ensure_sk(
    image: &mut HiveImage,
    ring_member: u32,
    descriptor: Vec<u8>,
) -> Result<u32, FormatError> {
    let mut cur = ring_member;
    loop {
        let sk = read_sk(image, cur)?;
        if sk.descriptor == descriptor {
            let mut bumped = sk;
            bumped.refcount += 1;
            write_sk(image, cur, &bumped);
            return Ok(cur);
        }
        cur = sk.flink;
        if cur == ring_member {
            break;
        }
    }
    add_sk(image, ring_member, descriptor)
}

/// Drop one reference to the sk at `sk_off`. While other keys still reference
/// it, this just decrements the refcount; when the count would reach 0 the
/// cell is unlinked from its ring and freed. The root's shared sk never
/// reaches 0 (the root always references it), so deleting created keys only
/// decrements it.
pub(super) fn release_sk(image: &mut HiveImage, sk_off: u32) -> Result<(), FormatError> {
    let mut sk = read_sk(image, sk_off)?;
    if sk.refcount > 1 {
        sk.refcount -= 1;
        write_sk(image, sk_off, &sk);
        return Ok(());
    }

    // Last reference: unlink from the ring (when it has other members) and
    // free the cell.
    let (prev, next) = (sk.blink, sk.flink);
    if prev != sk_off {
        let mut p = read_sk(image, prev)?;
        p.flink = next;
        write_sk(image, prev, &p);
        let mut n = read_sk(image, next)?;
        n.blink = prev;
        write_sk(image, next, &n);
    }
    image.free(sk_off);
    Ok(())
}

/// Allocate a new sk cell carrying `descriptor` and splice it into the ring
/// immediately after `anchor_off`, returning its offset. Refcount starts at 1.
fn add_sk(image: &mut HiveImage, anchor_off: u32, descriptor: Vec<u8>) -> Result<u32, FormatError> {
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
