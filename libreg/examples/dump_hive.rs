//! Dump the structure of a hive file using libreg's own parsers.
//!
//! Usage: `cargo run --example dump_hive -- path/to/hive.hiv`
//!
//! Prints the base block summary, a cell walk, and the key tree (root nk,
//! its security cell, its subkey list, and each immediate child). Useful for
//! eyeballing offreg reference hives against what libreg produces.

use libreg::format::base_block::{BaseBlock, BASE_BLOCK_SIZE};
use libreg::format::cell::Cell;
use libreg::format::hbin::walk;
use libreg::format::nk::{KeyNode, KEY_COMP_NAME};
use libreg::format::security_descriptor::SecurityDescriptor;
use libreg::format::sk::SecurityCell;

fn decode_name(name: &[u8], comp: bool) -> String {
    if comp {
        name.iter().map(|&b| b as char).collect()
    } else {
        let units: Vec<u16> = name
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

fn read_payload(bins: &[u8], off: u32) -> &[u8] {
    Cell::parse_at(bins, off as usize).expect("frame cell").data
}

fn dump_nk(bins: &[u8], off: u32, label: &str) {
    let nk = KeyNode::parse(read_payload(bins, off)).expect("nk");
    let comp = nk.flags & KEY_COMP_NAME != 0;
    println!(
        "{label} @ {off:#06x}: name={:?} flags={:#06x} comp_name={} parent={:#x} \
         subkeys={} (list @ {:#x}) values={} (list @ {:#x}) sk @ {:#x}",
        decode_name(&nk.name, comp),
        nk.flags,
        comp,
        nk.parent,
        nk.subkey_count,
        nk.subkeys_list_offset,
        nk.value_count,
        nk.values_list_offset,
        nk.security_offset,
    );
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_hive <path>");
    let file = std::fs::read(&path).expect("read file");
    println!("== {path} ({} bytes) ==", file.len());

    let bb = BaseBlock::parse(&file).expect("base block");
    println!(
        "base block: v{}.{} root @ {:#x} hbins_size={:#x} clean={} checksum_valid={}",
        bb.major_version,
        bb.minor_version,
        bb.root_cell_offset,
        bb.hbins_size,
        bb.is_clean(),
        bb.checksum_valid(),
    );

    let bins = &file[BASE_BLOCK_SIZE..BASE_BLOCK_SIZE + bb.hbins_size as usize];
    match walk(bins) {
        Ok(s) => println!(
            "walk: {} hbins, {} allocated, {} free cells",
            s.hbin_count, s.allocated_cells, s.free_cells
        ),
        Err(e) => println!("walk error: {e}"),
    }

    let root_off = bb.root_cell_offset;
    dump_nk(bins, root_off, "root");

    let root = KeyNode::parse(read_payload(bins, root_off)).expect("root nk");

    // Security cell of the root.
    let sk = SecurityCell::parse(read_payload(bins, root.security_offset)).expect("sk");
    println!(
        "root sk @ {:#x}: refcount={} flink={:#x} blink={:#x} desc_len={}",
        root.security_offset,
        sk.refcount,
        sk.flink,
        sk.blink,
        sk.descriptor.len(),
    );
    println!("  descriptor bytes: {}", hex(&sk.descriptor));
    match SecurityDescriptor::parse(&sk.descriptor) {
        Ok(sd) => println!(
            "  parsed SD: control={:#06x} owner={:?} group={:?} dacl_aces={:?}",
            sd.control,
            sd.owner.map(|s| s.sub_authorities),
            sd.group.map(|s| s.sub_authorities),
            sd.dacl.map(|a| a.aces.len()),
        ),
        Err(e) => println!("  SD parse error: {e}"),
    }

    // Subkey list of the root: report the cell signature and, for lf/lh,
    // each child.
    if root.subkeys_list_offset != 0xffff_ffff && root.subkey_count > 0 {
        let payload = read_payload(bins, root.subkeys_list_offset);
        let sig = String::from_utf8_lossy(&payload[0..2]).into_owned();
        let count = u16::from_le_bytes([payload[2], payload[3]]);
        println!(
            "subkey list @ {:#x}: sig={:?} count={}",
            root.subkeys_list_offset, sig, count
        );
        if sig == "lh" || sig == "lf" {
            // Each element is 8 bytes: a u32 offset then a 4-byte hint/hash.
            let n = (count as usize).min(8);
            for i in 0..n {
                let base = 4 + i * 8;
                let child_off = u32::from_le_bytes([
                    payload[base],
                    payload[base + 1],
                    payload[base + 2],
                    payload[base + 3],
                ]);
                let disc = &payload[base + 4..base + 8];
                println!("  [{i}] child @ {child_off:#x} hint/hash={}", hex(disc));
                dump_nk(bins, child_off, "    child");
            }
            if (count as usize) > n {
                println!("  ... {} more", count as usize - n);
            }
        } else if sig == "ri" {
            let n = (count as usize).min(8);
            for i in 0..n {
                let base = 4 + i * 4;
                let leaf_off = u32::from_le_bytes([
                    payload[base],
                    payload[base + 1],
                    payload[base + 2],
                    payload[base + 3],
                ]);
                let lp = read_payload(bins, leaf_off);
                let lsig = String::from_utf8_lossy(&lp[0..2]).into_owned();
                let lcount = u16::from_le_bytes([lp[2], lp[3]]);
                println!("  ri[{i}] leaf @ {leaf_off:#x} sig={lsig:?} count={lcount}");
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
