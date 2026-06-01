//! End-to-end crash-recovery demo: the exact flow the Linux agent's
//! `/test/crash_save` + recovery-aware `hive_load` will implement, with real
//! file I/O. This is the prototype the ADR 0004 / issue #61 hook is built
//! against; copy the two helpers below into the agent.
//!
//! Usage: `cargo run --example crash_recovery [-- /path/to/test.hiv]`
//! (defaults to a temp path). Runs the issue-#61 recovery sequence for the
//! core crash point and prints the recovered state, then the clean-commit case.

use libreg::log::{crash_save_plan, recover, CrashPoint, Slot};
use libreg::logical::Hive;
use std::fs;

const REG_DWORD: u32 = 4;

/// The on-disk path for a save slot. `Slot::Primary` is the hive path P; the
/// logs sit beside it. This is the whole mapping the agent needs.
fn slot_path(primary: &str, slot: Slot) -> String {
    match slot {
        Slot::Primary => primary.to_string(),
        Slot::Log1 => format!("{primary}.LOG1"),
        Slot::Log2 => format!("{primary}.LOG2"),
    }
}

/// Execute a `crash_save_plan` against disk: write each `(slot, bytes)` to its
/// file, in order. A crash point stops the plan early, so some files are left
/// at the previous generation. This is the body of `/test/crash_save`.
fn write_plan(primary: &str, plan: &[(Slot, Vec<u8>)]) {
    for (slot, bytes) in plan {
        fs::write(slot_path(primary, *slot), bytes).expect("write slot");
    }
}

/// Load a hive with recovery: read the primary and any logs that exist, and let
/// `recover` select the newest valid generation. This is `hive_load` once
/// recovery is wired.
fn load_recovered(primary: &str) -> Hive {
    let primary_bytes = fs::read(primary).ok();
    let log1 = fs::read(slot_path(primary, Slot::Log1)).ok();
    let log2 = fs::read(slot_path(primary, Slot::Log2)).ok();
    recover(primary_bytes.as_deref(), log1.as_deref(), log2.as_deref()).expect("recover")
}

fn cleanup(primary: &str) {
    for slot in [Slot::Primary, Slot::Log1, Slot::Log2] {
        let _ = fs::remove_file(slot_path(primary, slot));
    }
}

/// Run the issue-#61 recovery sequence on a single handle and return the
/// recovered hive: baseline saved, mutation applied, then `crash_save` at
/// `point` instead of a normal save, then a fresh load.
fn recovery_run(primary: &str, point: CrashPoint) -> Hive {
    cleanup(primary);

    // 1. Create, build a baseline, and hive_save (a completed save commits the
    //    primary and advances the generation).
    let mut hive = Hive::new_empty();
    hive.create_key("Software\\Baseline").unwrap();
    write_plan(
        primary,
        &crash_save_plan(&mut hive, CrashPoint::AfterPrimary),
    );
    println!("  baseline committed at generation {}", hive.generation());

    // 2. Mutation M, on the SAME handle.
    hive.create_key("Software\\Added").unwrap();
    hive.set_value("Software\\Added", "Count", REG_DWORD, &7u32.to_le_bytes())
        .unwrap();

    // 3. crash_save at `point` instead of /hive/save.
    write_plan(primary, &crash_save_plan(&mut hive, point));
    println!("  crashed at {point:?} (journaled the new generation)");

    // 4. Discard the in-memory handle (as /hive/close would).
    drop(hive);

    // 5. Fresh load -> recovery.
    load_recovered(primary)
}

fn report(label: &str, hive: &Hive) {
    println!(
        "  recovered: Software subkeys = {:?}, generation {}",
        hive.subkeys("Software").unwrap(),
        hive.generation()
    );
    println!(
        "  recovered: Software\\Added\\Count = {:?}",
        hive.get_value("Software\\Added", "Count").unwrap()
    );
    println!("  => {label}: recovered baseline + mutation\n");
}

fn main() {
    let primary = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/libreg_crash_recovery_demo.hiv".to_string());
    println!("primary hive: {primary}\n");

    println!("[after_log_before_primary] the core recovery case:");
    let hive = recovery_run(&primary, CrashPoint::AfterLogBeforePrimary);
    report("after_log_before_primary", &hive);

    println!("[after_primary] the clean-commit control (no recovery needed):");
    let hive = recovery_run(&primary, CrashPoint::AfterPrimary);
    report("after_primary", &hive);

    cleanup(&primary);
    println!("done (files cleaned up).");
}
