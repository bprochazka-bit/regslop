//! Layer 3: dual transaction logs and crash recovery.
//!
//! Recovery is a libreg-internal property, not a differential one: offreg
//! writes no transaction logs (ADR 0004), so libreg owns this format. The
//! scheme here is the simplest one that satisfies the recovery contract in
//! issue #61:
//!
//! - Each save is a *generation*. A generation is a complete, self-consistent
//!   hive snapshot ([`Hive::snapshot`]) stamped with a sequence number, valid
//!   checksum and all. The committed primary and the journal log of a save are
//!   the same snapshot bytes; the log is just stored at a `.LOG` path.
//! - A save journals the new generation to whichever log slot holds the older
//!   one (the slots alternate), then commits the primary. A crash leaves the
//!   journal on disk but the primary uncommitted.
//! - On load, [`recover`] picks the highest valid generation among the primary
//!   and the two logs. A partially written log fails its checksum and is
//!   ignored, so a clean (log, primary) pair always survives (the reason for
//!   two alternating logs, ADR 0004 part A).
//!
//! This is a full-snapshot journal. Real Windows journals only the dirty
//! pages; a delta format is a future optimization that does not change the
//! recovery contract. Because the log carries the whole generation, the two
//! pre-primary crash points ("after_first_log" and "after_log_before_primary")
//! recover identically here; the distinction matters only to a dirty-page
//! scheme. See the prototype notes on issue #61.

use crate::format::base_block::BaseBlock;
use crate::logical::{Hive, LogicalError};

/// One of the on-disk files a recoverable save touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// The primary hive file at path `P`.
    Primary,
    /// The first transaction log, `P.LOG1`.
    Log1,
    /// The second transaction log, `P.LOG2`.
    Log2,
}

/// Where a save is interrupted, mirroring ADR 0004 part B / issue #61.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    /// Only the older-generation log is written; the primary is not committed.
    AfterFirstLog,
    /// The journal is fully written but the primary is not committed.
    AfterLogBeforePrimary,
    /// The save completes: journal written and the primary committed.
    AfterPrimary,
}

/// The log slot a generation journals to. Generations alternate slots so that
/// after any save one log holds the new generation and the other holds the
/// previous one (so a torn write never loses both).
pub fn log_slot_for(generation: u32) -> Slot {
    if generation % 2 == 1 {
        Slot::Log1
    } else {
        Slot::Log2
    }
}

/// The ordered disk writes a recoverable save performs, truncated at `point`.
/// Each entry is `(slot, bytes)`; a caller (the agent's `/test/crash_save`, or
/// a test) executes them in order against the hive's files. A normal save is
/// `crash_save_plan(hive, AfterPrimary)`.
///
/// A completed save ([`CrashPoint::AfterPrimary`]) advances `hive`'s committed
/// generation, so a subsequent save on the same in-memory handle produces a
/// strictly newer generation (the harness keeps the same handle across the
/// baseline `hive_save` and the `crash_save`, issue #61). The pre-primary
/// points do NOT advance it: the save did not commit, and the handle is
/// discarded after a simulated crash anyway.
pub fn crash_save_plan(hive: &mut Hive, point: CrashPoint) -> Vec<(Slot, Vec<u8>)> {
    let new_generation = hive.generation() + 1;
    let snapshot = hive.snapshot(new_generation);
    let slot = log_slot_for(new_generation);

    // Step 1: journal the new generation to the alternating log slot.
    let mut plan = vec![(slot, snapshot.clone())];

    // Step 2: commit the primary. Only AfterPrimary reaches it; the two
    // pre-primary points stop after the journal.
    if point == CrashPoint::AfterPrimary {
        plan.push((Slot::Primary, snapshot));
        hive.set_generation(new_generation);
    }
    plan
}

/// Recover the most-recently-committed hive from a primary and its logs. Each
/// argument is the bytes of a candidate file (`None` if that file is absent).
/// Returns the [`Hive`] for the highest valid generation; a candidate with a
/// bad base block or checksum is ignored.
pub fn recover(
    primary: Option<&[u8]>,
    log1: Option<&[u8]>,
    log2: Option<&[u8]>,
) -> Result<Hive, LogicalError> {
    let mut best: Option<(u32, &[u8])> = None;
    for candidate in [primary, log1, log2].into_iter().flatten() {
        let Ok(bb) = BaseBlock::parse(candidate) else {
            continue;
        };
        if !bb.checksum_valid() {
            continue;
        }
        // A self-consistent snapshot has primary == secondary; use the
        // committed (secondary) sequence as its generation.
        let generation = bb.secondary_seq;
        if best.is_none_or(|(g, _)| generation > g) {
            best = Some((generation, candidate));
        }
    }

    match best {
        Some((_, bytes)) => Hive::from_file_bytes(bytes),
        None => Err(LogicalError::Unsupported(
            "no recoverable generation: every candidate file was invalid",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny in-memory stand-in for the three on-disk files, so a test can
    /// execute a crash_save plan and then recover exactly as the harness will.
    #[derive(Default)]
    struct Disk {
        primary: Option<Vec<u8>>,
        log1: Option<Vec<u8>>,
        log2: Option<Vec<u8>>,
    }

    impl Disk {
        fn apply(&mut self, plan: &[(Slot, Vec<u8>)]) {
            for (slot, bytes) in plan {
                match slot {
                    Slot::Primary => self.primary = Some(bytes.clone()),
                    Slot::Log1 => self.log1 = Some(bytes.clone()),
                    Slot::Log2 => self.log2 = Some(bytes.clone()),
                }
            }
        }

        fn recover(&self) -> Result<Hive, LogicalError> {
            recover(
                self.primary.as_deref(),
                self.log1.as_deref(),
                self.log2.as_deref(),
            )
        }
    }

    /// The harness recovery sequence at `point`, on a SINGLE handle (as the
    /// harness does, issue #61): baseline saved (a real `hive_save`), a
    /// mutation applied in memory, then a `crash_save` at `point` instead of a
    /// save. Returns the hive recovered from disk, which must show
    /// baseline + the mutation.
    fn run_recovery(point: CrashPoint) -> Hive {
        let mut hive = Hive::new_empty(); // generation 1
        hive.create_key("Baseline").unwrap();

        // Baseline hive_save: a completed save advances the handle's generation
        // (to 2) and leaves a log of the previous generation on disk.
        let mut disk = Disk::default();
        disk.apply(&crash_save_plan(&mut hive, CrashPoint::AfterPrimary));
        assert_eq!(hive.generation(), 2, "the committed save advanced the gen");

        // Mutation M on the SAME handle, then crash at `point`. Because the
        // baseline advanced the generation, this journals a strictly newer
        // generation (3), so recovery prefers it over the committed baseline.
        hive.create_key("Added").unwrap();
        hive.set_value("Added", "v", 4, &7u32.to_le_bytes())
            .unwrap();
        disk.apply(&crash_save_plan(&mut hive, point));

        // A fresh load triggers recovery.
        disk.recover().unwrap()
    }

    fn assert_baseline_plus_m(hive: &Hive) {
        assert_eq!(hive.subkeys("").unwrap(), vec!["Added", "Baseline"]);
        assert_eq!(
            hive.get_value("Added", "v").unwrap().unwrap(),
            (4, 7u32.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn recovers_after_log_before_primary() {
        assert_baseline_plus_m(&run_recovery(CrashPoint::AfterLogBeforePrimary));
    }

    #[test]
    fn recovers_after_first_log() {
        // Generation selection: the new generation is in the other log slot,
        // the previous one is still in the baseline's slot; the newer wins.
        assert_baseline_plus_m(&run_recovery(CrashPoint::AfterFirstLog));
    }

    #[test]
    fn after_primary_is_the_clean_commit() {
        let hive = run_recovery(CrashPoint::AfterPrimary);
        assert_baseline_plus_m(&hive);
        assert_eq!(hive.generation(), 3, "the primary committed the third gen");
    }

    #[test]
    fn generations_alternate_log_slots() {
        assert_eq!(log_slot_for(1), Slot::Log1);
        assert_eq!(log_slot_for(2), Slot::Log2);
        assert_eq!(log_slot_for(3), Slot::Log1);
    }

    #[test]
    fn a_torn_log_is_ignored_and_the_primary_survives() {
        // Baseline committed (primary gen 2 + log2 gen 2). A crash writes a
        // corrupt journal to the other log; recovery must fall back to the
        // clean primary rather than the torn log.
        let mut hive = Hive::new_empty();
        hive.create_key("Baseline").unwrap();
        let mut disk = Disk::default();
        disk.apply(&crash_save_plan(&mut hive, CrashPoint::AfterPrimary));

        // Corrupt journal in log1 (a torn write): valid length, bad checksum.
        // The valid baseline log (log2) and primary survive.
        let mut torn = disk.primary.clone().unwrap();
        torn[8] ^= 0xff; // flip a secondary-seq byte, breaking the checksum
        disk.log1 = Some(torn);

        let recovered = disk.recover().unwrap();
        assert_eq!(recovered.subkeys("").unwrap(), vec!["Baseline"]);
        assert_eq!(
            recovered.generation(),
            2,
            "ignored the torn log, kept gen 2"
        );
    }

    #[test]
    fn recover_errors_when_nothing_is_valid() {
        let disk = Disk {
            primary: Some(vec![0u8; 16]),
            ..Default::default()
        };
        assert!(matches!(disk.recover(), Err(LogicalError::Unsupported(_))));
    }
}
