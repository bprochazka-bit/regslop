//! Layer 3: dual transaction logs and crash recovery.
//!
//! Recovery is a libreg-internal property, not a differential one: offreg
//! writes no transaction logs (ADR 0004), so libreg owns this format. The
//! scheme satisfies the recovery contract in issue #61 and the precedence
//! ratified in CONTRACTS 0.1.9 "Transaction Log Behavior":
//!
//! - Each save is a *generation*: a complete, self-consistent hive snapshot
//!   ([`Hive::snapshot`]) stamped with a sequence number and valid checksum.
//! - A completed save journals the new generation to the alternating log slot
//!   and writes a CLEAN primary at that generation. A pre-primary crash writes
//!   a DIRTY primary (primary_seq = new, secondary_seq = previous) plus the
//!   journal, so the primary is marked "awaiting recovery".
//! - On load, [`recover`] obeys the precedence: a present, clean, valid primary
//!   is AUTHORITATIVE and no log is replayed over it (even one with a higher
//!   sequence). A log is replayed only when the primary is dirty, missing, or
//!   corrupt. This is what keeps a stale `.LOG` left at a reused path from
//!   mutating a freshly saved clean hive (issue #93).
//!
//! This is a full-snapshot journal. Real Windows journals only the dirty
//! pages; a delta format is a future optimization that does not change the
//! recovery contract. Because the log carries the whole generation, the two
//! pre-primary crash points ("after_first_log" and "after_log_before_primary")
//! recover identically here; the distinction matters only to a dirty-page
//! scheme.

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

/// The ordered disk writes a recoverable save performs for `point`. Each entry
/// is `(slot, bytes)`; a caller (the agent's `/test/crash_save`, or a test)
/// executes them in order against the hive's files. A normal save is
/// `crash_save_plan(hive, AfterPrimary)`.
///
/// A completed save ([`CrashPoint::AfterPrimary`]) writes a CLEAN primary at
/// the new generation and advances `hive`'s committed generation, so the next
/// save on the same handle is strictly newer (the harness keeps one handle
/// across the baseline `hive_save` and the `crash_save`, issue #61). A
/// pre-primary crash writes a DIRTY primary (primary_seq = new, secondary_seq =
/// previous) plus the journal: on the next load the dirty primary triggers
/// recovery, which replays the journal. Marking the primary dirty is required
/// by CONTRACTS 0.1.9 ("Transaction Log Behavior"): a load only replays a log
/// over a primary that is itself awaiting recovery, never over a clean one, so
/// a stale `.LOG` left at the path cannot mutate a freshly saved hive
/// (issue #93). It does not advance the committed generation: the save did not
/// commit, and the handle is discarded after a simulated crash.
pub fn crash_save_plan(hive: &mut Hive, point: CrashPoint) -> Vec<(Slot, Vec<u8>)> {
    let prev = hive.generation();
    let new = prev + 1;
    let journal = hive.snapshot(new); // clean snapshot at the new generation
    let log_slot = log_slot_for(new);

    if point == CrashPoint::AfterPrimary {
        // Clean commit: the journal and a clean primary, both at `new`. The
        // primary is authoritative on load; the log does not exceed it.
        hive.set_generation(new);
        vec![(log_slot, journal.clone()), (Slot::Primary, journal)]
    } else {
        // Crash before commit: a dirty primary (new/prev) marks "save in
        // flight"; the journal at `new` carries the would-be-committed state.
        let dirty_primary = hive.snapshot_with_seqs(new, prev);
        vec![(Slot::Primary, dirty_primary), (log_slot, journal)]
    }
}

/// Recover the hive to load from a primary file and its logs. Each argument is
/// the bytes of a candidate file (`None` if absent). Precedence per CONTRACTS
/// 0.1.9 "Transaction Log Behavior":
///
/// - A present, clean (primary_seq == secondary_seq), valid primary is
///   AUTHORITATIVE: it is returned and no log is replayed over it, even if a
///   log carries a higher sequence (so a stale `.LOG` left at the path cannot
///   mutate a freshly saved hive, issue #93).
/// - Otherwise (the primary is dirty, missing, or fails its checksum) the most
///   recent valid log is replayed. If no valid log exists, the primary is
///   loaded as-is when present.
pub fn recover(
    primary: Option<&[u8]>,
    log1: Option<&[u8]>,
    log2: Option<&[u8]>,
) -> Result<Hive, LogicalError> {
    // A clean, valid primary wins outright.
    if let Some(bytes) = primary {
        if let Ok(bb) = BaseBlock::parse(bytes) {
            if bb.checksum_valid() && bb.is_clean() {
                return Hive::from_file_bytes(bytes);
            }
        }
    }

    // Primary dirty/missing/corrupt: replay the newest valid log.
    let mut best: Option<(u32, &[u8])> = None;
    for candidate in [log1, log2].into_iter().flatten() {
        let Ok(bb) = BaseBlock::parse(candidate) else {
            continue;
        };
        if !bb.checksum_valid() {
            continue;
        }
        let generation = bb.secondary_seq;
        if best.is_none_or(|(g, _)| generation > g) {
            best = Some((generation, candidate));
        }
    }

    match (best, primary) {
        // A log to replay.
        (Some((_, bytes)), _) => Hive::from_file_bytes(bytes),
        // No valid log, but a primary is present (dirty/corrupt): best effort.
        (None, Some(bytes)) => Hive::from_file_bytes(bytes),
        (None, None) => Err(LogicalError::Unsupported(
            "no recoverable hive: no primary and no valid log",
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
    fn recover_errors_when_there_is_nothing() {
        // No primary and no valid log: nothing to recover.
        let disk = Disk::default();
        assert!(matches!(disk.recover(), Err(LogicalError::Unsupported(_))));
    }

    #[test]
    fn a_clean_primary_ignores_a_stale_higher_generation_log() {
        // Issue #93: a fresh, clean save at a path that still has a stale log
        // from a previous, unrelated hive (with a HIGHER sequence) must load as
        // the freshly saved primary, not the stale log. The clean primary is
        // authoritative (CONTRACTS 0.1.9).
        let mut fresh = Hive::new_empty();
        fresh.create_key("Fresh").unwrap();
        let mut disk = Disk::default();
        disk.apply(&crash_save_plan(&mut fresh, CrashPoint::AfterPrimary)); // clean gen 2

        // A leftover log from an earlier hive: a valid snapshot at a much
        // higher generation (50), with different content.
        let mut prior = Hive::new_empty();
        prior.create_key("Stale").unwrap();
        disk.log1 = Some(prior.snapshot(50));

        let recovered = disk.recover().unwrap();
        assert_eq!(
            recovered.subkeys("").unwrap(),
            vec!["Fresh"],
            "the clean primary won; the stale gen-50 log was not replayed"
        );
        assert_eq!(recovered.generation(), 2);
    }

    #[test]
    fn a_dirty_primary_does_replay_the_log() {
        // The flip side: when the primary IS dirty (a real interrupted save),
        // the newer log is replayed, even though the primary is present.
        let recovered = run_recovery(CrashPoint::AfterLogBeforePrimary);
        assert_baseline_plus_m(&recovered);
    }
}
