# ADR 0004: Dual transaction logs and the recovery-test control surface

- Status: proposed
- Date: 2026-05-31
- Deciders: spec agent
- Scope: CONTRACTS.md "Transaction Log Behavior" and the `recovery` test
  category; prompted by the harness agent's spec question 2
  (tests/harness/spec-questions.md). The control surface in part B is a
  proposal and is NOT yet in CONTRACTS.md (see Consequences).

## Context

v0.1 targets dual-log hives: a primary file plus two transaction logs
(`.LOG1` and `.LOG2`). Two things needed settling.

1. Why two logs, and how recovery orders them. CONTRACTS "Transaction Log
   Behavior" states the rule but not the rationale, and ADRs are where the
   rationale lives.

2. How the harness exercises the `recovery` tag. The harness needs to make
   libreg abort a save deterministically, after the log is written but
   before the primary is committed, so it can verify log replay on the next
   load. CONTRACTS mentions "a separate test mode that simulates crashes"
   but defines no control surface, so the recovery tag is blocked and the
   harness reports it as n/a.

A constraint shapes everything below: only libreg writes transaction logs.
The Windows oracle uses offreg, which does not write logs and reports
`not_supported` for log behavior (agents/windows/CLAUDE.md). So `recovery`
is not a differential comparison against the oracle. It is a libreg-internal
property: a recovered hive must equal the logical state that was committed
before the crash.

## Decision

### Part A: dual-log design (background)

The base block and each log carry a primary and a secondary sequence number
(hive-format.md base block; offsets 4 and 8). A clean hive, one not awaiting
recovery, has `primary == secondary` (CONTRACTS invariant 2).

On a flush, dirty pages are journaled to one log before the primary is
updated, and the two logs alternate generations: dirty pages go to whichever
log holds the older sequence number, while the other log retains the
previous generation until the primary commit succeeds (CONTRACTS
"Transaction Log Behavior"). On load, if the primary and secondary sequence
numbers differ the hive is dirty; the loader inspects both logs, applies the
most recent self-consistent set, and rewrites a clean primary.

Why two logs and not one: the single-log scheme (`.LOG`, minor version 3)
has a window during which its one log is being overwritten, and a crash in
that window loses recoverability. Two alternating logs guarantee that at
every instant there is at least one intact (log, primary) pair to recover
from. This is the reason Windows 8.1 moved to dual logging, and it is the
behavior v0.1 targets.

### Part B: recovery-test control surface (proposed)

Recovery is tested on the libreg side only. The oracle for a recovery test
is the pre-crash canonical dump of the same hive, captured with a normal
`/hive/dump` before the simulated crash. The Windows agent takes no part.

Proposed surface: a test-only endpoint in a `/test/` namespace, Linux agent
only, Windows agent returns `not_supported`.

```
POST /test/crash_save  { "handle", "point" }
     point in { "after_log_before_primary", "after_first_log", "after_primary" }
-> { "ok": true, "data": { "crashed_at": "<point>" }}
```

The agent performs the save up to the named point, flushes what precedes the
point to disk, then stops without completing the rest, leaving the on-disk
primary and logs in the mid-save state.

Proposed harness recovery sequence:

1. Build a hive, capture canonical dump `D0`.
2. Apply a mutation, but commit it via `POST /test/crash_save` with
   `point = after_log_before_primary` instead of `/hive/save`.
3. `/hive/close` to discard in-memory state.
4. `/hive/load` the same path, which triggers log replay.
5. `/hive/dump` and assert it equals `D1`, the post-mutation logical state.
   Passing proves the logged-but-not-committed write was recovered.

A second variant crashes at `after_first_log` to exercise generation
selection (one log written, the other still previous-generation).

Why an endpoint and not a launch flag or a process kill: an endpoint gives
deterministic, per-operation control that is reproducible from a YAML
operation sequence (the fuzzer can emit it) and inspectable with curl,
consistent with ADR 0001. Killing the process (SIGKILL) cannot pin the crash
to the log/primary boundary and is non-deterministic about how far the save
got, so it cannot distinguish a complete pre-primary flush from a partial
log write.

## Alternatives considered

### Single log (minor version 3) as the recovery target

Simpler, but it is the scheme dual logging exists to replace, and it has the
unrecoverable window described above. We may still read single-log corpus
hives, but the write-and-recover target is dual-log. Rejected as the target.

### Kill the process to simulate a crash

Non-deterministic crash point; cannot isolate the log/primary boundary;
leaves the harness unable to tell a successful pre-primary flush from a
partial log write. Rejected for the deterministic recovery tests. It may
still serve as a fuzz-level stressor later.

### Syscall-level IO fault injection (LD_PRELOAD on `fsync`/`write`)

Closer to a real power loss, but opaque to the contract and hard to aim at a
specific logical point. Out of scope for v0.1; revisit if the endpoint-based
crash points prove too coarse.

## Consequences

- This ADR does NOT add `/test/crash_save` to CONTRACTS.md. The spec agent
  does not add endpoints without an implementation behind them (docs/CLAUDE.md).
  The endpoint enters CONTRACTS as a MINOR (test-mode, Linux only, Windows
  `not_supported`) once the library agent has a working log-recovery path and
  a prototype of the hook, and the harness confirms it can drive `recovery`
  green.
- Until then the `recovery` tag stays n/a, which the harness already reports.
- Open question, unresolved: the exact on-disk minor version libreg writes
  for dual logs (5 vs 6; CONTRACTS loosely says "v1.5 hives"). hive-format.md
  leans 6. Do not pin it in CONTRACTS until a corpus hive or the live VM
  confirms what libreg actually writes. When resolved, reconcile the
  CONTRACTS "Transaction Log Behavior" wording in the same PATCH.

## Downstream (owning agents)

- Library agent: implement dual-log write and crash-recovery on load, then
  prototype the `/test/crash_save` hook (or propose an alternative shape).
  This is the gating item; everything else waits on it.
- Harness agent: once the hook exists, implement the recovery sequence above
  and flip `recovery` from n/a to a real pass rate.
- Windows agent: none. Continue reporting `not_supported` for log behavior.
- Spec agent: on a working prototype, add the test endpoint to CONTRACTS
  (MINOR) and resolve the minor-version wording.
