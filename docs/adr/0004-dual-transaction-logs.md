# ADR 0004: Dual transaction logs and the recovery-test control surface

- Status: proposed (Part B control surface confirmed for the prototype; see
  the revision note)
- Date: 2026-05-31
- Deciders: spec agent
- Scope: CONTRACTS.md "Transaction Log Behavior" and the `recovery` test
  category; prompted by the harness agent's spec question 2
  (tests/harness/spec-questions.md). The control surface in part B is a
  confirmed design but is NOT yet in CONTRACTS.md (see Consequences).

## Revision note (issue #61)

The harness agent (issue #61) asked four questions to lock the `/test/crash_save`
contract before the library agent builds it. They are answered in
"Part B.2: answers to the harness, confirmed" below. In short: the request/response shape
stands as written; the three crash points and their on-disk postconditions are
confirmed; `crash_save` writes to the hive's bound path so a later
`/hive/load` of that path works; and an invalid `point` is a `BAD_REQUEST`
(no new error code). Everything in this ADR remains a design: nothing enters
CONTRACTS until the prototype exists.

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

### Part B.1: recovery-test control surface (rationale)

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

### Part B.2: answers to the harness, confirmed (issue #61)

These confirm/refine the proposal so the library agent can build the hook in
one pass. They describe the intended contract; they are still a design until
the prototype lands.

**1. Request/response shape: confirmed as written.**

```
POST /test/crash_save  { "handle", "point" }
     point in { "after_log_before_primary", "after_first_log", "after_primary" }
-> { "ok": true, "data": { "crashed_at": "<point>" }}
```

`crashed_at` echoes the point actually honored. Linux/libreg only; the
Windows agent need not route it (the harness will not call it there). If the
harness ever does call it on a non-libreg agent, the standard "unknown
endpoint" path applies (`BAD_REQUEST`, per the agents' existing routing).

**2. The three crash points and their on-disk postconditions: confirmed.**

The save sequence is: journal M's dirty pages to the active log, fsync the
log, then write and fsync the primary (sequence numbers bumped). The points
cut that sequence:

- `after_log_before_primary`: M's dirty pages are in the active log and
  fsynced; the primary is NOT updated, so on disk `primary != secondary`
  sequence (dirty). On the next `hive_load`, the loader detects the dirty
  hive, replays the log, and the recovered dump is `baseline + M`. Core test.
- `after_first_log`: only the older-generation log has been written; the
  other log still holds the previous generation; the primary is not
  committed. Exercises log-generation selection on load. Recovered dump is
  still `baseline + M`. (For a hive with a single dirty generation this may
  be observationally identical to `after_log_before_primary`; the library
  agent decides whether the two points differ for a given mutation, and may
  treat them the same when only one log is in play. The harness treats a
  point it cannot distinguish as a pass, not a failure.)
- `after_primary`: M is fully committed (primary written, sequences equal,
  clean hive). Reload needs no recovery; the dump is `baseline + M`. Control
  / no-op case.

In all three, the call writes to the hive's bound path P and its `.LOG1`/
`.LOG2` siblings (see answer 3), so a subsequent `hive_load P` against a
fresh handle observes exactly what was left on disk.

**3. Path: `crash_save` writes to the hive's already-bound path.**

The handle was opened by `hive_create`/`hive_load` with a path; like
`/hive/save`, `crash_save` targets that same path (and its `.LOG1`/`.LOG2`).
No path is passed in or returned. The harness closes the handle after the
call and reloads by path, so the handle may be consumed/invalidated by
`crash_save`; agents need not keep it valid.

**4. Invalid `point`: `BAD_REQUEST` (no new error code).**

An unrecognized `point` is a malformed request, exactly what `BAD_REQUEST`
(CONTRACTS 0.1.4) already covers ("an unknown constant"). No new code is
warranted. The harness treats any `ok:false` envelope as "skip this recovery
case" rather than a crash, so `BAD_REQUEST` for an unsupported point is also
the graceful-degradation path on an agent that has not implemented every
point yet.

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
  The shape, crash points, path behavior, and error code are now confirmed
  (Part B answers), so the library agent can build the hook to spec; the
  endpoint enters CONTRACTS as a MINOR (test-mode, Linux only, Windows
  `not_supported`) once that prototype exists and the harness confirms it can
  drive `recovery` green.
- Until then the `recovery` tag stays n/a, which the harness already reports.
  Everything else is green (issue #61: libreg-vs-offreg 16/16 semantic, 9/9
  structural, 8/8 roundtrip), so `recovery` is the last open differential
  axis.
- The invalid-`point` error code is settled as `BAD_REQUEST` (existing,
  0.1.4); the eventual CONTRACTS MINOR adds the endpoint, not a new code.
- The dual-log minor-version question is RESOLVED (CONTRACTS 0.1.7 work):
  offreg writes minor version 5 for a fresh create, and minor 6 is the
  live-kernel dual-log variant offreg does not produce (hive-format.md
  Versions). Recovery is a libreg-internal property, so libreg's own
  log-bearing hives may carry whichever minor version its writer uses; this
  is not gated on offreg and does not block the recovery tag.

## Downstream (owning agents)

- Library agent: implement dual-log write and crash-recovery on load, then
  prototype the `/test/crash_save` hook (or propose an alternative shape).
  This is the gating item; everything else waits on it.
- Harness agent: once the hook exists, implement the recovery sequence above
  and flip `recovery` from n/a to a real pass rate.
- Windows agent: none. Continue reporting `not_supported` for log behavior.
- Spec agent: on a working prototype, add the test endpoint to CONTRACTS
  (MINOR) and resolve the minor-version wording.
