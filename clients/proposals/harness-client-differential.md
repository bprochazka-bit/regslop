# Proposal: harness client-differential mode

Status: draft, for the harness agent (and spec agent where noted).
Author: clients agent. Date: 2026-06-01.

## Summary

Validate the `reg` and `sc` client utilities the same way libreg is validated:
differentially, against the Windows originals, with the existing harness as the
judge. Run an operation with our Linux `reg`/`sc` against a hive file, run the
same operation with the real `reg.exe`/`sc.exe` on the Windows VM against an
equivalent hive, then compare the two resulting hives in canonical form. A test
passes when the differ reports `semantic` equality.

This closes the one gap that keeps the clients from meeting universal rule 3
("the harness is the judge"). Today `reg`/`sc` are covered only by cli-core unit
tests and local end-to-end smoke runs, which prove they are self-consistent but
not that they match Windows.

## Why this is a harness change

The clients are done and live in `clients/` (built, tested, packaged). What is
missing is the offreg-grounded acceptance, and that machinery (driving both
sides, pulling hives, running the differ, reporting per tag) is the harness's
job and lives in `tests/harness/`, which the clients agent does not write to.
This document is the coordination note universal rule 2 asks for.

## Key insight: the command line is the test

The clients are designed to be syntax compatible with the Windows tools, so in
most cases the *same command line* runs on both sides. A test case can be
literally the argument string:

```
reg add SomeKey /v Greeting /t REG_SZ /d "hello"
```

run by our `reg` on Linux and by `reg.exe` on Windows, each against its own copy
of the same starting hive. No per-side translation table is needed for the
common verbs, which keeps the test corpus small and honest: if the strings ever
need to diverge, that is itself a fidelity bug worth surfacing.

## How each side mutates an offline hive

### Linux side (our tools)

Point the client at a specific file with the existing `--hive FILE` override
(or set `$LIBREG_HIVES` to a throwaway mount map). The client opens the file,
mutates, and saves in place. No server, no daemon. Deterministic.

### Windows side (real tools)

`reg.exe` and `sc.exe` work on the live registry, so to mutate an offline hive
the harness wraps each invocation:

```
reg load   HKLM\HarnessTmp  C:\work\test.hiv
reg add    HKLM\HarnessTmp\<subpath> ...      (the operation under test)
reg unload HKLM\HarnessTmp                      (flushes the hive back to disk)
```

For `sc`, the services live under a control set, so the wrapper targets
`HKLM\HarnessTmp\<ControlSet>\Services` after loading the SYSTEM hive. The
`load`/`unload` pair requires administrator rights and an exclusive hive, both
already true on the dedicated VM.

The mutated hive file is then pulled to the Linux side over the existing SMB
path (`tests/harness/src/smb.rs`) for comparison.

## Comparison

Reuse what already exists:

- Parse both result hives with the harness regf parser
  (`tests/harness/src/differ/regf.rs`).
- Compare canonical form with the semantic differ
  (`tests/harness/src/differ/semantic.rs`), which already ignores `last_write`
  and normalizes SDDL. Allocation-order and timestamp deltas stay `bytewise`
  warnings, exactly as for the agent differential.

The clients write real `regf` bytes through libreg, so the same canonical
comparison that grades the Linux agent applies unchanged.

## Mapping to the existing harness

The current harness drives two HTTP agents. This mode drives two command-line
tools instead, but the back half (pull hive, parse, diff, report per tag) is
shared. Suggested shape:

- A new runner mode, for example `tests/harness/src/client_differ.rs`, that:
  1. seeds a starting hive (a fresh empty hive from libreg, or a corpus hive),
  2. copies it to both sides,
  3. runs the operation: our binary locally, `reg.exe`/`sc.exe` on the VM via
     the load/operate/unload wrapper,
  4. pulls the Windows result, runs the differ, records the verdict.
- A test-case format. The existing YAML op format
  (`tests/harness/CLAUDE.md`) can carry a `client` op whose payload is the
  shared argument string plus the starting-hive reference and the in-hive mount
  point used for `reg load`.

## What each agent does

- **Harness agent (owns `tests/harness/`)**: the runner mode, the Windows-side
  `reg.exe`/`sc.exe` wrapper and its remote-exec mechanism (WinRM/SSH/psexec;
  the harness already has SMB pull and the `winvm_lock` flock to reuse), the
  comparison wiring, and reporting under the new or reused tag.
- **Clients agent (owns `clients/`)**: provides the binaries (done) and a stable
  invocation contract (below), helps author the starter test corpus, and fixes
  any client-side divergence the differ catches. Will not debug the harness.
- **Spec agent (owns CONTRACTS.md)**: needed only if a new test tag is
  introduced. The test categories are listed in CONTRACTS.md, so adding, for
  example, `client-semantic` is a `contracts`-labelled change. Reusing the
  existing `semantic` tag avoids a contract change; a distinct tag is cleaner
  for per-area reporting. Harness and spec agents should pick one.

## Client invocation contract (stable, from the clients side)

The harness can rely on these without further coordination:

- `reg <verb> ...` and `sc <verb> ...` accept a `--hive FILE` global option
  that binds the path's root to `FILE` (so the whole subpath is in-hive). `sc`
  also takes `--controlset N` (default ControlSet001). The service tool's binary
  is now `regsc` (it ships under that name to avoid the Debian/Ubuntu `sc`
  calculator clash; a `sc` alias is added on install when the name is free), so
  the harness should point `--sc-bin` at `target/release/regsc`. The verb
  grammar is unchanged and sc.exe-identical.
- Alternatively set `$LIBREG_HIVES` to a temp mount-map file to avoid touching
  the user's map. The clients never write outside the named hive and the mount
  map.
- Exit codes: 0 success, 1 error or empty search, 2 for `reg compare`
  differences. `sc` runtime verbs (start/stop/pause/continue) exit nonzero with
  a clear "not available offline" message and must be excluded from the corpus.
- Output goes to stdout; errors to stderr prefixed `ERROR:` (`reg`) or `[SC]`
  (`sc`). The differential grades the resulting hive, not stdout, so output
  format is not load-bearing for the comparison.

## Edge cases and exclusions

- **Timestamps and allocation order**: already handled by the semantic differ
  (ignored / warning-only). No new work.
- **`reg save` semantics**: our `reg save` writes a fresh hive whose root is the
  saved key; `reg.exe save` snapshots the on-disk subtree. To compare, define
  the "result hive" identically on both sides (compare the saved file's
  canonical tree rooted at the saved key). Worth a dedicated case, not the first
  one.
- **Security descriptors**: `reg.exe` does not edit ACLs, so key security is out
  of scope for the client differential. It is already exercised at the agent
  level (`security.yaml`) and in regedit.
- **`.reg` import/export**: a strong second phase. Compare the hive produced by
  our `reg import file.reg` against the hive produced by `reg.exe import` of the
  same file. Also export from a corpus hive on both sides and diff the `.reg`
  text (after normalizing line endings and value ordering).
- **Admin/exclusivity**: `reg load`/`unload` need the hive not be open
  elsewhere; serialize through the existing VM flock.

## Suggested phasing

1. `reg add` and `reg delete` (key and value), the state-changing core. Starter
   corpus of ~15 cases over the REG types, nested keys, default values,
   recursive delete. Green on `semantic` is the bar.
2. `sc create`/`config`/`delete` against a SYSTEM hive (compare the
   `...\Services\<name>` subtree).
3. `.reg` import differential, then export-and-diff.
4. Fuzz integration: the operation fuzzer can emit the shared command strings,
   feeding both sides.

## Acceptance

The clients are "validated" once phase 1 is green on `semantic` for the starter
corpus on the live VM, matching how libreg's steps were closed. Subsequent
phases extend coverage.
