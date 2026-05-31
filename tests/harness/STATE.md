# Harness: STATE

Last updated: 2026-05-31

## CONTRACTS 0.1.2 conformance (this session)

- **SDDL comparison** (`src/differ/sddl.rs`, new): parses each side's SDDL into a
  normalized descriptor and compares per ADR 0003: owner and group SIDs exact,
  DACL as an ACE list in canonical category order (deny/allow/inherited) with
  per-ACE token normalization, SACL only when both sides report one. A one-sided
  SACL is a `semantic` WARNING, never a failure. Wired into `semantic.rs` (the
  `sddl` field is intercepted, not string-compared). 9 unit tests.
- **Semantic warnings channel**: `semantic::compare` now returns `{ diffs,
  warnings }`; `compute_semantic` maps a warnings-only result to
  `AspectOutcome::Warn` (passes, counted as a warning). `semantic::diff` kept as
  a thin wrapper so existing tests/callers are unaffected.
- **Case-insensitive Unicode ordinal sort** (uppercase) in the semantic
  normalizer and the structural invariant-17 check, matching the canonical sort
  rule in 0.1.2 and both agents' emitters.
- **Invariant wording** (3, 4, 9, 16) updated to the precise 0.1.1 definitions
  (checksum = XOR of first 127 dwords with quirks; "hive bins data size"
  excludes the base block; 32-byte hbin header; KEY_COMP_NAME 0x0020 not the old
  VALUE_COMP_NAME typo).
- **Negative test** `key_delete_nonempty_needs_recursive` now expects
  `KEY_HAS_CHILDREN` (was `ACCESS_DENIED`).
- Full `--standin` run is GREEN (11/11 semantic, 0 warnings; the stand-in is
  symmetric so the SACL-warning path is exercised only by the unit test).

## What is done

- HTTP client (`src/client.rs`) used for both agents interchangeably. Sends
  GET-with-body faithfully via `Agent::run` with a hand-built request; treats
  non-2xx as readable envelopes. `/version` handshake.
- Semantic differ (`src/differ/semantic.rs`): canonical JSON equality with
  defensive re-normalization (key order, array order) and timestamp ignoring.
  5 unit tests over hand-rolled JSON pairs, all green.
- Structural checker (`src/differ/structural.rs`): invariants 1 to 18 each a
  named function. Invariant 17 (subkeys sorted) evaluated from the canonical
  dump; 18 folded from the agent's `/hive/validate`; 1 to 16 return `Skipped`
  with the reason (need raw hive bytes) rather than false passes.
- Bytewise differ (`src/differ/bytewise.rs`): compares `sha256_file`; a
  mismatch is a warning, not a failure (allocator divergence expected).
- Runner (`src/runner.rs`): YAML op-sequence executor. Per-agent handle capture
  and `$var` substitution, expected-error checks, cross-agent op divergence,
  auto-snapshot before close, and an automatic save/reload roundtrip per saved
  hive. Stable entry point `run_operations(test, agents)` for the fuzzer.
- Report (`src/report.rs`): per-tag pass-rate table (report.txt), machine
  report.json, and per-failure dirs containing `ops.yaml` plus both canonical
  dumps. Process exit code is 1 on RED, 0 on GREEN.
- Windows VM advisory `flock` (`src/winvm_lock.rs`), acquired only in two-agent
  mode; queues parallel harness runs.
- `scripts/run.sh` (builds, starts agents, runs; `--standin` launches a second
  Linux agent as the Windows stand-in) and `scripts/fetch-corpus.sh`
  (placeholder pending corpus licensing).
- Test definitions in `tests/*.yaml` covering lifecycle, keys (incl. error
  paths), all value types, and security.

## Current pass rates (Linux agent vs. a Linux stand-in on :7879)

```
semantic:    11/11 (100.0%)
structural:   4/4  (100.0%)
bytewise:     2/2  (100.0%)
roundtrip:    7/7  (100.0%)
recovery:     n/a
fuzz:         n/a
Overall: GREEN
```

The stand-in is a second Linux agent, so this proves the pipeline and differ,
not cross-implementation correctness. Real numbers wait on the Windows agent.

## What is in progress / not done

- **Recovery harness** (crash injection / log replay): not started. Needs an
  agent control surface; see `spec-questions.md` item 3.
- **Corpus roundtrip**: `fetch-corpus.sh` is a placeholder; no hives are
  downloaded (licensing unresolved). Roundtrip currently exercises synthetic
  save/reload only.
- **Byte-level structural invariants (1 to 16)**: scaffolded but `Skipped`
  until an agent exposes raw hive bytes.
- `--strict-timestamps` is not wired to a CLI flag yet; the differ defaults to
  ignoring timestamps.

## What I would do next

1. Wire the recovery tag once the agent crash hook is specified.
2. Implement the byte-level invariants against real hive bytes when the agent
   exposes them, replacing the `Skipped` stubs.
3. Add the corpus loader after licensing is agreed with the spec agent.
4. Coordinate with the fuzzer agent on `run_operations` (already stable).
