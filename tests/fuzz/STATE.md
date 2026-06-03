# Fuzzer Agent STATE

Last session: 2026-06-02. Branch: `agent/fuzz-opfuzz` (off `origin/main`).

## What is done

The fuzzing crate `tests/fuzz/` is built and green (`cargo test`: 29 passing).
All three fuzzer binaries build in release. The operation fuzzer runs end to
end against the libreg agent through the differential harness and currently
reports libreg GREEN (100 sequences, 0 failures on the latest run).

### Core (library, shared by the three binaries)

- `src/rng.rs`: deterministic SplitMix64 (no `rand`, so a seed replays
  identically across rebuilds and endianness).
- `src/coverage.rs`: endpoint coverage over all 17 contract ops; steers the op
  generator toward undercovered ops (hard rule 4).
- `src/generators/paths.rs`, `values.rs`, `ops.rs`: realistic paths, per-type
  value payloads + edge-case catalog, and the weighted operation-sequence
  generator (category weights 30/30/15/10/10/5). Emits the harness YAML format
  directly; a unit test round-trips every sequence through a mirror of the
  harness `TestDef` parser.
- `src/generators/mutate.rs`: structure-aware regf mutator; offsets and the
  base-block checksum mirror the harness `regf.rs`.
- `src/triage.rs`: classification, stable FNV-1a signatures, and a generic
  1-minimal minimizer.
- `src/harness_runner.rs`: drives the `libreg-harness` binary and parses
  `report.json` + `summary.txt`. Never reimplements the differ (hard rule 3).
  Also owns `sweep_companions` (see hermeticity below).

### Binaries

- `op_fuzz` (priority 1, complete): generate -> harness -> dedup -> minimize ->
  file. P0 crashes/hangs to `corpus/crashes/`, P1 differ findings to
  `corpus/interesting/`; appends `triage.log`.
- `data_fuzz` (priority 2, functional): one minimal `value_set` per catalog
  entry; `--emit-catalog` writes `corpus/interesting/values.yaml`.
- `hive_fuzz` (priority 3, functional): seeded structural mutations of corpus
  hives loaded via the libreg agent; needs `--backend libreg`.
- `scripts/run-fuzz.sh [op|data|hive]`: builds, starts the libreg agent
  (optional `--standin`), runs the chosen fuzzer.

## Findings this session

None confirmed against libreg. A short run (8 seqs) initially surfaced four
`validation-mismatch` (roundtrip) "findings", but triage proved all four were
fuzzer/harness artifacts, not libreg bugs (see "Lessons" below). After fixing
them, libreg is GREEN. A real bug hunt needs the long run that is now unblocked.

## Lessons (what the false positives taught, all fixed)

1. **Unsubstituted handle in the generator.** The trailing `hive_save`/
   `hive_close` used the bare capture name `h` instead of the `$h` reference,
   so the runner sent `{"handle":"h"}`, the final save silently no-oped
   (HANDLE_INVALID), and roundtrip compared unsaved in-memory state against the
   earlier save. Fixed in `ops.rs`; regression test
   `handles_are_substitutable_references` now asserts no op carries a bare `h`.
   Caught with a logging TCP proxy after curl could not reproduce what the
   harness reported.
2. **Stale transaction logs.** The harness reuses one hive path per seed across
   runs; a leftover `.LOG1/.LOG2` from a previous run is replayed on the next
   `hive_load` and changes the reloaded hive. `op_fuzz`/`data_fuzz`/`hive_fuzz`
   now call `harness_runner::sweep_companions` before every agent run.
3. **Minimizer slip.** Minimizing on "same FailureKind" let a real save/reload
   divergence shrink to a trivial "modified after the last save" sequence. The
   predicate now requires the same failure SIGNATURE and a `roundtrip_consistent`
   sequence (no mutating op after the last `hive_save`), so every minimized
   repro stays a valid roundtrip test.

These three together are why "verify with curl before filing" is mandatory: all
four initial findings would have been bogus libreg bug reports.

## Coverage and fuzz time

- Endpoint coverage: 17/17 (100%) within ~8 sequences.
- Accumulated continuous fuzz time: still under an hour (bring-up plus a
  100-sequence confidence run). The long run is the next step.

## Open items for other agents (see issues filed)

- **Spec agent**: whether `hive_load` should replay pre-existing `.LOG1/.LOG2`
  left at a path by a prior, unrelated hive generation, or whether a clean
  `hive_save` should reset/invalidate stale logs. This decides whether log
  hygiene is libreg's job or the caller's. Filed as a spec question.
- **Harness / Linux agent**: semantic differential fuzzing against the
  `--backend mem` stand-in is blocked because both agents report `agent=linux`
  and share `/tmp` paths, so saved files collide. Needs per-agent hive
  directories (or a unique logical path per agent). Until then `op_fuzz` runs
  single-agent (structural + roundtrip). Filed as an issue.

## What I would do next

1. Long continuous `op_fuzz` run (thousands of sequences) now that the
   false-positive sources are closed.
2. `data_fuzz` and `hive_fuzz` against `--backend libreg`; file what the
   db-boundary, big-data, and mutation cases turn up.
3. Resolve the path-collision item to unlock semantic differential fuzzing.
4. Add `corpus_mgmt.rs` coverage-guided corpus (keep sequences that hit new
   op-pair transitions), per the CLAUDE-fuzz layout. Not started.
