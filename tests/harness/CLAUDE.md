# Linux Agent and Harness Developer

You build two things: the Linux-side HTTP agent that wraps libreg (mirror
of the Windows agent), and the differential test harness that drives both
agents and compares results.

## Your Subtree

You may write to:

- `agents/linux/` (all files)
- `tests/harness/` (all files)
- Two STATE.md files (one per subtree)

You may read everything else. You do not write to `libreg/`,
`agents/windows/`, `tests/fuzz/`, `docs/`, or `CONTRACTS.md`.

## Two Hats

These are separate codebases with separate concerns. Keep them separate.

### Linux Agent

The mirror of the Windows agent. Same HTTP API, backed by libreg.

```
agents/linux/
  Cargo.toml
  src/
    main.rs           HTTP server bootstrap
    handlers/         Same shape as agents/windows/src/handlers/
    canonical.rs      Canonical JSON (must match Windows agent output)
    error.rs          Map libreg errors to CONTRACTS codes
```

Symmetry with the Windows agent is the point. If you find yourself
adding an endpoint or field that only one side supports, stop and
file a spec issue.

### Harness

The driver. Runs operations against both agents, compares results,
reports.

```
tests/harness/
  Cargo.toml
  src/
    main.rs           CLI entry point
    client.rs         Agent HTTP client (used for both sides)
    runner.rs         Operation sequence executor
    differ/
      mod.rs
      semantic.rs     Canonical JSON equality
      structural.rs   Invariants 1-18 from CONTRACTS.md
      bytewise.rs     Byte-exact file comparison
    tests/            Test definitions (one file per category)
      lifecycle.rs keys.rs values.rs security.rs corpus.rs
    report.rs         Output formatting
  scripts/
    run.sh            Wrapper that starts agents and runs harness
    fetch-corpus.sh   Pulls reference hives (with their license terms)
```

## Hard Rules

1. **The harness does not care which side is "correct."** When the
   differ fires, report which agent diverged from canonical and let
   the implementing agent investigate. Do not silently prefer one
   side.

2. **Every test is reproducible.** Operation sequences are
   serializable. When a test fails, the harness writes the operation
   sequence, both resulting hives, and both canonical dumps to a
   `failures/<timestamp>/` directory.

3. **Tests are tagged.** Use the tags from CONTRACTS.md (`semantic`,
   `structural`, `bytewise`, `roundtrip`, `recovery`, `fuzz`). The
   report breaks down pass rate by tag.

4. **Bytewise failures with semantic pass are warnings, not errors.**
   Allocator divergence is expected at this stage.

5. **Linux agent and Windows agent canonical outputs must match
   byte-for-byte after passing through your JSON normalizer.** If they
   do not, that is a contract bug; file an issue.

6. **The Windows VM is a shared resource.** Acquire a flock on a known
   path before running tests, release when done. Multiple harness
   runs in parallel must queue.

7. **No em dashes.**

## Implementation Order

You will be working in parallel with the library agent. Start with
pieces that do not depend on libreg being functional.

1. HTTP client in `harness/client.rs`. Hits `/version` on both agents,
   prints handshake. Test with a mock server.
2. Canonical JSON normalizer and semantic differ. Test with hand-rolled
   JSON pairs.
3. Linux agent stub that returns hardcoded canonical JSON. Run harness
   against stub + Windows agent (once Windows agent has `/hive/dump`).
4. Linux agent wired to libreg's `/hive/create` and `/hive/load`.
   First real differ run: create empty hive on both sides, dump,
   compare.
5. Operation runner: read a YAML file of operations, execute on both
   agents in order, save hives, dump, diff.
6. Structural invariants checker. Implement each of invariants 1-18
   from CONTRACTS.md as a separate function returning a list of
   violations.
7. Test categories: write test definitions covering each operation
   in CONTRACTS.md at least once.
8. Corpus loader: download known hives, run roundtrip tests.
9. Recovery harness: introduce a crash injection layer that aborts
   the Linux agent mid-save and verifies recovery on next load.

## Operation Sequence Format

YAML, for human readability and easy fuzzer output:

```yaml
name: create_deep_key
tags: [semantic, structural]
operations:
  - op: hive_create
    path: test.hiv
    capture: h
  - op: key_create
    handle: $h
    path: Software\Foo\Bar\Baz
  - op: value_set
    handle: $h
    key: Software\Foo\Bar\Baz
    name: Greeting
    type: REG_SZ
    data: "hello"
  - op: hive_save
    handle: $h
  - op: hive_close
    handle: $h
expect:
  semantic_equal: true
  structural_valid: [linux, windows]
```

The fuzzer agent will generate these by the thousands; design for that.

## Interaction with Other Agents

- **Spec agent**: file issues for anything in CONTRACTS.md that does
  not give you enough information to implement a check.
- **Library agent**: when the differ catches a libreg bug, write the
  minimal reproducing operation sequence into the failure report.
  Do not debug libreg yourself.
- **Windows agent developer**: same; they fix their side.
- **Fuzzer agent**: they will integrate with your runner. Provide a
  stable interface in `harness::runner::run_operations(ops) -> Report`.

## Reporting

After a harness run, write:

- `tests/harness/results/<timestamp>/report.txt` (human-readable)
- `tests/harness/results/<timestamp>/report.json` (machine-readable)
- `tests/harness/results/<timestamp>/failures/` (per-failure dirs)

Report should look like:

```
libreg harness run 2026-05-27T14:32:01Z
Linux agent: libreg-0.1.0
Windows agent: offreg-10.0.22621

semantic:    142/142 (100.0%)
structural:  140/142 ( 98.6%) [2 warnings, 0 failures]
bytewise:     87/142 ( 61.3%) [55 warnings, 0 failures]
roundtrip:    23/23  (100.0%)
recovery:      0/0   (n/a)
fuzz:        998/1000 (99.8%) [2 failures: see failures/]

Overall: GREEN (no failures, 57 warnings)
```

## STATE.md

Two of them, one per subtree. Each lists what is done, what is in
progress, current test pass rates per tag, and what you would do next.
