# Harness: STATE

Last updated: 2026-05-31

## Corpus loader + byte-level structural invariants (latest session)

PR #29 checked in offreg-generated synthetic hives under
`tests/corpus/synthetic/` (real `regf` bytes, no third-party content). That
unblocked the byte-level structural invariants, which had been `Skipped` stubs
for want of real hive bytes in the repo.

- New `src/differ/regf.rs`: a minimal `regf` byte parser (base block + checksum
  + hbin/cell walk). Not a logical parser; the same parser will back the
  differential roundtrip once libreg can read `regf`.
- `structural::check_bytes(bytes)`: evaluates invariants 1 to 6, 9, 10 from the
  base block and hbin/cell structure against a real hive file. 7, 8, 11 to 16
  need a logical-tree parse and stay `Skipped`; 17/18 belong to the agent-output
  `check()`.
- New `src/corpus.rs`: reads every `*.hiv` under `--corpus-dir` (default
  `tests/corpus/synthetic`) and emits one `structural`-tagged `TestResult` per
  hive. Runs in every mode (it reads files, no agent needed). `run.sh` passes an
  absolute `--corpus-dir`.
- Result: `structural` is now 8/8 (4 agent-based + 4 corpus hives), all PASS,
  validating the regf checker against known-good offreg output. 3 new corpus
  unit tests (all synthetic hives pass; a flipped checksum byte fails inv3; a
  missing dir yields nothing).

NOT done (and why): the load-on-both-agents differential *roundtrip* over the
corpus is still blocked. It needs the Linux agent to parse a real `regf` hive,
which the in-memory `MemBackend` cannot (it reads only its own JSON envelope);
libreg's `regf` reader is in progress. When it lands, `differ::regf` is the
parser to reuse, and the logical-tree invariants (7, 11 to 16) can be filled in
from the same parse.

## Read-op response comparison (latest session)

Closed a real gap: the harness compared only the final hive dump, never the
response payloads of read ops, so a read endpoint returning wrong data despite
correct storage (a bad `/key/list` order, a wrong `/key/info` count, a
divergent `/value/get`) would slip through. Now `OpResult` carries the response
`data` for successful read ops (`key_list`, `key_info`, `value_get`,
`key_security_get`), and `compare_op_results` diffs them cross-agent by reusing
the semantic differ (so `last_write` is ignored and `sddl` is normalized, SACL
conditional). Hard divergences become `problems` (fail the test); a one-sided
SACL from `key_security_get` is a `semantic` warning, not a failure. New
`tests/reads.yaml` (3 tests) exercises all four read endpoints. Live VM run is
GREEN, 14/14 semantic, confirming offreg and the Linux agent agree on every
read-endpoint response (default and explicit SDDL included).

The recovery tag is still the next substantial effort and remains blocked on
the library agent (ADR 0004: the `/test/crash_save` hook is not in CONTRACTS
until libreg has a working log-recovery path; Rule 7 forbids inventing it).

## CONTRACTS 0.1.3 to 0.1.6 (latest session)

The harness needs NO code change for these: 0.1.3 (default SDDL) is already
asserted by the existing O/G/D SDDL normalization; 0.1.4 (`BAD_REQUEST`) is just
another error-code string the differ compares verbatim; 0.1.5 (`/key/create`)
and 0.1.6 (GET-body transport) are documented existing behavior with no wire
change. The Linux agent gained `BAD_REQUEST` conformance this session. Re-ran
the live VM differential: GREEN.

Possible future harness test: a malformed-request negative test asserting
`BAD_REQUEST`. Held back because the Windows agent has not adopted 0.1.4 yet, so
a cross-agent version would diverge (linux=BAD_REQUEST vs windows=INTERNAL).
Add it once the Windows agent conforms.

Recovery tag: ADR 0004 now proposes the crash-injection control surface that was
the blocker. Still not implemented; this is the next substantial harness effort.

## First live VM differential run (2026-05-31)

Ran the harness against the real Windows agent (offreg-10.0.22621) on the shared
VM (`vmreg.lan:7879`), not the stand-in. **Result: GREEN, semantic 11/11**,
structural 4/4, bytewise 2/2 (warnings = allocator divergence, expected),
roundtrip 7/7. Three findings, in the order they were peeled back:

1. **Harness bug, fixed: hive paths are per-agent filesystem paths.** Tests use
   `/tmp/libreg_*.hiv`, which offreg cannot create (win32 error 3). The harness
   now maps a logical hive path onto each agent's hive dir (`Client::map_hive_path`),
   keyed off the agent's reported `agent` field so a Linux stand-in still gets
   `/tmp`. New flags `--linux-hive-dir` (default `/tmp`) and `--windows-hive-dir`
   (default `C:\Windows\Temp`). This was masking every other result.
2. **Linux agent bug, fixed: REG_QWORD encoding.** The Linux agent emitted a
   sub-2^53 QWORD as a string; CONTRACTS says integer (string only above 2^53).
   Fixed in the Linux agent to mirror the Windows `v > (1<<53)` rule.
3. **Default security descriptor, matched to oracle.** The Linux placeholder
   default (2 ACEs) diverged from offreg's real default (4 ACEs). Set the Linux
   `DEFAULT_SDDL` to the observed oracle default; recorded for spec ratification
   in `agents/linux/spec-questions.md` item 4.

The remaining `semantic` WARNING (1) is the one-sided-SACL case firing for real
on `key_rename`: offreg exposes a SACL on the renamed key that the Linux side
does not, and ADR 0003 makes that a warning, not a failure. End-to-end proof
that the SACL-asymmetry rule works against the live oracle.

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
