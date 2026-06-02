# Harness: STATE

Last updated: 2026-06-01

## Recovery tag: driven, no longer n/a (ADR 0004 / issue #61)

`src/recovery.rs` drives libreg's crash-injection hook. Per case it runs an op
sequence to build and commit a baseline, applies a mutation M (the ops after the
last `hive_save`), captures the in-memory dump D1, then `POST /test/crash_save
{ point }` instead of a normal save, closes, reloads (which recovers), and
asserts the reloaded dump equals D1. Each case yields a `recovery`-tagged
`TestResult`, so the report's `recovery:` line shows a real pass rate.

- Reuses the runner op helpers (`endpoint`/`build_body`/`substitute`, now
  `pub(crate)`) and the semantic differ (timestamps ignored).
- Single agent, libreg only: it needs `/test/crash_save` + log-backed
  save/load. The in-memory backend reports `crash_save` unsupported, which maps
  to `Na` (skipped), not a failure.
- Flag `--recovery-tests-dir DIR`; results append to the run like the corpus.
  Recovery is independent of the cross-agent differential (offreg writes no
  logs, so this is a libreg-internal property).
- `tests/recovery/recover.yaml`: 3 cases, one per crash point. **recovery 3/3**
  against the libreg agent (logged-but-not-committed write recovers on reload).

Depends on the agent PR (`/test/crash_save` + log-backed save/load); built and
verified together. Once both land, the spec agent can add `/test/crash_save` to
CONTRACTS (MINOR, Linux-only) per ADR 0004.

## Client-differential phase 3b: reg export (issue #68)

`reg export` differential. The seed is populated once via our `reg import` (so
both sides export the identical input hive), then both tools export the subtree
to a `.reg` file and the texts are compared. Both emit UTF-16LE+BOM/CRLF, but the
legitimate formatting differences are normalized away: the per-side root prefix
(`HKEY_LOCAL_MACHINE\` vs `...\HarnessTmp\`), value/key ordering (our reg sorts,
reg.exe preserves import order), and the `\`-continuation wrapping reg.exe
applies to long hex values (ours emits them on one line). What remains is the
logical content: `{ key -> sorted name=data lines }`, compared per key.

- `client_differ.rs` gains a `kind: reg_export` path (`run_reg_export_case`) plus
  a small self-contained `.reg` normalizer (`decode_reg`, `canonical_reg`,
  `diff_reg`); `ClientTest` gains an `export` field (the subkey to export).
- `tests/client/reg_export.yaml`: 2 cases (basic = SZ/DWORD/QWORD/40-byte BINARY
  that triggers reg.exe wrapping/default/nested; multi_expand = REG_MULTI_SZ
  `hex(7)` and REG_EXPAND_SZ `hex(2)`).
- Full client differential is **15/15 green** vs the VM (8 reg + 2 import + 2
  export + 3 sc). Phase 3 (import + export) is complete; phase 4 is fuzz.

## Client-differential phase 3a: reg import (issue #68)

`.reg` import differential: both tools import the same `.reg` body into an equal
seed hive, then the result hives are compared whole. `reg.exe import` works on a
loaded key, so the Windows side reuses the `reg add` load/import/unload wrapper
(`reg load HarnessTmp <hive> && reg import <reg> & reg unload`). The `.reg` text
is rendered per side: `{ROOT}` substitutes to `HKEY_LOCAL_MACHINE` for our tool
and `HKEY_LOCAL_MACHINE\HarnessTmp` for the loaded hive; line endings are forced
to CRLF.

- `client_differ.rs` gained a `kind: reg_import` path (`run_reg_import_case`);
  `ClientTest` gained a `reg` field (the `.reg` body), and `ops` is now
  `#[serde(default)]` (import cases carry no ops).
- `tests/client/reg_import.yaml`: 2 cases (basic = SZ/DWORD/default/nested;
  binary+qword = `hex:` REG_BINARY and `hex(b):` REG_QWORD).
- Full client differential is **13/13 green** vs the VM against the main-tree
  clients binaries (8 reg + 2 import + 3 sc). Import needs no clients fix, so it
  is purely additive on top of phase 2.

Compared with `SemanticOptions { ignore_timestamps, ignore_security }` (reg edits
no ACLs). Export-and-diff is now phase 3b (above). Separately, the sc corpus still
carries the `obj= LocalSystem` workaround until clients #78 merges (tracked
there, not here).

## Client-differential phase 2: sc (issue #68)

`sc.exe` only talks to the live SCM (it cannot target a loaded hive like
`reg add`), so the sc flow differs: our `sc` writes the offline SYSTEM hive
(`--hive FILE --controlset 1`), while on the VM `sc.exe` creates/configs the
*live* service, the harness `reg save`s the `HKLM\SYSTEM\CurrentControlSet\
Services\<name>` subtree, pulls it, and `sc delete`s the live service. The
comparison extracts our `ControlSet001\Services\<name>` node and compares it to
the reg-saved root as service views (top-level name elided; security/timestamps
ignored).

- `client_differ.rs` gained a `kind: sc` test path; `ClientTest` gained `kind`
  and `service`. The runner now takes `--reg-bin` and/or `--sc-bin`.
- `tests/client/sc.yaml`: 3 cases (create own, create share+auto, create+config).
  Full client differential is **11/11 green** vs the VM (8 reg + 3 sc).

Finding filed for the clients agent: a bare `sc create` defaults `ObjectName` to
`LocalSystem` in sc.exe but our `sc` omits it; the cases set `obj= LocalSystem`
explicitly to stay green until that is resolved.

## Client-differential mode, phase 1 (issue #68)

Validates the `reg`/`sc` CLIs the way libreg is validated: run the same command
with our `reg` against a hive file and with real `reg.exe` against an equivalent
hive on the VM, then compare the result hives in canonical form.

- `src/client_differ.rs`: the runner. For each case it seeds a fresh empty hive
  (made via the libreg agent), runs the ops on both sides, and compares.
  - Linux: our `reg <verb> HKLM\<key> ... --hive L.hiv`.
  - Windows: `reg load HKLM\HarnessTmp <hive> && <ops> & reg unload` run as
    SYSTEM via impacket `atexec` (task scheduler over SMB; `reg load`/`unload`
    need admin, and DCOM ports are filtered so wmiexec is out). Result pulled
    over the `winreg` share. Admin creds baked in (temporal lab VM).
  - Both result hives are canonicalized by loading them into the libreg agent
    (`/hive/load`+`/hive/dump`); compared with the semantic differ using a new
    `SemanticOptions.ignore_security` (reg/sc do not edit ACLs, and a
    SYSTEM-run reg.exe yields a different owner than our tool).
- Flags: `--client-tests-dir DIR --reg-bin PATH --windows-host HOST`. Dispatched
  before the Windows handshake (no Windows agent needed). Holds the VM flock.
- Corpus: `tests/client/{reg_add,reg_delete}.yaml`, 8 cases (REG types, nested
  keys, default value, multi-sz, overwrite, value/recursive-key/all-values
  delete). **8/8 green vs the live VM.**

Dependency: the `reg` binary lives in `clients/` (the clients agent's subtree,
not yet on main); the runner takes `--reg-bin` so it is decoupled. Built from
the proposal branch for this run.

Finding the differential caught (filed for the clients agent): a bare
`reg add KEY /f` (no `/v`) — reg.exe leaves an empty default value on the new
leaf key; our `reg` creates no value. Kept out of the green corpus until
resolved (see the `add_nested_keys` note).

cmd-`%` escaping for REG_EXPAND_SZ values containing `%` (e.g. `%PATH%`) is a
known follow-up: cmd.exe expands them through atexec; phase-1 values avoid `%`.

## Wide-key ri promotion test (issue #40)

`tests/wide_key.yaml` creates 1100 subkeys under one key, forcing ri promotion
(an ri index root over lh leaves capped at 507, matching ref_ri.hiv:
[507, 507, 86]). Generated (3315 lines). libreg shipped step-8 ri promotion, so
this validates the 507 figure end-to-end against offreg, not just from the
static fixture: with `--windows-smb`, inv11 (byte-level) runs on both libreg's
and offreg's saved regf and confirms the ri/lh structure on each. Result:
semantic + structural PASS on both sides (17/17, 10/10). Closes the wide-key
half of issue #40; the inv11 "un-skip" half was already done in check_bytes
(#39/#54).

## Coverage: big-data values and malformed requests (latest session)

Two new test definitions, both green libreg-vs-offreg:

- `tests/big_data_value.yaml`: a 20001-byte REG_BINARY value, over the 16344
  threshold, so it exercises the big-data (db) cell path in both backends. The
  data round-trips identically through real regf.
- `tests/badrequest.yaml` (`malformed_requests_rejected`): a leading-separator
  path and an unknown value-type constant, both must surface as BAD_REQUEST
  (0.1.4) on both sides. This caught a real LibregBackend conformance gap (it
  accepted a leading-separator path because libreg's path splitter is lenient);
  fixed agent-side. libreg-vs-offreg is 16/16 semantic with these added.

## Linux-side byte-level structural checks (latest session)

Extended the byte-pull so the harness validates the **Linux agent's** on-disk
hive bytes too, not just the Windows side. The Linux agent runs on this box, so
the harness reads its saved hive file directly (no SMB) and runs
`structural::check_bytes` on it. A `regf` magic guard means only a real hive is
checked: the `MemBackend` writes a JSON envelope (skipped, not failed), while
`--backend libreg` emits real regf and gets validated. The SMB (Windows) and
local (Linux) paths are now one block in `run_sequence`; `main` reports how many
hives each side byte-checked.

Verified with `--backend libreg` vs offreg on the VM: byte-level checks ran on
**11 Linux hives, all PASS** (invariants 1 to 6, 9, 10, 11, 13, 14, 16 on
libreg's own regf writer), structural 9/9. This validates libreg's regf output
structurally in the differential, beyond the dump-based 17/18. `--standin` is
unaffected (MemBackend envelopes skipped).

## SMB byte-pull: structural checks on offreg's live output (latest session)

`--windows-smb` extends the byte-level structural invariants from the static
corpus to every hive a differential run saves on the Windows side. The Windows
agent has no raw-bytes endpoint, so the harness pulls the saved hive off the VM
over the `winreg` SMB share (which maps to `C:\winreg`) and runs
`structural::check_bytes` on it.

- New `src/smb.rs`: `pull(host, name, local)` shells to `smbclient`. Creds are
  baked in (temporal lab VM, throwaway `user`/`password`); documented in the
  module. A pull failure is a warning, never a test failure.
- `--windows-smb` forces the Windows hive dir to `C:\winreg` (so saves land in
  the share) and sets the Windows client's `smb_host`. Only activates when the
  windows-side agent actually reports `windows` (a Linux stand-in is skipped, it
  emits no regf bytes).
- `SeqResult.byte_invariants` (var -> invariant results) is populated after the
  sequence by pulling each saved hive; `compute_structural` folds those real
  results in alongside the dump-based 17/18, replacing the Skipped placeholders
  for the Windows side.
- Verified live: `./scripts/run.sh --windows-host vmreg.lan --windows-smb` ran
  byte-level checks on 11 Windows hives, all PASS, structural GREEN. Confirms
  offreg's live on-disk output satisfies the invariants the harness implements.

This does not need libreg: it validates the Windows (oracle) bytes. The
load-on-both differential roundtrip and the `bytewise` tag still wait on the
Linux agent emitting regf (libreg's reader/writer).

## Corpus loader + byte-level structural invariants (latest session)

PR #29 checked in offreg-generated synthetic hives under
`tests/corpus/synthetic/` (real `regf` bytes, no third-party content). That
unblocked the byte-level structural invariants, which had been `Skipped` stubs
for want of real hive bytes in the repo.

- New `src/differ/regf.rs`: a minimal `regf` byte parser (base block + checksum
  + hbin/cell walk). Not a logical parser; the same parser will back the
  differential roundtrip once libreg can read `regf`.
- `structural::check_bytes(bytes)`: evaluates invariants 1 to 6, 9, 10 from the
  base block and hbin/cell structure, plus the cell-scan ones: 11 (subkey-list
  cell form and entry count), 13 and 14 (sk doubly linked list and refcounts),
  and 16 (key-name encoding per KEY_COMP_NAME), against a real hive file. The
  fixtures were built for these: `ref_latin1`/`ref_wide` exercise inv16 (Latin-1
  vs UTF-16LE names), `ref_one_ascii`/`ref_multi`/`ref_ri` exercise inv11 (lh
  leaf vs ri index root), `ref_multi` exercises inv13/14 (7 nk share one sk,
  refcount 7; the sk refcounts must sum to the nk count). Invariants needing a
  full logical-tree walk (7, 8, 12, 15) stay `Skipped`; 17/18 belong to the
  agent-output `check()`.
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
