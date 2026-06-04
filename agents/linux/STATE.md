# Linux Agent: STATE

Last updated: 2026-06-04

## FfiBackend: the C ABI as a Backend, for the FFI acceptance (issue #112)

`src/ffi_backend.rs` adds `FfiBackend`, a third `Backend` (alongside Mem and
Libreg) that drives libreg's Layer 4 C ABI (`libreg::api::*`, the cdylib surface,
#106) instead of the rlib `logical::Hive`. The agents link libreg by path, so the
`extern "C"` entry points are called directly from Rust (every `unsafe` block is a
documented FFI call into that boundary, with its panic guard and global handle
registry). Selected with `--backend ffi`.

It reuses the agent's existing `valuec` (value codec), `sddl` (binary <-> SDDL),
and `canonical` (dump), so its canonical form matches `LibregBackend`'s by
construction; any divergence is then a real C ABI surface bug. The dump walks the
hive through the C ABI enumeration primitives (`list_subkeys` / `list_values` /
`value_get` / `key_security_get`), so those get exercised, not just the mutations.
Handles are the C ABI's `u64` tokens stringified; `last_write` is fixed and
`class_name` null, matching the rlib backend's dump (the differ ignores
`last_write`). `crash_save` is unsupported (the C ABI save writes a clean primary
only; recovery stays on the libreg backend).

Acceptance: the standard two-agent differential with `--backend libreg` vs
`--backend ffi` is **green** (semantic 17/17, structural 10/10, bytewise 2/2,
roundtrip 8/8) over the op-sequence corpus and all five synthetic reference hives.
Run it with `scripts/run.sh --ffi`.

**One layering note (flagged for the binding/spec):** the C ABI's
`libreg_key_create` is lenient on malformed paths (a leading separator), while the
agent enforces the contract's BAD_REQUEST via `check_path`, as all its backends
do. `FfiBackend.key_create` does the same `split_path` validation (needed for
semantic equality, else it creates a spurious key). A direct C ABI consumer (the
Python binding, #108) must validate paths itself.

## SDDL SID-alias table completed (issue #102)

The operation fuzzer (semantic axis, unblocked by #94) found that `set_key_security`
rejected standard SDDL SID abbreviations as `BAD_REQUEST "unknown SID or alias"`.
The alias table lives here in `src/sddl.rs` (the agent owns SDDL <-> binary, ADR
0003), not in libreg as the issue first guessed. Refactored the two ad-hoc match
arms into one `SID_ALIASES` table used in both directions (so round-trips emit the
same token offreg does), and added the standard absolute aliases: AU, AN, IU, NU,
SU, CO, CG, WR, PU, AO, BG, BO, ER (alongside the existing SY, BA, BU, WD, RC).

Domain-relative `LA`/`LG` (local admin/guest, RID 500/501) are intentionally NOT
added: they expand to `S-1-5-21-<machine>-50x`, with no fixed value offline (Win32
`ConvertStringSidToSid` rejects them standalone too), so they fall through to the
`S-1-...` path rather than getting a fabricated SID that would not round-trip
against offreg. Flagged for the fuzzer/spec to confirm against offreg or exclude.
Verified: all 18 absolute aliases accepted by the live agent; unit tests round-trip
each; LA/LG still rejected by design.

## Recovery: /test/crash_save + log-backed save/load (ADR 0004, issue #61)

libreg shipped `log::{crash_save_plan, recover, CrashPoint, Slot}`, so the
LibregBackend now goes through the transaction-log path:

- `hive_save` -> `crash_save_plan(AfterPrimary)`: journals the new generation to
  the alternating log slot, then commits the primary (advancing the
  generation). Writes P, P.LOG1, P.LOG2.
- `hive_load` -> `recover(P, P.LOG1, P.LOG2)`: picks the highest valid
  generation and replays a log if the primary is stale (a clean hive recovers
  to itself).
- New test-only `POST /test/crash_save { handle, point }` -> `crash_save_plan(point)`
  with point in {after_first_log, after_log_before_primary, after_primary}.
  `apply_plan` writes each (Slot, bytes) to the primary / .LOG1 / .LOG2; a crash
  point omits the primary, leaving the on-disk state mid-save. MemBackend
  returns "only the libreg backend supports it" (no logs).

Verified manually for all three points: build -> save -> mutate M ->
crash_save(point) -> close -> load -> dump recovers baseline+M (the
logged-but-not-committed write survives). The existing libreg-vs-offreg
differential stays GREEN (17/17 semantic, 10/10 structural, 8/8 roundtrip) with
the new save/load path. /test/crash_save is not yet in CONTRACTS; the spec agent
adds it (MINOR, Linux-only) once the harness drives `recovery` green (ADR 0004).

## LibregBackend path validation (latest)

The new BAD_REQUEST coverage test caught that `LibregBackend` accepted a
leading-separator path (`\Foo`): it delegated straight to libreg, whose path
splitter filters empty components and so silently strips the separator, while
the contract (and the MemBackend) require BAD_REQUEST. Added a `check_path`
helper (reusing `model::Key::split_path`) called by `key_create` and
`require_key`, so every path-taking op validates at the agent edge before
touching libreg. libreg-vs-offreg back to GREEN (16/16 with the new tests).

## LibregBackend: GREEN vs offreg, 14/14 semantic (latest)

The `LibregBackend` (`--backend libreg`, default stays `mem`) now wraps libreg's
`logical::Hive` for the full implemented surface: hive lifecycle, key
create/list/info/delete/rename, value set/get/delete, and **security get/set**.
The canonical dump walks the logical tree into `model::Key` and reuses
`canonical`.

- `src/valuec.rs`: JSON <-> (REG type code, raw bytes) codec, mirroring
  agents/windows/src/valuec.rs (BAD_REQUEST for an unknown type name,
  TYPE_MISMATCH for a wrong shape).
- `src/sddl.rs`: SDDL <-> binary security-descriptor conversion (ADR 0003, the
  agent owns it). Built on libreg's `format::security_descriptor` types
  (`SecurityDescriptor`/`Sid`/`Ace`/`Acl`), so `security_get` parses libreg's
  binary descriptor to SDDL and `security_set` parses SDDL to binary for
  `set_key_security`. Well-known SID aliases (SY/BA/WD/RC/BU) and key-rights
  tokens (KA/KR) offreg emits are recognized so the harness comparator matches;
  others fall back to `S-1-...` / `0x...`.
- `key_rename` is emulated agent-side (create destination, deep-copy the
  subtree, delete source), like the Windows agent, since libreg has no native
  rename. KEY_EXISTS is enforced at the agent edge (libreg's `create_key` is
  idempotent).
- libreg grew `delete_key` (with `HasSubkeys` -> KEY_HAS_CHILDREN),
  `delete_value`, and `set_key_security` over the session; all wired.

**Live libreg-vs-offreg differential** (`--backend libreg` vs offreg on the VM):
**semantic 14/14, structural 9/9, roundtrip 7/7, bytewise 2/2 (warnings).**
GREEN across the whole suite on real `regf` bytes. The only remaining deltas are
the two `bytewise` allocator-layout warnings (expected; the harness treats them
as warnings, not failures). libreg now matches the offreg oracle for the entire
implemented operation set.

Not yet exercised against offreg: big-data values (no test sets one above 16344
bytes), and the recovery tag (blocked on libreg's log path + the ADR 0004 hook).

## CONTRACTS 0.1.3 to 0.1.6 conformance (latest session)

Caught up after several spec PRs merged while this subtree sat at 0.1.2.

- **0.1.4 `BAD_REQUEST`** (new code). The agent now returns it for a malformed
  request: invalid JSON, a missing or wrong-typed required field, an unknown
  endpoint, an unknown value-type constant, and a leading-separator path. Done
  mostly by pointing the existing `AgentError::bad_request` helper at the new
  `Code::BadRequest` (was `Code::Internal`); plus the invalid-JSON path in
  `main.rs` and the unknown-value-type path in `backend.rs` (was
  `TYPE_MISMATCH`). `TYPE_MISMATCH` is now strictly a well-formed value whose
  data does not fit the declared type. 7 new unit tests. NOTE: the Windows agent
  still returns `INTERNAL`/`TYPE_MISMATCH` for these; their conformance is
  pending (no differential test exercises it yet, so the VM run stays green).
- **0.1.3 default security descriptor**: ratified value matches the agent's
  `DEFAULT_SDDL` already (set last session); no change. Issue #11 closed.
- **0.1.5 `/key/create`** intermediate-key semantics and **0.1.6** GET-body
  read transport: both document existing agent behavior; no change, confirmed
  green on the VM.
- Re-ran the live VM differential: GREEN (semantic 11/11, structural 4/4,
  bytewise 2/2 warnings, roundtrip 7/7).

All of `agents/linux/spec-questions.md` is now resolved through 0.1.6.

## First live VM differential run (2026-05-31)

Validated against the real offreg oracle on the VM. Two Linux-agent fixes the
run surfaced, both now GREEN against the VM:

- **REG_QWORD encoding.** Was emitting a sub-2^53 QWORD as a string; CONTRACTS
  says integer (string only above 2^53). Added `canonicalize_value` in
  `backend.rs`, applied at `value_set`, mirroring the Windows `v > (1<<53)` rule.
- **Default security descriptor.** The placeholder default (2 ACEs) diverged
  from offreg's real 4-ACE default on every key. Captured offreg's default live
  and set `model::DEFAULT_SDDL` to match:
  `O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)`. This is a
  stand-in default pending spec ratification (see `spec-questions.md` item 4);
  the real libreg backend must produce the same descriptor.

## CONTRACTS 0.1.2 conformance (this session)

Brought the Linux agent up to CONTRACTS 0.1.2, mirroring the Windows agent
(commit cf73eef):

- `/key/security` now routes read vs write by HTTP method (GET reads, POST
  writes and requires `sddl`), not by the presence of the `sddl` field. The
  method is threaded `main.rs -> handlers::dispatch -> security::dispatch`.
- Non-recursive delete of a key with subkeys returns the new `KEY_HAS_CHILDREN`
  code (was `ACCESS_DENIED`). Added `Code::KeyHasChildren` to the closed set.
- Canonical sort and `/key/list` order now use a case-insensitive Unicode
  ordinal comparison (names uppercased), matching the Windows agent's
  `to_uppercase()` comparator so the two outputs agree on ordering.
- `protocol`/`format_version` stay at "0.1.0": the 0.1.1/0.1.2 changes were
  additive clarifications plus one error code, not a wire-shape change, and the
  Windows agent also reports "0.1.0". Bumping would have broken the
  byte-for-byte canonical match.

## What is done

- Full HTTP agent implementing every endpoint in CONTRACTS.md "Agent HTTP
  Protocol": `/version`, hive lifecycle, key ops, value ops, `/key/security`,
  and diagnostics (`/hive/dump`, `/hive/checksum`, `/hive/validate`).
- Response envelope `{ ok, error, code, data }` with the closed error-code set
  from the CONTRACTS.md table (see `src/error.rs`).
- Canonical JSON serializer (`src/canonical.rs`) matching the "Canonical JSON
  Form" section: sorted object keys (serde default), `subkeys`/`values` sorted
  case-insensitively by name with casing preserved, `class_name` null-not-empty.
- Value type validation across the full REG_* table; bad shapes return
  `TYPE_MISMATCH`.
- Backend abstraction (`src/backend.rs`, trait `Backend`). The only impl today
  is `MemBackend`, an in-memory registry model. Handlers, canonical serializer,
  and wire types are all backend-agnostic.
- Builds clean on Debian (native binary, no containers). Worker-pool server
  over `tiny_http`. Verified end to end with curl and with the harness.

## What is in progress / not done

- **No real libreg backend.** libreg has no API surface yet (empty on all
  branches), so there was nothing to link against. `MemBackend` stands in. When
  libreg's `api/` layer lands, add `LibregBackend: Backend` and select it in
  `main.rs` via a flag. No other file should need to change.
- **Save does not emit a `regf` hive.** `MemBackend::hive_save` writes a JSON
  envelope so `load` round-trips and checksums are stable. Consequently the
  `bytewise` and byte-level `structural` invariants are not exercised against
  this backend (by design; the harness reports them as n/a/skipped).
- Handlers are split per area (`handlers/{hive,key,value,security,diag}.rs`) to
  mirror the (not-yet-existing) Windows agent layout. When the Windows agent
  appears, diff file-for-file to keep symmetry.

## Assumptions I am relying on

- Provisional semantics documented in `spec-questions.md` (intermediate-key
  creation, INTERNAL for bad requests, default SDDL, GET-with-body transport).
  The non-empty-delete code is now settled as `KEY_HAS_CHILDREN` per 0.1.2. The
  differ will flag any remaining disagreement with offreg once both agents run
  against the real Windows VM.
- Deterministic fixed `last_write` (`2026-01-01T00:00:00Z`) so canonical output
  is reproducible; the harness ignores timestamps by default anyway.

## What I would do next

1. Add `LibregBackend` once `libreg::api` is callable; wire `--backend libreg`.
2. Expose a raw-bytes accessor (`/hive/raw` or extend `/hive/checksum`) so the
   harness structural checker can evaluate invariants 1 to 18 on real hives.
3. Get the default security descriptor ratified in CONTRACTS.md. It now matches
   the offreg oracle (so `semantic` is GREEN), but it is an observed value, not
   a specified one; see `spec-questions.md` item 4.
