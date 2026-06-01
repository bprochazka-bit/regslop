# Linux Agent: STATE

Last updated: 2026-06-01

## LibregBackend: values + delete, 11/14 semantic vs offreg (latest session)

The `LibregBackend` (`--backend libreg`, default stays `mem`) now wraps libreg's
`logical::Hive` for the hive lifecycle, key create/list/info/**delete**, value
**set/get/delete**, and the canonical dump (walk the logical tree into
`model::Key`, reuse `canonical`). New `src/valuec.rs` is the JSON <-> (REG type
code, raw bytes) codec, mirroring agents/windows/src/valuec.rs so both agents
emit identical canonical `data` (BAD_REQUEST for an unknown type name,
TYPE_MISMATCH for a wrong shape). libreg grew `delete_key` (with a `HasSubkeys`
error -> KEY_HAS_CHILDREN) and `delete_value` since the first slice, so those are
wired too. The agent enforces KEY_EXISTS at its edge (libreg's `create_key` is
idempotent) and reports the ratified default descriptor for every key.

**Live libreg-vs-offreg differential** (`--backend libreg` vs offreg on the VM):
**semantic 11/14, structural 9/9, bytewise 2/2 (warnings), roundtrip 5/7.**
Passing on real `regf`: lifecycle, key create/delete, all REG_* value types
round-tripping, value overwrite/delete, the read endpoints, and the error paths.
**bytewise compares two real regf implementations** (allocator divergence, a
warning). The 3 remaining semantic fails are the only gaps left:

- **key_rename** -- libreg has no rename yet (library agent). Returns INTERNAL
  "not yet supported".
- **set_and_get_sddl, security_get_reads** -- non-default security. libreg's
  `key_security` returns the binary descriptor and there is no setter, and the
  agent owns binary <-> SDDL conversion (not implemented). This is my next
  slice; until then `security_get` returns the default descriptor, which
  diverges once a custom SDDL is set.

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
