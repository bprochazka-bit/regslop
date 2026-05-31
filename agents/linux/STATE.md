# Linux Agent: STATE

Last updated: 2026-05-30

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
  creation, ACCESS_DENIED for non-empty delete, INTERNAL for bad requests,
  default SDDL, GET-with-body transport). The differ will flag any that
  disagree with offreg once the Windows agent exists.
- Deterministic fixed `last_write` (`2026-01-01T00:00:00Z`) so canonical output
  is reproducible; the harness ignores timestamps by default anyway.

## What I would do next

1. Add `LibregBackend` once `libreg::api` is callable; wire `--backend libreg`.
2. Expose a raw-bytes accessor (`/hive/raw` or extend `/hive/checksum`) so the
   harness structural checker can evaluate invariants 1 to 18 on real hives.
3. Resolve the spec-questions, especially the default security descriptor,
   which currently guarantees a `security`/`bytewise` divergence.
