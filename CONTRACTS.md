# libreg Contracts

This file is the single source of truth for interfaces between components.
All agents read this file. Only the spec agent writes to it.
Changes require a PR labeled `contracts` and a version bump.

**Current version: 0.1.8**

## Versioning

Contracts follow semver. Implementation agents pin to a minor version.

- PATCH: clarifications, typo fixes, no wire/format change
- MINOR: additive changes (new endpoints, new optional fields)
- MAJOR: breaking changes

Bumping requires updating `version` in agent handshakes and in the harness
config. The harness refuses to run if Linux and Windows agents report
different major versions.

## Component Map

```
libreg          Linux-side library, layered (format/allocator/logical/log/api)
agents/linux    HTTP server wrapping libreg, mirror of Windows agent
agents/windows  HTTP server wrapping offreg.dll on Windows
tests/harness   Driver that exercises both agents and runs the differ
tests/fuzz      Operation/data/boundary fuzzers
tests/corpus    Known-good hives from real Windows systems
```

## Agent HTTP Protocol

Both agents implement the same protocol. The harness treats them
interchangeably.

### Transport

- HTTP/1.1 over TCP
- JSON request and response bodies, `Content-Type: application/json`
- Reads use GET and writes use POST. Both carry their parameters in the JSON
  request body, never the query string. Read requests therefore carry a GET
  body; this is intentional for the closed harness transport (see ADR 0001).
- Default ports: Linux agent 7878, Windows agent 7879
- All endpoints return `{ "ok": bool, "error": null | string, "data": ... }`
- Errors include a stable `code` field for programmatic matching

### Handshake

```
GET /version
-> { "ok": true, "data": {
     "agent": "linux" | "windows",
     "protocol": "0.1.0",
     "backend": "libreg-0.1.0" | "offreg-10.0.22621" }}
```

The harness calls this first on both agents and aborts on mismatch.

### Hive lifecycle

```
POST /hive/create   { "path": "/tmp/test.hiv" }
-> { "ok": true, "data": { "handle": "h_abc123" }}

POST /hive/load     { "path": "/tmp/test.hiv" }
-> { "ok": true, "data": { "handle": "h_abc123" }}

POST /hive/save     { "handle": "h_abc123" }
-> { "ok": true, "data": { "bytes_written": 8192 }}

POST /hive/close    { "handle": "h_abc123" }
-> { "ok": true, "data": {}}
```

Handles are opaque strings. Both agents must accept any string the other
emits without parsing it.

### Key operations

```
POST /key/create    { "handle", "path": "Software\\Foo\\Bar" }
POST /key/delete    { "handle", "path": "Software\\Foo\\Bar", "recursive": false }
POST /key/rename    { "handle", "path", "new_name" }
GET  /key/list      { "handle", "path" }
                    -> { "data": { "subkeys": [...], "values": [...] }}
GET  /key/info      { "handle", "path" }
                    -> { "data": { "last_write": "2026-01-15T12:00:00Z",
                                   "class_name": null,
                                   "subkey_count": 3,
                                   "value_count": 5 }}
```

Path separator is `\\` (escaped backslash in JSON, literal backslash in path).
Paths never start with a separator. Empty string `""` means the hive root.

`/key/create` MUST create every missing component along `path`, not only the
leaf (RegCreateKeyEx semantics). Existing intermediate components are reused,
not an error. It MUST return `KEY_EXISTS` only when the final (leaf)
component already exists; a create that merely materializes missing
intermediates and a new leaf succeeds. offreg's `ORCreateKey` does not create
intermediates on its own, so the Windows agent creates each level in turn to
honor this. Settled and green on the live VM (harness `deep_key_create` and
`key_create_existing_is_error`).

`/key/rename` MUST preserve the renamed key's values, class name, security,
and its entire subkey subtree (names, values, security). It MAY update the
renamed key's own `last_write`. Because the Windows oracle has no native
rename and emulates it by create plus subtree copy plus delete, copied
descendants receive fresh timestamps; the oracle therefore cannot preserve
descendant `last_write`. For this reason the harness EXCLUDES `last_write`
from semantic comparison for the renamed key and every key beneath it. The
library MAY still preserve descendant timestamps natively; that is correct
but not asserted by the `semantic` tag.

### Value operations

```
POST /value/set     { "handle", "key", "name", "type", "data" }
POST /value/delete  { "handle", "key", "name" }
GET  /value/get     { "handle", "key", "name" }
                    -> { "data": { "type", "data" }}
```

Value types use Windows constants by name:

| Type             | JSON `data` representation           |
|------------------|--------------------------------------|
| REG_NONE         | null                                 |
| REG_SZ           | string                               |
| REG_EXPAND_SZ    | string                               |
| REG_BINARY       | base64 string                        |
| REG_DWORD        | integer (little-endian semantics)    |
| REG_DWORD_BE     | integer (big-endian semantics)       |
| REG_LINK         | string                               |
| REG_MULTI_SZ     | array of strings                     |
| REG_QWORD        | integer (sent as string if > 2^53)   |
| REG_RESOURCE_LIST etc. | base64 string (treat as opaque)|

Default value is name `""` (empty string), not `"(Default)"`.

### Security

```
GET  /key/security  { "handle", "path" }
                    -> { "data": { "sddl": "O:BAG:BAD:..." }}
POST /key/security  { "handle", "path", "sddl": "..." }
```

Read and write are distinguished by HTTP method, not by request body:
`GET /key/security` reads (no `sddl` in the request) and `POST /key/security`
writes (the `sddl` field is REQUIRED on POST). Agents MUST NOT infer the
operation from the presence of the `sddl` field.

Security descriptors transit as SDDL strings. Agents are responsible for
converting to/from the binary form. The harness compares both SDDL and
canonical binary form.

For comparison the SDDL is normalized to the owner, group, and DACL
components (`O:`, `G:`, `D:`). The SACL (`S:`) is compared only when BOTH
agents report one: offline hives do not always expose a readable SACL and
offreg may omit it, so a one-sided SACL is not a semantic difference. See
`docs/adr/0003-sddl-security.md` for the normalization rules and rationale.

A key created via `POST /key/create` without an explicit descriptor (no
`POST /key/security` has run against it) MUST carry this default, observed
from offreg (offreg-10.0.22621, freshly created hive) and ratified here as
the contract:

```
O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)
```

That is owner and group Administrators (`BA`), and a DACL granting SYSTEM
(`SY`) and Administrators (`BA`) full control (`KA`) plus Everyone (`WD`) and
Restricted Code (`RC`) read (`KR`), all container-inheritable (`CI`). Because
the default lives in the owner/group/DACL triple, it IS asserted by the
`semantic` tag under the normalization above (it is not excluded the way
`last_write` is). An explicit `POST /key/security` replaces the default.

### Diagnostics

```
GET /hive/dump      { "handle" }
                    -> { "data": { "canonical_json": {...} }}
GET /hive/checksum  { "handle" }
                    -> { "data": { "sha256_file": "...",
                                   "sha256_canonical": "..." }}
GET /hive/validate  { "handle" }
                    -> { "data": { "valid": bool,
                                   "errors": [...],
                                   "warnings": [...] }}
```

The canonical JSON form is defined below and is what semantic diffs compare.

### Test-mode endpoints

These exist only to drive the `recovery` tag and are not part of the
production protocol. The Linux/libreg agent implements them; the Windows
(offreg) agent does not (offreg writes no logs, so it has nothing to
recover). The harness calls them only against the Linux agent. See ADR 0004
for the rationale.

```
POST /test/crash_save  { "handle", "point" }
     point in { "after_log_before_primary", "after_first_log", "after_primary" }
                    -> { "data": { "bytes_written": int,
                                   "crashed_at": "<point>" }}
```

`crash_save` performs a recoverable save truncated at `point`, writing to the
hive's already-bound path (and its `.LOG1`/`.LOG2` siblings), then stops,
leaving the on-disk primary and logs mid-save so the next `/hive/load` of
that path exercises recovery. `crashed_at` echoes the honored point. The
crash points:

- `after_log_before_primary`: dirty pages are journaled and fsynced; the
  primary is not committed (`primary != secondary` sequence). The next load
  detects the dirty hive, replays the log, and recovers `baseline + M`.
- `after_first_log`: only the older-generation log is written; exercises
  log-generation selection on load. Recovers `baseline + M`. May be
  observationally identical to the previous point when one generation is in
  play.
- `after_primary`: fully committed (clean hive); reload needs no recovery.

An unknown `point` is a `BAD_REQUEST` (no dedicated code). The handle may be
consumed by the call; the harness closes it and reloads by path. The recovery
oracle is the pre-crash canonical dump of the same hive (a libreg-internal
property), not a comparison against the Windows agent.

## Canonical JSON Form

Both agents must serialize hives to this exact structure for semantic
comparison. Field order matters (use sorted keys). Whitespace does not
(harness re-parses before diffing).

```json
{
  "format_version": "0.1.0",
  "root": {
    "name": "",
    "last_write": "ISO8601",
    "class_name": null,
    "security": { "sddl": "..." },
    "values": [
      { "name": "", "type": "REG_SZ", "data": "..." }
    ],
    "subkeys": [
      { "name": "Software", ... recursive ... }
    ]
  }
}
```

Rules:

- `subkeys` and `values` arrays are sorted by `name` using a
  case-insensitive Unicode ordinal comparison (compare names uppercased,
  per Windows semantics); the original casing is preserved in the JSON.
  Both agents MUST use this same comparator or semantic diffs will fire on
  ordering alone. Sibling names are case-insensitive-unique in a hive, so
  no casing tiebreak is reachable in valid data.
- `last_write` is ISO 8601 UTC with second precision; nanoseconds are
  dropped during canonicalization to allow cross-platform comparison
- `class_name` is null when absent, never an empty string
- Binary data is base64 with no line breaks, no padding stripped

## Hive File Format Invariants

These invariants must hold for any hive produced by libreg or offreg
after a successful save. The harness checks all of these. See
`docs/hive-format.md` for the field-level layout each invariant refers to.
"dword X" below means the 4-byte little-endian value at byte offset X, not
the Xth dword.

1. Base block magic = `regf`
2. Base block primary sequence = secondary sequence (clean hive)
3. Base block checksum matches stored value: XOR of the first 127 dwords
   (bytes 0 through 507), with the quirks 0 stored as 1 and 0xFFFFFFFF
   stored as 0xFFFFFFFE
4. Hive bins data size (base block dword at offset 40) matches the actual
   total of all hbins; this excludes the 4096-byte base block
5. Every hbin starts with magic `hbin`, has size multiple of 4096
6. Every cell has size != 0; sign indicates allocated (-) or free (+)
7. Allocated cells form a tree rooted at root cell offset (base block dword 36)
8. Free cells are tracked in the allocator's free list (implementation defined)
9. Sum of cell sizes within an hbin equals hbin size minus the 32-byte header
10. No cell crosses an hbin boundary
11. Subkey list cell types follow promotion: an lf/lh leaf holds at most
    507 entries; a key with more than 507 subkeys uses an ri index root over
    multiple leaves; li only when loading old hives. (Empirical, from offreg
    via tests/corpus/synthetic/ref_ri.hiv: 1100 subkeys form an ri over
    three lh leaves of 507, 507, and 86. The earlier "1015" was wrong.)
12. Big-data cells (db) only for values whose data exceeds 16344 bytes
13. Security cells form a doubly linked list with reference counts
14. Reference counts on sk cells are accurate (no orphans, no dangling)
15. Class name strings, if present, are UTF-16LE
16. Key names are UTF-16LE if the nk flag KEY_COMP_NAME (0x0020) is clear,
    ASCII (Latin-1) if set
17. Subkey lists are sorted; binary search is valid
18. Transaction log files (.LOG1, .LOG2) are either absent (clean hive)
    or contain a valid recovery sequence

## Transaction Log Behavior

For v1.5 hives (Windows 8.1+), libreg writes dual logs:

- Dirty pages are written to whichever log has the older sequence number
- The other log retains the previous-generation entries until commit
- On crash recovery, both logs are inspected and the most recent
  consistent set is applied

Agents must save with logs by default. The harness simulates crashes
between log write and primary write via the `POST /test/crash_save`
test-mode endpoint (see "Test-mode endpoints"), which the Linux agent
implements and the Windows agent does not.

## Test Categories

Tests are tagged with one of:

- `semantic` - canonical JSON equality after operation
- `structural` - invariants 1-18 hold on both outputs
- `bytewise` - exact byte equality (only when allocator behavior matches)
- `roundtrip` - load corpus hive, save, re-load, compare to original
- `recovery` - crash injection, log replay correctness
- `fuzz` - generated operation sequences

The harness reports per-tag pass rates. Bytewise failures with semantic
pass are warnings, not errors.

## Error Codes

| Code                  | Meaning                                         |
|-----------------------|-------------------------------------------------|
| HIVE_NOT_FOUND        | path does not exist on agent's filesystem       |
| HIVE_CORRUPT          | base block or hbin chain invalid                |
| HANDLE_INVALID        | handle string not known to this agent           |
| KEY_NOT_FOUND         | path resolution failed                          |
| KEY_EXISTS            | create called on existing path                  |
| VALUE_NOT_FOUND       | named value does not exist on key               |
| TYPE_MISMATCH         | data shape does not match declared type         |
| ACCESS_DENIED         | security descriptor blocks operation            |
| LOG_CORRUPT           | transaction log replay failed                   |
| KEY_HAS_CHILDREN      | non-recursive delete of a key that has subkeys   |
| BAD_REQUEST           | request is malformed; caller error, not agent bug |
| INTERNAL              | bug; include stack/trace in error string        |

`BAD_REQUEST` covers a structurally malformed request: a body that is not
valid JSON, a missing or wrong-typed REQUIRED field, or an unknown constant
(e.g. an unrecognized value-type name or a path that starts with a
separator). It is the caller's error. `INTERNAL` is reserved for the agent
failing to process a well-formed request, which is an agent bug; the harness
relies on this split to tell test mistakes from real defects. `BAD_REQUEST`
is distinct from `TYPE_MISMATCH`: the latter applies when a well-formed
`/value/set` carries `data` that does not fit the declared REG type.

## What This Document Does Not Cover

- Internal data structures of libreg (each layer's CLAUDE.md owns those)
- Build systems, packaging, CI (see top-level README.md when written)
- Performance targets (deferred to v0.2)
- Multi-user / concurrent access (libreg is single-writer for v0.1)

## Change Log

- 0.1.8 (minor): add the `POST /test/crash_save` test-mode endpoint (Linux
  agent only; Windows does not implement it) that drives the `recovery` tag,
  now that the implementation has landed (libreg log recovery, the agent
  endpoint, and the harness recovery runner are all merged; issue #61, ADR
  0004). Additive and test-only; no change to the production protocol.
- 0.1.7 (patch): correct invariant 11's subkey-list promotion threshold from
  the approximate "1015" to 507, the per-leaf cap offreg actually uses
  (verified against tests/corpus/synthetic/ref_ri.hiv: 1100 subkeys form an
  ri over lh leaves of 507, 507, 86). Documentation only; no wire change.
- 0.1.6 (patch): confirm the read-request transport: reads are GET and carry
  their parameters in the JSON request body, not the query string (so GET
  requests carry a body). Documents existing behavior; rationale and the
  GET-body caveat added to ADR 0001. No wire change.
- 0.1.5 (patch): clarify `/key/create` semantics: creates all missing
  intermediate components (RegCreateKeyEx-style), reuses existing
  intermediates, and returns `KEY_EXISTS` only when the leaf already exists.
  Documents existing behavior already green on the live VM; no wire change.
- 0.1.4 (minor): add error code `BAD_REQUEST` for a malformed request
  (invalid JSON, missing/wrong-typed required field, unknown constant);
  previously surfaced as `INTERNAL`. Lets the harness tell caller/test
  errors from agent bugs. Additive only; no breaking change.
- 0.1.3 (minor): ratify the default security descriptor for a key created
  without an explicit one (offreg-observed value, see the Security section
  and issue #11). It is asserted by the `semantic` tag via the O/G/D
  normalization. Additive only; no breaking change.
- 0.1.2 (minor): add error code `KEY_HAS_CHILDREN` (non-recursive delete of
  a key with subkeys; was surfaced as `INTERNAL`). Clarify `/key/security`
  read vs write is by HTTP method (GET vs POST), not by `sddl` presence.
  Define canonical SDDL normalization (O/G/D always, SACL only when both
  sides report one; see ADR 0003). Specify `/key/rename` preserves the
  subtree and that the harness excludes `last_write` under a renamed path
  from semantic comparison. Sharpen the canonical sort comparator
  (case-insensitive Unicode ordinal). Additive only; no breaking change.
- 0.1.1 (patch): clarifications only, no wire or format change. Invariant 3
  checksum computation made precise (127 dwords / bytes 0..507, plus the
  0 and 0xFFFFFFFF quirks). Invariant 4 reworded to "hive bins data size"
  and noted it excludes the base block. Invariant 9 states the 32-byte hbin
  header. Invariant 16 typo fixed: KEY_COMP_NAME, not VALUE_COMP_NAME.
  Added a pointer to docs/hive-format.md and clarified "dword X" notation.
- 0.1.0 (initial): defines protocol, canonical form, hive invariants
