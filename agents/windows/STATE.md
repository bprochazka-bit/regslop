# Windows Agent State

Last session: 2026-05-31. Author: Windows agent developer.

## Headline (2026-05-31)

The agent is **live on the VM and confirmed running the latest build**
(offreg-10.0.22621, `vmreg.lan:7879`). The differential harness has **run GREEN
against the real Windows oracle** (harness session 2026-05-31: semantic 11/11,
structural 4/4, bytewise 2/2 warnings-only, roundtrip 7/7), so the "not yet run
through the harness" gate from the prior session is **closed**. CONTRACTS has
advanced to **0.1.7**; the agent conforms.

**Follow-up (later 2026-05-31): `BAD_REQUEST` conformance (CONTRACTS 0.1.4).**
The harness flagged that the Windows agent still returned `INTERNAL`/`HANDLE_INVALID`/
`TYPE_MISMATCH` for malformed requests where 0.1.4 requires `BAD_REQUEST`. Fixed
in `handlers/mod.rs` (`req_str`, new `req_path`, `get_hive`), `handlers/hive.rs`
(close), `main.rs` (invalid JSON), and `valuec.rs` (unknown type name): invalid
JSON, missing/wrong-typed required fields, a path with a leading separator, and
an unknown value-type name all now return `BAD_REQUEST`; a present-but-unknown
handle stays `HANDLE_INVALID`, and a data-shape mismatch stays `TYPE_MISMATCH`.
Builds clean for the gnu target, 19 unit tests pass under wine (3 new). Needs the
rebuilt exe redeployed/restarted on the VM before the harness can add the
cross-agent malformed-request negative test (the Linux side already conforms).

**Follow-up (2026-06-04): root delete/rename `ACCESS_DENIED` (CONTRACTS 0.1.13, issue #126).**
0.1.13 pins delete/rename of the hive root (empty path) to `ACCESS_DENIED`: the
root is structurally protected, so it is NOT `INTERNAL` (not a bug) and NOT
`KEY_NOT_FOUND` (the root exists). Previously the agent let these fall through to
offreg, which returns `INTERNAL` on root delete and a stale `KEY_NOT_FOUND` on
root rename. Fixed in `handlers/key.rs` with a `reject_root` guard run before any
offreg call in both `delete` and `rename`. Builds clean for the gnu target; 21
unit tests pass under wine (2 new). libreg already conforms. Needs the rebuilt exe
redeployed/restarted on the VM for the harness to confirm green on root-touching
fuzz sequences.

This session (earlier) did no agent-code changes. It used the live agent as the project's
offreg oracle to answer the outstanding corpus-gated spec questions, and added
synthetic reference hives to the corpus:

- **PR #8 (merged earlier):** rename no longer stamps a spurious SACL
  (`set_security` with `SEC_NO_SACL`). Verified live: a renamed key whose source
  has no SACL reads back with no `S:` token.
- **Issue #23 (answered, ratified):** a single-subkey create emits an `lh` leaf
  (never `lf`), allocated in the root's hbin (order nk, sk, lh, child nk); the
  child shares the root `sk` (refcount rises); root `last_write` is bumped.
  Root nk `flags=0x0020` (no 0x04 hive-entry bit).
- **Issue #22 (answered, ratified):** the `lh` name hash is
  `hash = (hash*37 + RtlUpcaseUnicodeChar(unit)) & 0xFFFFFFFF` with the **full
  Unicode** upcase table (the `Café` fixture distinguishes it from ASCII-only).
  KEY_COMP_NAME is set iff every char <= U+00FF, else UTF-16LE.
- **Issue #34 (answered -> CONTRACTS 0.1.7, docs 3.4):** an `lh`/`lf` leaf holds
  at most **507** entries (one hbin of cell space, `(4096-32-8)/8`); the 508th
  subkey promotes to an `ri` index. Leaves fill sequentially, so the Nth leaf
  appears at `507*(N-1)+1`; the docs' old "~1015" was the second split.
- **Corpus fixtures (PR #29 + PR #35, both merged):**
  `tests/corpus/synthetic/{ref_one_ascii,ref_multi,ref_latin1,ref_wide,ref_ri}.hiv`
  plus PROVENANCE.md. These are offreg-generated, content-free, and sha256-pinned.

How the oracle data was obtained (not previously documented anywhere): generate
hives via the agent saving into `C:\winreg`, pull the raw `.hiv` over the
`winreg` SMB share, and parse the regf cells offline. The agent still exposes no
raw-bytes HTTP endpoint; SMB is the byte-inspection path.

Open, not blocking and not owned by this agent:
- **Issue #40** (harness subtree): un-skip invariant 11 and add a wide-key
  differential test, gated on the **library agent** building >507-subkey keys.
- `class_name` capture: no v0.1 op sets a key class, so nothing to observe yet.

## Headline (2026-05-30, prior session)

The agent implements every endpoint in **CONTRACTS 0.1.2** (updated from 0.1.0
after the spec agent resolved all of this agent's open items), cross-compiles
cleanly to `x86_64-pc-windows-gnu` (zero warnings), and was **validated live
against real offreg.dll on the VM** (2026-05-30): every endpoint exercised end
to end, including a save/close/load/dump round trip, all REG_* value types,
rename, security read+write, recursive delete, and all error codes. Three offreg
bugs found during that validation are fixed (see quirks below).

The 0.1.2 changes (KEY_HAS_CHILDREN, method-based /key/security, sort
comparator, rename preserving class+security) are **built and unit-green but
not yet re-validated live**: needs a redeploy of the new exe to the VM.

**Still not run through the differential harness.** Per "the harness is the
judge", the remaining gate is a green `semantic` tag from a Linux-vs-Windows
harness run. The agent is ready for the harness agent to come up.

## Blocker history: VM unreachable at session start

`vmreg.lan` initially did not resolve from the build box, and offreg.dll is not
present here (it ships with the Windows ADK, Windows-only). It later resolved
(an `/etc/hosts` entry) and the VM came up, enabling live validation. Anything
that does not call offreg was also exercised
under wine instead. Next session, with VM access (queue the shared VM), the
first job is to run the harness and close the gap.

## Endpoints implemented

| Endpoint            | Implemented | Locally checked | offreg-validated |
|---------------------|-------------|-----------------|------------------|
| GET /version        | yes         | yes (wine boot) | n/a              |
| /hive/create        | yes         | no              | pending VM       |
| /hive/load          | yes         | no              | pending VM       |
| /hive/save          | yes         | no              | pending VM       |
| /hive/close         | yes         | no              | pending VM       |
| /hive/checksum      | yes         | no              | pending VM       |
| /hive/dump          | yes         | codec unit-tested | pending VM     |
| /hive/validate      | yes         | no              | pending VM       |
| /key/create         | yes         | no              | pending VM       |
| /key/delete         | yes         | no              | pending VM       |
| /key/rename         | yes (emul.) | no              | pending VM       |
| /key/list           | yes         | no              | pending VM       |
| /key/info           | yes         | no              | pending VM       |
| /value/set          | yes         | codec unit-tested | pending VM     |
| /value/get          | yes         | codec unit-tested | pending VM     |
| /value/delete       | yes         | no              | pending VM       |
| GET/POST /key/security | yes      | no              | pending VM       |

"Locally checked" = exercised on this Linux box (wine boot test for startup;
unit tests for the value codec, multi_sz, and time conversions). The HTTP
dispatch and offreg-backed paths cannot run without offreg.dll.

## offreg functions wrapped (dynamic-loaded)

OROpenHive, ORCreateHive, ORCloseHive, ORSaveHive, OROpenKey, ORCreateKey,
ORCloseKey, ORDeleteKey, ORDeleteValue, ORSetValue, ORGetValue, OREnumKey,
OREnumValue, **ORQueryInfoKey**, ORGetKeySecurity, ORSetKeySecurity. All
resolved at startup from offreg.dll; a missing export fails fast with a clear
message.

**Confirmed against a real ADK install (2026-05-30):** loading the agent on the
VM resolved every export above in order up through ORQueryInfoKey, so those
names are correct on real offreg.dll. ORGetKeySecurity/ORSetKeySecurity come
after and are standard offreg exports but were not yet observed resolving (the
run stopped earlier on the bug below); confirm on the next run.

## offreg quirks discovered

All found 2026-05-30 by validating the live agent against real offreg on the VM.

- **There is no `ORGetKeyInfo` export.** The key-info function is
  **`ORQueryInfoKey`** (it mirrors `RegQueryInfoKey`; same signature). Initial
  bindings used the wrong name and failed fast at startup. Fixed.
- **`ORSaveHive` does not overwrite.** If the target file exists it returns
  ERROR_FILE_EXISTS (80). `Hive::save` now deletes the target first. (offreg
  writes no log files, so the .hiv is the only artifact to clear.)
- **`ORCreateKey` does not create intermediate keys** (unlike RegCreateKeyEx).
  A multi-level path with a missing parent fails with ERROR_FILE_NOT_FOUND (2)
  and creates nothing. `Key::create` now creates each level in turn.
- **SDDL conversion returns trailing null padding.**
  ConvertSecurityDescriptorToStringSecurityDescriptorW reported a length that
  included extra null chars, so the dumped SDDL had trailing ` `s.
  `sd_to_sddl` now cuts at the first null. (Would have broken every security
  semantic diff against libreg.)

## Tests run this session

`cargo test --release --target x86_64-pc-windows-gnu` with
`CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine`: 16 passed, 0 failed.
Covered: REG_SZ/EXPAND_SZ/LINK round trips, REG_DWORD/REG_DWORD_BE endianness,
REG_QWORD (number vs string above 2^53), REG_MULTI_SZ (incl. empty), REG_BINARY
base64, REG_NONE, type-mismatch detection, multi_sz double-null framing, wide
string round trips, and FILETIME/Unix-to-ISO8601 conversion (epoch, leap day,
known timestamps).

## Assumptions I am relying on (verify against real offreg + harness)

1. **ORDeleteKey is not recursive.** `delete_key` deletes children depth-first
   itself; non-recursive delete of a key with children is refused. If offreg's
   ORDeleteKey actually deletes recursively, the recursive path still works but
   the pre-check is redundant. Confirm on the VM.
2. **ORGetValue/ORGetKeyInfo size-query convention** (null buffer returns the
   required size, possibly via ERROR_MORE_DATA / ERROR_INSUFFICIENT_BUFFER).
   The two-call pattern handles SUCCESS, MORE_DATA, and INSUFFICIENT_BUFFER on
   the size query. Verify offreg's exact return on a zero-length value.
3. **OREnumKey/OREnumValue length units**: name lengths in chars excluding the
   null; data length in bytes. Buffers sized from ORGetKeyInfo max-lengths + 1.
4. **OROpenKey with an empty path**: handled without an offreg call (root is
   returned as a non-owning reference), sidestepping the question of whether
   offreg accepts a null/empty subkey.
5. **Hive format version**: ORSaveHive is called with OS 6.3 by default to get
   v1.5 hives. Configurable via `--hive-os-major/--hive-os-minor`. Confirm 6.3
   actually yields the minor version the harness's structural checks expect.
6. **SACL readability**: canonical dump, /key/security, and rename copy try
   OWNER|GROUP|DACL|SACL first, then fall back to OWNER|GROUP|DACL if the SACL
   is not readable on an offline hive. CONTRACTS 0.1.2 / ADR 0003 make a
   one-sided SACL a warning, not a semantic failure, so this is safe.
7. **Canonical key-name sort** is now case-insensitive Unicode ordinal with
   names uppercased (CONTRACTS 0.1.2). The Linux agent must use the identical
   comparator or semantic diffs fire on ordering alone.

## Spec items (all resolved in CONTRACTS 0.1.2, agent updated to match)

The spec agent resolved every open item in CONTRACTS 0.1.2 + ADR 0003. This
agent now conforms:

- **`KEY_HAS_CHILDREN` error code added.** Non-recursive delete of a key with
  subkeys now returns `KEY_HAS_CHILDREN` (was `INTERNAL`).
- **`/key/security` read vs write is by HTTP method, not `sddl` presence.**
  Dispatch now routes GET to read and POST to write; POST requires `sddl`.
  (The HTTP method is threaded from main through `handlers::dispatch`.)
- **`/key/rename` preserves class, security, values, and the whole subtree.**
  The emulated copy now also copies each key's class name (via ORCreateKey's
  class arg) and its security descriptor (raw self-relative bytes, full mask
  with SACL fallback). Descendant `last_write` still cannot be preserved by a
  copy; CONTRACTS 0.1.2 explicitly excludes `last_write` under a renamed path
  from the semantic comparison, so this is now sanctioned, not a divergence.
- **Canonical/list sort comparator pinned.** Now case-insensitive Unicode
  ordinal with names uppercased (was lowercased), per 0.1.2. Must match the
  Linux agent exactly.
- **SDDL semantics** per ADR 0003: SDDL on the wire, harness compares the
  parsed binary descriptor; SACL compared only when both sides report one.
  Our O/G/D-always with SACL fallback and null-trimmed output already matches.

## VM snapshot status

Unknown / not applicable this session: the VM was never reached, so no hive was
written to it and no snapshot was taken or disturbed. Before the first real run,
install ADK + offreg, then snapshot clean.

## What I would do next

1. Acquire the VM (respect the harness flock), install ADK Deployment Tools,
   snapshot clean.
2. Copy the exe over, run `winreg-agent.exe --port 7879 --backend offreg-<ver>`
   as administrator, curl `/version` from Linux.
3. Walk the implementation order on real offreg: create+close (check `file -k`
   sees a hive), load+save round trip a corpus hive, then keys, values (all
   REG_* types against the corpus), security, dump.
4. Run the differential harness Linux-vs-Windows; fix divergences on this side
   first per the CLAUDE.md interaction rules. Target: green `semantic`.
5. Resolve assumptions 1-7 above with observed offreg behavior; update this file.
6. Pin and record the exact offreg/ADK version in README and `--backend`.
