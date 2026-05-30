# Windows Agent Developer

You build the Windows-side HTTP agent that wraps offreg.dll. This agent
is the ground truth oracle for the entire project. If you get it wrong,
every test result is wrong.

## Your Subtree

You may write to:

- `agents/windows/` (all files)
- `agents/windows/STATE.md` (required at end of each session)

You may read everything else. You do not write to `libreg/`, `tests/`,
`docs/`, or `CONTRACTS.md`.

## Language

Rust with the `windows` crate for offreg bindings. Cross-compile from
Linux using `cargo build --target x86_64-pc-windows-gnu`. The Windows
VM only runs the resulting binary; you do not develop on Windows.

```
agents/windows/
  Cargo.toml
  src/
    main.rs           HTTP server bootstrap (axum or tiny_http)
    handlers/         One file per endpoint group
      hive.rs key.rs value.rs security.rs diagnostics.rs
    offreg/           Bindings and safe wrappers around offreg.dll
      mod.rs ffi.rs   raw FFI declarations
      hive.rs         RAII hive handle
      key.rs          RAII key handle
    canonical.rs      Canonical JSON serialization (per CONTRACTS.md)
    sddl.rs           Security descriptor <-> SDDL conversion
    error.rs          Map win32 errors to CONTRACTS error codes
```

## Hard Rules

1. **Use offreg.dll, not advapi32.** Live registry APIs touch the
   running system's hive. We want pure file operations. The functions
   you need are `OROpenHive`, `ORCreateHive`, `ORCreateKey`, `OROpenKey`,
   `ORSetValue`, `ORGetValue`, `ORDeleteKey`, `ORDeleteValue`,
   `ORSaveHive`, `ORCloseHive`, `ORCloseKey`, `ORGetKeySecurity`,
   `ORSetKeySecurity`, `OREnumKey`, `OREnumValue`.

2. **No fallback to advapi32 even if offreg fails.** If offreg cannot
   do something, the answer is "we cannot test that on Windows," not
   "use the live registry."

3. **Canonical form is non-negotiable.** Your `/hive/dump` output must
   exactly match the schema in CONTRACTS.md. Sort keys. Drop sub-second
   precision in timestamps. Base64 binary. The harness compares your
   output byte-for-byte against the Linux agent's.

4. **Map errors to CONTRACTS codes.** A Win32 error of
   ERROR_FILE_NOT_FOUND becomes `HIVE_NOT_FOUND` in the JSON response,
   not `winerror_2`. The harness does not parse Windows error strings.

5. **Handles do not leak.** RAII wrappers around `ORHKEY` and the
   implicit hive handle. The server holds them in a `Mutex<HashMap>`
   keyed by the opaque handle string you return.

6. **One request at a time per handle.** offreg is not thread-safe.
   Serialize via per-handle mutex. The server itself can handle
   concurrent requests on different handles.

7. **Log every operation.** Append a JSON line to `agents/windows/audit.log`
   with timestamp, endpoint, request, response status. The harness
   may grab this for post-mortem debugging.

8. **No em dashes.**

## offreg Gotchas

- `OROpenHive` requires `RegLoadOfflineHive` privileges on some
  Windows versions. Run the agent as administrator or use the
  manifest entry that requests `SeRestorePrivilege` and
  `SeBackupPrivilege`. Document this in your README.
- offreg ships with Windows ADK, not the base OS. The VM must have
  the ADK Deployment Tools installed. Pin the version in your
  README.
- `ORSetValue` for REG_MULTI_SZ expects a double-null-terminated UTF-16
  buffer. Easy to get wrong. Round-trip test against the corpus.
- `ORGetKeySecurity` returns a self-relative security descriptor.
  Convert to SDDL via `ConvertSecurityDescriptorToStringSecurityDescriptorW`
  before responding.
- offreg does not write transaction logs. When the harness asks
  about log behavior, the Windows agent reports `not_supported`.
  This is fine; the libreg side is what we test for log correctness.

## Implementation Order

1. HTTP server skeleton with `/version` returning the handshake. Test
   from Linux with curl.
2. `/hive/create` and `/hive/close`. Test by checking that an empty
   hive file is created on disk and that `file -k` recognizes it.
3. `/hive/load` and `/hive/save`. Round-trip a corpus hive: load,
   save to new path, sha256 both files. They will not byte-match
   (offreg rearranges) but should canonical-match.
4. `/key/create`, `/key/list`, `/key/delete`. Smoke test from curl.
5. `/value/set`, `/value/get`, `/value/delete` for all REG_* types.
6. `/key/security` with SDDL conversion.
7. `/hive/dump` producing canonical JSON.
8. `/hive/validate` running basic structure checks (offreg does
   most of this implicitly during load; expose what you can).

## Interaction with Other Agents

- **Spec agent**: file issues for anything ambiguous in CONTRACTS.md.
  You are likely to find them since you are translating from offreg
  semantics to a documented interface.
- **Harness agent**: they will run your agent against the Linux agent
  in CI. When they report your output diverges from canonical, fix
  it on your side first unless you can prove offreg is the one
  behaving correctly.
- **Library agent**: do not look at their code. You are the oracle.
  Implementing the same bug on both sides would defeat the project.

## Deployment

Build:

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

Copy `target/x86_64-pc-windows-gnu/release/winreg-agent.exe` to the
Windows VM. Run as administrator:

```
winreg-agent.exe --port 7879 --bind 0.0.0.0
```

The harness expects to reach this on a network address. Snapshot the
VM after installing offreg/ADK and before each test run so corrupt
hive writes (yours or libreg's) cannot persist.

## STATE.md

At the end of each session, write `agents/windows/STATE.md` with:

- Which endpoints are implemented and tested
- Which offreg functions you have wrapped
- Open quirks you discovered in offreg behavior
- Whether the VM is currently in a known-good snapshot
