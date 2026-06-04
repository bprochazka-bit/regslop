# Python binding STATE

Last updated: 2026-06-04

## Latest session: Debian packaging (#117)

Added `packaging/build-deb.sh`, which builds `python3-libreg` (a pure-Python,
`Architecture: all` package) with `dpkg-deb` only, modeled on
`clients/packaging/build-deb.sh` and `libreg/packaging/build-deb.sh`. It
installs the `libreg` package to `/usr/lib/python3/dist-packages/libreg/`,
ships the README to `/usr/share/doc/python3-libreg/`, and declares
`Depends: python3:any, liblibreg0 (>= 0.1.0)`.

`libreg/_ffi.py` now also searches the SONAME `liblibreg.so.0` (and the
`liblibreg.so` dev symlink) after the repo `target/` paths, so the binding
loads the installed C ABI by name off a system install while keeping
`$LIBREG_LIBRARY` and the repo build as development fallbacks.

Verified: the `.deb` builds; `dpkg-deb -I`/`-c` show the right control,
`Depends`, and contents; and a clean-room test (extract `python3-libreg` +
`liblibreg0` to a staging root, with no `$LIBREG_LIBRARY` and the package's
repo-relative `target/` not present) imports `libreg`, loads `liblibreg.so.0`
by SONAME via `LD_LIBRARY_PATH`, and round-trips a value. The 29 unit/FFI tests
still pass. This is the #117 deliverable; #115 (`liblibreg0`) is its merged
prerequisite.

## What this subtree is

`clients/python/` is a native Python binding for libreg (issue #108). It links
the libreg C ABI (`libreg/include/libreg.h`, governed by `docs/ffi-abi.md`,
shipped under #106) directly through the standard library's `ctypes`. No HTTP
agent, no third-party Python packages, no compiler on the Python side. It
exposes every registry operation libreg offers, in process.

A prior HTTP-client-to-agent prototype was explored and rolled back; the native
C ABI binding is the intended design (decided with the user 2026-06-04).

## What works (this session)

- Package `libreg` (import `libreg`), pure stdlib:
  - `_ffi.py`: locates and loads `liblibreg.so` (`$LIBREG_LIBRARY`, repo
    `target/{release,debug}`, then loader path), declares all 20 `libreg_*`
    signatures, and provides status-checking and buffer-reading (with
    `libreg_free`) helpers.
  - `client.py`: `Library` (version/create/load) and `Hive` (save, close,
    context manager; key create/delete/rename/list_subkeys/list_values/info/
    class; value set/get/get_raw/delete; security get/set as SDDL and raw bytes;
    validate; dump). Dataclasses for each result shape.
  - `types.py`: `RegType` (numeric REG_* values, `reg_name`, `from_name`) and
    the value codec. Binary-native per ffi-abi.md: DWORD 4 LE / DWORD_BE 4 BE /
    QWORD 8 LE, strings UTF-16LE, MULTI_SZ UTF-16LE double-NUL, binary raw.
    `encode_value`/`decode_value` are the native (Pythonic) view; `canonical_data`
    is the JSON view (base64 binary, QWORD>2^53 as string) for dump. Byte
    layouts mirror `agents/linux/src/valuec.rs`.
  - `sddl.py`: binary self-relative descriptor <-> SDDL, a faithful port of
    `clients/cli-core/src/sddl.rs` plus the binary layout from
    `libreg/src/format/security_descriptor.rs` (SID/ACE/ACL/SD, SACL-DACL-owner-
    group body order, well-known SID aliases, KA/KR rights, ACE flag tokens).
  - `canonical.py`: builds the CONTRACTS canonical JSON Python-side, matching
    `agents/linux/src/canonical.rs` (sorted subkeys/values, class null-when-
    absent, security sddl). `last_write` is a documented placeholder (the C ABI
    does not expose timestamps; the semantic differ ignores them).
  - `errors.py`: `RegError` (code name + int + detail), `LibraryNotFound`,
    `SddlError`, `LibregError`, and `ErrorCode` (1:1 with the status enum).
- Tests: 29, all green (`python3 -m unittest discover -s tests`).
  - `test_sddl.py`, `test_values.py`: pure Python, no library.
  - `test_ffi.py`: end-to-end against the built `liblibreg.so` (all REG types
    round-trip, default value + listing, KEY_EXISTS, KEY_HAS_CHILDREN,
    VALUE_NOT_FOUND, rename preserves subtree+values, SDDL round-trip, raw
    security bytes equal the Python codec's output, validate, canonical dump
    shape, closed-handle guard). Skips if the .so is absent.
- `examples/quickstart.py`: runnable end-to-end demo (verified).
- `pyproject.toml` (zero deps), `.gitignore`, `README.md`.

Verified: `cd libreg && cargo build --release` then the full suite and the
example both pass.

## Assumptions / notes

- The C ABI does not expose `last_write`, canonical `dump`, or `checksum` (by
  design, ffi-abi.md). dump is built here from the enumeration primitives;
  checksum is not provided (consumer-side hashing if ever needed).
- Security crosses as the raw binary descriptor; SDDL conversion is done in
  Python (ADR 0003), reusing the same token tables as the Rust codec.
- `Hive.save()` is explicit; leaving a `with` block closes the handle but does
  not save (mirrors the agent and the Rust clients).
- Handles are not thread-safe (one `Hive` per thread), per ffi-abi.md.

## What I would do next

1. Harness acceptance (the real bar, ffi-abi.md section 5, universal rule 3):
   wire an FFI-driven backend into the harness so a binding-driven op sequence
   is compared semantically against the agent-driven one. That is a
   `tests/harness/` change (separate subtree), so coordinate. Until then the
   dump is validated structurally and the value/SDDL codecs against the Rust
   byte layouts, not yet against the live differ.
2. Packaging: a `.deb` shipping the binding plus `liblibreg.so` alongside
   `libreg-tools` (Debian first), once a libreg shared-object package exists.
3. Optional: a structured ACE editor / SACL support in `sddl.py` (currently
   owner/group/DACL, SACL dropped on write like the offline codec); a
   `checksum` helper; richer `key_info` if the C ABI later exposes `last_write`.
