# Python client STATE

Last updated: 2026-06-04

## What this subtree is

`clients/python/` is a Python binding for libreg. It is a pure standard library
client for the libreg agent HTTP protocol (CONTRACTS.md), giving Python access
to every registry operation libreg exposes: hive lifecycle, key and value
operations, security descriptors, and diagnostics. It drives either agent (the
Linux/libreg agent on 7878 or the symmetric Windows/offreg agent on 7879).

## Why this shape (decision record)

The request was "a Python library that can use libreg for all registry
functions." Two ways to bind were possible:

1. A native in process binding (PyO3 / cffi / ctypes) linking libreg directly.
2. A client over the agent's HTTP protocol.

Chose (2). libreg has no C ABI yet (Layer 4 `api/` FFI is unimplemented per
`libreg/src/lib.rs` and `libreg/CLAUDE.md`), libreg is read only to the clients
subtree, and the build box has no package registry, so a compiled extension is
not buildable here. The agent already wraps the full library behind HTTP and is
the surface the harness trusts, so the client reaches everything with no
compiler and no third party packages, matching the project's Debian first,
dependency light stance. If libreg later grows a stable C ABI, an in process
`ctypes` backend can sit behind the same `Agent`/`Hive` API with no change to
caller code.

## What works

- Package `libreg` (import name `libreg`), stdlib only, no runtime deps.
  - `client.py`: `Agent` (transport, `version`, `create`, `load`) and `Hive`
    (save, close, context manager; key create/delete/rename/list/info; value
    set/get/delete; security get/set; dump/checksum/validate; `crash_save` for
    the recovery test endpoint). Dataclasses for each response shape.
  - `types.py`: `RegType` (wire name as the enum value, numeric `.code`,
    `from_wire`) and the value codec (`encode_data`/`decode_data`) covering the
    full CONTRACTS.md type table: base64 for binary/opaque types, int for
    DWORD/DWORD_BE, the QWORD > 2^53 string rule, list[str] for MULTI_SZ,
    None for REG_NONE, plus range and type validation.
  - `errors.py`: `RegError` (carries the contract `code` + message),
    `TransportError`, `LibregError` base, and `ErrorCode` constants.
- Reads are GET with a JSON body, writes are POST (ADR 0001); `/key/security`
  is read=GET, write=POST. Verified by the tests.
- Tests: `tests/test_client.py`, 18 tests, all green. They run against an in
  process mock agent (stdlib `http.server`), so no real agent or network is
  needed. Run: `python3 -m unittest discover -s clients/python/tests`.
- `examples/quickstart.py`: runnable end to end demo against a live agent.
- `pyproject.toml`: setuptools metadata, zero dependencies.

## Assumptions

- The agent envelope is `{ ok, error, code, data }` with `code` at the top
  level on failure (confirmed in `agents/linux/src/main.rs`). `ok: false` maps
  to `RegError`; transport/parse failures map to `TransportError`.
- `/key/list` returns name arrays (`subkeys`, `values`), `/value/get` returns
  `{ type, data }`, `/key/info` returns the four documented fields. Matched to
  `agents/linux/src/model.rs` and the handlers, not just the contract prose.
- `Hive.save()` is explicit (not implicit on context exit), mirroring the Rust
  clients and the agent: leaving a `with` block closes the handle but does not
  save.

## What I would do next

1. Acceptance against a live agent: bring up `agents/linux` and run
   `examples/quickstart.py`, ideally wired into the harness as a Python client
   differential mode (parallel to the existing client-differential proposal in
   `clients/proposals/`). The harness is the judge; local unit tests are not the
   bar.
2. A `ctypes` backend if/when libreg ships a C ABI, selected behind the same
   `Agent`/`Hive` API for in process use without a running server.
3. Optional conveniences: a higher level mount map aware path layer (mirroring
   `cli-core`), `.reg` import/export, and typed helpers for SDDL.
4. Packaging: a `.deb` for the Python client if it ships alongside
   `libreg-tools`, consistent with the Debian first rule.
