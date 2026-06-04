# libreg (Python)

A pure standard library Python client for libreg. It exposes every registry
operation libreg offers (hive lifecycle, keys, values, security, diagnostics)
by speaking the libreg agent HTTP protocol defined in the repository's
`CONTRACTS.md`.

## Why a client, not a native binding

libreg is a Rust library. The clients in this repository that link it directly
(`reg`, `regsc`, `regedit`, `regmount`) are themselves Rust and depend on
libreg by path. There is no C ABI on libreg yet (Layer 4 FFI is unimplemented),
and the build environment has no package registry, so a compiled extension
binding (PyO3, cffi) is not buildable here.

The agent already wraps libreg behind a complete HTTP protocol that the
differential harness drives. This package targets that same protocol, so it
reaches the full library surface with no compiler and no third party packages,
matching the project's Debian first, native, dependency light stance. The same
protocol is implemented by the Windows agent, so this client drives either side
interchangeably.

If libreg later grows a stable C ABI, an in process `ctypes` backend can be
added behind the same `Agent`/`Hive` API without changing caller code.

## Requirements

Python 3.8 or newer. Standard library only, no `pip install` of dependencies.
A running libreg agent (the Linux agent listens on 7878 by default):

```bash
cd agents/linux && cargo run --release
```

## Usage

```python
from libreg import Agent, RegType

agent = Agent(port=7878)          # Linux agent default; 7879 for Windows
print(agent.version())            # Handshake(agent, protocol, backend)

with agent.create("/tmp/demo.hiv") as hive:
    hive.create_key("Software\\Example")
    hive.set_value("Software\\Example", "Greeting", RegType.SZ, "hello")
    hive.set_value("Software\\Example", "Count", RegType.DWORD, 7)
    hive.set_value("Software\\Example", "Names", RegType.MULTI_SZ, ["a", "b"])
    hive.set_value("Software\\Example", "Blob", RegType.BINARY, b"\x00\x01")
    hive.save()                   # not automatic; call before leaving the block
```

Paths use the contract separator `\` (a literal backslash), never start with a
separator, and `""` means the hive root. The default value is the value named
`""`.

### Operations

| Area          | Methods |
|---------------|---------|
| Lifecycle     | `Agent.create`, `Agent.load`, `Hive.save`, `Hive.close` (context manager) |
| Keys          | `create_key`, `delete_key(recursive=)`, `rename_key`, `list_key`, `key_info` |
| Values        | `set_value`, `get_value`, `delete_value` |
| Security      | `get_security`, `set_security` (SDDL strings) |
| Diagnostics   | `dump`, `checksum`, `validate` |
| Handshake     | `Agent.version` |
| Recovery test | `Hive.crash_save` (Linux/libreg agent only) |

### Value data

You work with native Python values; the codec applies the contract's wire
rules:

| RegType                          | Python value          |
|----------------------------------|-----------------------|
| `SZ`, `EXPAND_SZ`, `LINK`        | `str`                 |
| `DWORD`, `DWORD_BE`              | `int` (unsigned 32 bit) |
| `QWORD`                          | `int` (string on the wire above 2^53) |
| `MULTI_SZ`                       | `list[str]`           |
| `BINARY` and the opaque resource types | `bytes` (base64 on the wire) |
| `NONE`                           | `None`                |

### Errors

A registry operation the agent rejects raises `RegError` with a `.code` from
`ErrorCode` (matching the CONTRACTS.md error table) and a `.message`. A
connection level failure (refused, timeout, malformed envelope) raises
`TransportError`. Both derive from `LibregError`.

```python
from libreg import RegError, ErrorCode

try:
    hive.create_key("Existing")
except RegError as e:
    if e.code == ErrorCode.KEY_EXISTS:
        ...
```

## Tests

The test suite runs against an in process mock agent (stdlib `http.server`), so
it needs no real agent and no network:

```bash
python3 -m unittest discover -s clients/python/tests
```

## Example

`examples/quickstart.py` is a runnable end to end demo against a live agent.
