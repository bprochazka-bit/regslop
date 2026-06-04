# libreg (Python)

A native Python binding for libreg. It links the libreg C ABI
(`libreg/include/libreg.h`, governed by `docs/ffi-abi.md`) directly through the
standard library's `ctypes`, exposing every registry operation libreg offers
in process: hive lifecycle, keys, values, security descriptors, validation,
and a Python-side canonical dump.

## Why ctypes over a C ABI (not PyO3)

The build environment has no crate registry, so a compiled Rust extension
(PyO3) is not buildable here, and the project is Debian-first and dependency
light. The C ABI (issue #106) is a stable, language-agnostic surface; binding
it with `ctypes` needs nothing outside the Python standard library and no
compiler on the Python side. See issue #108 for the full rationale.

## Requirements

Python 3.8+ and the libreg shared library. Build it once:

```bash
cd libreg && cargo build --release      # produces libreg/target/release/liblibreg.so
```

The binding finds the library via, in order: `$LIBREG_LIBRARY`, the repo build
outputs (`libreg/target/{release,debug}/liblibreg.so`), then the dynamic
loader's search path (`LD_LIBRARY_PATH`). Pass an explicit path with
`Library("/path/to/liblibreg.so")` if you prefer.

## Usage

```python
import libreg
from libreg import Library, RegType

lib = Library()
print(lib.version())                      # "libreg-0.1.0"

with lib.create("/tmp/demo.hive") as hive:
    hive.create_key("Software\\Example")
    hive.set_value("Software\\Example", "Greeting", RegType.SZ, "hello")
    hive.set_value("Software\\Example", "Count", RegType.DWORD, 7)
    hive.set_value("Software\\Example", "Names", RegType.MULTI_SZ, ["a", "b"])
    hive.set_value("Software\\Example", "Blob", RegType.BINARY, b"\x00\x01")
    hive.save()                           # explicit; context exit only closes
```

Paths use the contract separator `\` (a literal backslash), never start with a
separator, and `""` means the hive root. The default value is the value named
`""`.

### Operations

| Area        | Methods |
|-------------|---------|
| Lifecycle   | `Library.create`, `Library.load`, `Hive.save`, `Hive.close` (context manager) |
| Keys        | `create_key`, `delete_key(recursive=)`, `rename_key`, `list_subkeys`, `list_values`, `list_key`, `key_info`, `key_class` |
| Values      | `set_value`, `get_value`, `get_value_raw`, `delete_value` |
| Security    | `get_security` / `set_security` (SDDL strings), `get_security_bytes` / `set_security_bytes` (raw) |
| Diagnostics | `validate`, `dump` (canonical JSON) |

### Value data

You pass and receive native Python values; the codec applies the C ABI's
binary-native encoding (no base64, no QWORD-as-string; those are HTTP-wire
rules that do not apply here):

| RegType                                  | Python value |
|------------------------------------------|--------------|
| `SZ`, `EXPAND_SZ`, `LINK`                | `str` (stored UTF-16LE) |
| `DWORD`, `DWORD_BE`                      | `int` (unsigned 32 bit) |
| `QWORD`                                  | `int` (unsigned 64 bit, full precision) |
| `MULTI_SZ`                               | `list[str]` |
| `BINARY` and the opaque resource types   | `bytes` |
| `NONE`                                   | `None` |

`Hive.dump()` returns the CONTRACTS canonical JSON form (base64 binary,
QWORD-as-string above 2^53, sorted keys), built Python-side to match
`agents/linux/src/canonical.rs`. The C ABI does not expose `last_write` (the
semantic differ ignores timestamps), so dump emits a fixed placeholder; pass
`dump(include_last_write=False)` to omit it.

### Security (SDDL)

`get_security` / `set_security` work in SDDL strings. libreg stores the raw
binary self-relative descriptor; this package converts to and from SDDL in pure
Python (`libreg.sddl`), a faithful port of `clients/cli-core/src/sddl.rs`, so
the tokens match the agents and the harness (ADR 0003). Use
`get_security_bytes` / `set_security_bytes` for the raw form.

### Errors

A rejected operation raises `RegError` with a `.code` from `ErrorCode`
(matching the CONTRACTS.md error table) and a `.message`. Failure to load the
shared library raises `LibraryNotFound`. An invalid SDDL string raises
`SddlError`. All derive from `LibregError`.

## Tests

```bash
python3 -m unittest discover -s clients/python/tests
```

The SDDL and value-codec tests are pure Python (no library needed). The
end-to-end tests in `test_ffi.py` run against the built `liblibreg.so` and
skip automatically if it is not present.

## Example

`examples/quickstart.py` is a runnable end-to-end demo.
