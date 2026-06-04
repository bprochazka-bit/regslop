"""Registry value types and the binary-native value codec.

At the C ABI a value crosses as a REG_* type code (a ``u32``) plus its raw
on-disk bytes (`docs/ffi-abi.md` section 2): no base64, no "QWORD as a string".
This module mirrors the agent's value codec (`agents/linux/src/valuec.rs`) so a
hive built through this binding is byte-for-byte and canonically identical to
one built through the HTTP agent.

Two views of a value are provided:

- The Pythonic view (:func:`encode_value` / :func:`decode_value`) used by
  ``Hive.set_value`` / ``Hive.get_value``: native Python objects (``str``,
  ``int``, ``bytes``, ``list[str]``, ``None``).
- The canonical view (:func:`canonical_data`) used by ``Hive.dump`` to build
  the CONTRACTS canonical JSON: base64 for binary types, a decimal string for a
  QWORD above 2^53, exactly as `canonical.rs` expects.
"""

import base64
from enum import IntEnum


class RegType(IntEnum):
    """A Windows registry value type, valued by its numeric REG_* constant."""

    NONE = 0
    SZ = 1
    EXPAND_SZ = 2
    BINARY = 3
    DWORD = 4
    DWORD_BE = 5
    LINK = 6
    MULTI_SZ = 7
    RESOURCE_LIST = 8
    FULL_RESOURCE_DESCRIPTOR = 9
    RESOURCE_REQUIREMENTS_LIST = 10
    QWORD = 11

    @property
    def reg_name(self):
        """The CONTRACTS wire name, e.g. ``"REG_DWORD"`` / ``"REG_DWORD_BE"``."""
        return _WIRE_NAME[self]

    @classmethod
    def from_name(cls, name):
        """Resolve a wire name (e.g. ``"REG_SZ"``) or an int/RegType to a RegType."""
        if isinstance(name, RegType):
            return name
        if isinstance(name, int):
            return cls(name)
        try:
            return _BY_WIRE_NAME[name]
        except KeyError:
            raise ValueError(f"unknown registry type name: {name!r}") from None


_WIRE_NAME = {
    RegType.NONE: "REG_NONE",
    RegType.SZ: "REG_SZ",
    RegType.EXPAND_SZ: "REG_EXPAND_SZ",
    RegType.BINARY: "REG_BINARY",
    RegType.DWORD: "REG_DWORD",
    RegType.DWORD_BE: "REG_DWORD_BE",
    RegType.LINK: "REG_LINK",
    RegType.MULTI_SZ: "REG_MULTI_SZ",
    RegType.RESOURCE_LIST: "REG_RESOURCE_LIST",
    RegType.FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
    RegType.RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
    RegType.QWORD: "REG_QWORD",
}
_BY_WIRE_NAME = {name: rt for rt, name in _WIRE_NAME.items()}

_STRING_TYPES = (RegType.SZ, RegType.EXPAND_SZ, RegType.LINK)


def type_name(type_code):
    """CONTRACTS wire name for a raw REG type code.

    An unrecognized code falls back to ``"REG_BINARY"`` (the opaque
    representation), matching `valuec.rs::type_name` so canonical output agrees
    even for types this binding does not model.
    """
    try:
        return _WIRE_NAME[RegType(type_code)]
    except ValueError:
        return "REG_BINARY"


def _is_binaryish(type_code):
    """True for the opaque types carried as raw bytes / base64 (REG_BINARY and
    the resource types, plus any unrecognized code)."""
    return type_code not in (
        RegType.NONE,
        RegType.SZ,
        RegType.EXPAND_SZ,
        RegType.LINK,
        RegType.DWORD,
        RegType.DWORD_BE,
        RegType.MULTI_SZ,
        RegType.QWORD,
    )


# --- string helpers (UTF-16LE on disk) -------------------------------------


def build_sz(s):
    """Encode a string as UTF-16LE with a single trailing NUL code unit."""
    return (s + "\x00").encode("utf-16-le")


def parse_sz(raw):
    """Decode UTF-16LE bytes, dropping one trailing NUL code unit if present."""
    units = _u16le(raw)
    if units and units[-1] == 0:
        units = units[:-1]
    return _from_u16(units)


def build_multi_sz(items):
    """Encode a list of strings as UTF-16LE, each NUL-terminated, double-NUL end."""
    out = bytearray()
    for s in items:
        out += s.encode("utf-16-le")
        out += b"\x00\x00"
    out += b"\x00\x00"
    return bytes(out)


def parse_multi_sz(raw):
    """Decode a double-NUL terminated list of UTF-16LE strings."""
    units = _u16le(raw)
    out = []
    cur = []
    for u in units:
        if u == 0:
            if not cur:
                break
            out.append(_from_u16(cur))
            cur = []
        else:
            cur.append(u)
    if cur:
        out.append(_from_u16(cur))
    return out


def _u16le(raw):
    n = len(raw) - (len(raw) % 2)
    return [raw[i] | (raw[i + 1] << 8) for i in range(0, n, 2)]


def _from_u16(units):
    return b"".join(u.to_bytes(2, "little") for u in units).decode("utf-16-le", "replace")


# --- Pythonic codec (native <-> raw bytes) ---------------------------------


def encode_value(type_code, value):
    """Encode a native Python ``value`` to raw bytes for REG type ``type_code``.

    - REG_NONE: ``None`` -> empty.
    - REG_SZ / REG_EXPAND_SZ / REG_LINK: ``str`` -> UTF-16LE.
    - REG_DWORD / REG_DWORD_BE: ``int`` (unsigned 32 bit) -> 4 bytes LE / BE.
    - REG_QWORD: ``int`` (unsigned 64 bit) -> 8 bytes LE.
    - REG_MULTI_SZ: sequence of ``str`` -> UTF-16LE list.
    - binary/opaque types: ``bytes``/``bytearray`` passthrough.
    """
    rt = RegType(type_code) if type_code in RegType._value2member_map_ else None

    if rt is RegType.NONE:
        if value not in (None, b""):
            raise TypeError("REG_NONE data must be None")
        return b""

    if rt in _STRING_TYPES:
        if not isinstance(value, str):
            raise TypeError(f"{rt.reg_name} data must be a str")
        return build_sz(value)

    if rt in (RegType.DWORD, RegType.DWORD_BE):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{rt.reg_name} data must be an int")
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"{rt.reg_name} out of 32 bit range: {value}")
        return value.to_bytes(4, "little" if rt is RegType.DWORD else "big")

    if rt is RegType.QWORD:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("REG_QWORD data must be an int")
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"REG_QWORD out of 64 bit range: {value}")
        return value.to_bytes(8, "little")

    if rt is RegType.MULTI_SZ:
        if isinstance(value, (str, bytes)):
            raise TypeError("REG_MULTI_SZ data must be a sequence of str")
        items = list(value)
        if not all(isinstance(s, str) for s in items):
            raise TypeError("REG_MULTI_SZ data must contain only str")
        return build_multi_sz(items)

    # Binary and opaque resource types (and any unknown code): raw bytes.
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError(f"{type_name(type_code)} data must be bytes")


def decode_value(type_code, raw):
    """Decode raw bytes into a native Python value for REG type ``type_code``.

    Inverse of :func:`encode_value`: binary types -> ``bytes``, DWORD/QWORD ->
    ``int``, MULTI_SZ -> ``list[str]``, string types -> ``str``, REG_NONE ->
    ``None``.
    """
    if type_code == RegType.NONE:
        return None
    if type_code in _STRING_TYPES:
        return parse_sz(raw)
    if type_code == RegType.DWORD:
        return int.from_bytes(_pad(raw, 4), "little")
    if type_code == RegType.DWORD_BE:
        return int.from_bytes(_pad(raw, 4), "big")
    if type_code == RegType.QWORD:
        return int.from_bytes(_pad(raw, 8), "little")
    if type_code == RegType.MULTI_SZ:
        return parse_multi_sz(raw)
    return bytes(raw)


# --- canonical codec (raw bytes -> JSON data) ------------------------------


def canonical_data(type_code, raw):
    """Build the canonical JSON ``data`` for a value, mirroring `valuec.rs`.

    Binary types become base64 strings, a QWORD above 2^53 becomes a decimal
    string (JSON precision), everything else matches :func:`decode_value`.
    """
    if type_code == RegType.NONE:
        return None
    if type_code in _STRING_TYPES:
        return parse_sz(raw)
    if type_code == RegType.DWORD:
        return int.from_bytes(_pad(raw, 4), "little")
    if type_code == RegType.DWORD_BE:
        return int.from_bytes(_pad(raw, 4), "big")
    if type_code == RegType.QWORD:
        v = int.from_bytes(_pad(raw, 8), "little")
        return str(v) if v > (1 << 53) else v
    if type_code == RegType.MULTI_SZ:
        return parse_multi_sz(raw)
    return base64.b64encode(bytes(raw)).decode("ascii")


def _pad(raw, n):
    """Left-justify (truncate or zero-pad) ``raw`` to ``n`` bytes, like the
    lenient integer readers in `valuec.rs`."""
    raw = bytes(raw[:n])
    return raw + b"\x00" * (n - len(raw))
