"""Registry value types and their on the wire data encoding.

CONTRACTS.md fixes how each ``REG_*`` type carries its ``data`` field in JSON.
This module mirrors that table exactly and gives callers a Pythonic view: you
pass and receive native Python values (``bytes`` for binary types, ``int`` for
DWORD/QWORD, ``list[str]`` for MULTI_SZ, ``str`` for the string types, ``None``
for REG_NONE), and the codec handles the base64 and large integer rules.

The contract's ``data`` representations:

==============================  ==========================================
Type                            JSON ``data``
==============================  ==========================================
REG_NONE                        null
REG_SZ / REG_EXPAND_SZ          string
REG_LINK                        string
REG_BINARY                      base64 string
REG_DWORD / REG_DWORD_BE        integer
REG_MULTI_SZ                    array of strings
REG_QWORD                       integer (sent as string if > 2^53)
REG_RESOURCE_LIST etc.          base64 string (opaque)
==============================  ==========================================
"""

import base64
from enum import Enum


class RegType(str, Enum):
    """A Windows registry value type.

    Each member's value is the wire name used in the protocol (e.g.
    ``RegType.SZ == "REG_SZ"``), so a member can be passed anywhere the agent
    expects the ``type`` string. :attr:`code` gives the numeric Windows
    constant for callers that need it.
    """

    NONE = "REG_NONE"
    SZ = "REG_SZ"
    EXPAND_SZ = "REG_EXPAND_SZ"
    BINARY = "REG_BINARY"
    DWORD = "REG_DWORD"
    DWORD_BE = "REG_DWORD_BE"
    LINK = "REG_LINK"
    MULTI_SZ = "REG_MULTI_SZ"
    QWORD = "REG_QWORD"
    RESOURCE_LIST = "REG_RESOURCE_LIST"
    FULL_RESOURCE_DESCRIPTOR = "REG_FULL_RESOURCE_DESCRIPTOR"
    RESOURCE_REQUIREMENTS_LIST = "REG_RESOURCE_REQUIREMENTS_LIST"

    @property
    def code(self):
        """The numeric Windows ``REG_*`` constant for this type."""
        return _NUMERIC[self]

    @classmethod
    def from_wire(cls, name):
        """Resolve a wire type name (e.g. ``"REG_SZ"``) to a :class:`RegType`.

        Accepts an existing :class:`RegType` unchanged. Raises ``ValueError``
        for an unknown name so a malformed agent response is caught early.
        """
        if isinstance(name, cls):
            return name
        try:
            return cls(name)
        except ValueError:
            raise ValueError(f"unknown registry type: {name!r}") from None


_NUMERIC = {
    RegType.NONE: 0,
    RegType.SZ: 1,
    RegType.EXPAND_SZ: 2,
    RegType.BINARY: 3,
    RegType.DWORD: 4,
    RegType.DWORD_BE: 5,
    RegType.LINK: 6,
    RegType.MULTI_SZ: 7,
    RegType.RESOURCE_LIST: 8,
    RegType.FULL_RESOURCE_DESCRIPTOR: 9,
    RegType.RESOURCE_REQUIREMENTS_LIST: 10,
    RegType.QWORD: 11,
}

#: Types whose ``data`` is an opaque base64 string on the wire.
_BINARY_TYPES = frozenset(
    {
        RegType.BINARY,
        RegType.RESOURCE_LIST,
        RegType.FULL_RESOURCE_DESCRIPTOR,
        RegType.RESOURCE_REQUIREMENTS_LIST,
    }
)

#: Types whose ``data`` is a plain string.
_STRING_TYPES = frozenset({RegType.SZ, RegType.EXPAND_SZ, RegType.LINK})

# JSON cannot carry an integer above 2^53 without precision loss, so the
# contract sends a QWORD larger than that as a decimal string. We mirror the
# threshold exactly on encode and accept either form on decode.
_JSON_SAFE_INT = 2 ** 53


def encode_data(reg_type, value):
    """Encode a native Python ``value`` into the wire ``data`` for ``reg_type``.

    - binary/opaque types: ``bytes``/``bytearray`` -> base64 string. A ``str``
      is assumed to already be base64 and passed through.
    - REG_DWORD / REG_DWORD_BE: ``int`` (unsigned 32 bit).
    - REG_QWORD: ``int``; rendered as a decimal string when it exceeds 2^53.
    - REG_MULTI_SZ: a sequence of ``str`` -> ``list[str]``.
    - REG_SZ / REG_EXPAND_SZ / REG_LINK: ``str``.
    - REG_NONE: must be ``None`` -> null.
    """
    reg_type = RegType.from_wire(reg_type)

    if reg_type is RegType.NONE:
        if value is not None:
            raise TypeError("REG_NONE data must be None")
        return None

    if reg_type in _BINARY_TYPES:
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray)):
            return base64.b64encode(bytes(value)).decode("ascii")
        raise TypeError(f"{reg_type.value} data must be bytes (or a base64 str)")

    if reg_type in (RegType.DWORD, RegType.DWORD_BE):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{reg_type.value} data must be an int")
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"{reg_type.value} data out of 32 bit range: {value}")
        return value

    if reg_type is RegType.QWORD:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("REG_QWORD data must be an int")
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"REG_QWORD data out of 64 bit range: {value}")
        return str(value) if value > _JSON_SAFE_INT else value

    if reg_type is RegType.MULTI_SZ:
        if isinstance(value, (str, bytes)):
            raise TypeError("REG_MULTI_SZ data must be a sequence of str")
        items = list(value)
        if not all(isinstance(s, str) for s in items):
            raise TypeError("REG_MULTI_SZ data must contain only str")
        return items

    # Remaining: the plain string types.
    if not isinstance(value, str):
        raise TypeError(f"{reg_type.value} data must be a str")
    return value


def decode_data(reg_type, data):
    """Decode wire ``data`` for ``reg_type`` into a native Python value.

    The inverse of :func:`encode_data`: binary types come back as ``bytes``,
    DWORD/QWORD as ``int`` (a string encoded QWORD is parsed back), MULTI_SZ as
    ``list[str]``, string types as ``str``, REG_NONE as ``None``.
    """
    reg_type = RegType.from_wire(reg_type)

    if reg_type is RegType.NONE:
        return None

    if reg_type in _BINARY_TYPES:
        if not isinstance(data, str):
            raise TypeError(f"{reg_type.value} wire data must be a base64 str")
        return base64.b64decode(data)

    if reg_type in (RegType.DWORD, RegType.DWORD_BE):
        return int(data)

    if reg_type is RegType.QWORD:
        # Either a JSON integer or, for values above 2^53, a decimal string.
        return int(data)

    if reg_type is RegType.MULTI_SZ:
        return list(data)

    return data
