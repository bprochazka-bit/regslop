"""Binary security descriptor <-> SDDL string conversion.

libreg stores key security as a self-relative binary SECURITY_DESCRIPTOR and
the C ABI hands it across as raw bytes (ADR 0003: SDDL conversion is the
consumer's job). This module is a faithful Python port of the Rust codec in
`clients/cli-core/src/sddl.rs` and the binary layout in
`libreg/src/format/security_descriptor.rs`, so the SDDL tokens this binding
emits match what the agents and the differential harness produce.

It covers owner, group, and a DACL of access-allowed/denied ACEs, with the
well-known SID aliases and key-rights tokens recognized by name and
``S-1-...`` / ``0x...`` fallbacks for the rest. The SACL is accepted but
dropped on write (offline key security is owner/group/DACL; the harness
compares the SACL only when both sides have one).
"""

import struct

from .errors import SddlError

# Control flags (self-relative descriptor).
SE_SELF_RELATIVE = 0x8000
SE_DACL_PRESENT = 0x0004
SE_SACL_PRESENT = 0x0010

SD_REVISION = 1
ACL_REVISION = 2

ACCESS_ALLOWED = 0x00
ACCESS_DENIED = 0x01

KEY_ALL_ACCESS = 0x000F003F
KEY_READ = 0x00020019

_SD_HEADER = 20
_ACL_HEADER = 8
_ACE_HEADER = 8

# --- SID -------------------------------------------------------------------


class Sid:
    """A security identifier: revision, 6-byte authority, sub-authorities."""

    __slots__ = ("authority", "sub_authorities")

    def __init__(self, authority, sub_authorities):
        self.authority = authority  # integer value of the 6-byte authority
        self.sub_authorities = list(sub_authorities)

    def __eq__(self, other):
        return (
            isinstance(other, Sid)
            and self.authority == other.authority
            and self.sub_authorities == other.sub_authorities
        )

    def byte_len(self):
        return 8 + 4 * len(self.sub_authorities)

    def to_bytes(self):
        out = bytearray()
        out.append(SD_REVISION)
        out.append(len(self.sub_authorities))
        out += self.authority.to_bytes(6, "big")
        for sub in self.sub_authorities:
            out += struct.pack("<I", sub)
        return bytes(out)

    @classmethod
    def parse(cls, buf, off):
        if off + 8 > len(buf):
            raise SddlError("SID header out of bounds")
        count = buf[off + 1]
        authority = int.from_bytes(buf[off + 2 : off + 8], "big")
        need = 8 + 4 * count
        if off + need > len(buf):
            raise SddlError("SID sub-authorities out of bounds")
        subs = [
            struct.unpack_from("<I", buf, off + 8 + 4 * i)[0] for i in range(count)
        ]
        return cls(authority, subs)


# Well-known SID aliases (authority, sub-authorities) <-> token.
_SID_ALIASES = {
    (5, (18,)): "SY",
    (5, (32, 544)): "BA",
    (5, (32, 545)): "BU",
    (1, (0,)): "WD",
    (5, (12,)): "RC",
}
_SID_BY_TOKEN = {tok: (auth, list(subs)) for (auth, subs), tok in _SID_ALIASES.items()}


def sid_to_string(sid):
    tok = _SID_ALIASES.get((sid.authority, tuple(sid.sub_authorities)))
    if tok is not None:
        return tok
    return "S-1-" + "-".join(str(x) for x in (sid.authority, *sid.sub_authorities))


def sid_from_string(s):
    if s in _SID_BY_TOKEN:
        auth, subs = _SID_BY_TOKEN[s]
        return Sid(auth, subs)
    if s.startswith("S-1-"):
        parts = s[4:].split("-")
        try:
            auth = int(parts[0])
            subs = [int(p) for p in parts[1:]]
        except ValueError:
            raise SddlError(f"bad SID: {s}") from None
        if auth > 0xFFFFFFFFFFFF:
            raise SddlError(f"SID authority too large: {s}")
        return Sid(auth, subs)
    raise SddlError(f"unknown SID or alias: {s}")


# --- access mask -----------------------------------------------------------


def _mask_to_string(mask):
    if mask == KEY_ALL_ACCESS:
        return "KA"
    if mask == KEY_READ:
        return "KR"
    return f"0x{mask:x}"


def _mask_from_string(s):
    if s == "KA":
        return KEY_ALL_ACCESS
    if s == "KR":
        return KEY_READ
    if s[:2] in ("0x", "0X"):
        try:
            return int(s[2:], 16)
        except ValueError:
            raise SddlError(f"bad access mask: {s}") from None
    raise SddlError(f"unknown rights token: {s}")


# --- ACE flags -------------------------------------------------------------

_FLAG_TABLE = [
    (0x01, "OI"),
    (0x02, "CI"),
    (0x04, "NP"),
    (0x08, "IO"),
    (0x10, "ID"),
]
_FLAG_BY_TOKEN = {tok: bit for bit, tok in _FLAG_TABLE}


def _flags_to_string(flags):
    return "".join(tok for bit, tok in _FLAG_TABLE if flags & bit)


def _flags_from_string(s):
    s = s.upper()
    if len(s) % 2 != 0:
        raise SddlError(f"odd-length ACE flags: {s}")
    flags = 0
    for i in range(0, len(s), 2):
        tok = s[i : i + 2]
        if tok not in _FLAG_BY_TOKEN:
            raise SddlError(f"unknown ACE flag token: {tok}")
        flags |= _FLAG_BY_TOKEN[tok]
    return flags


# --- ACE -------------------------------------------------------------------


class Ace:
    __slots__ = ("ace_type", "flags", "mask", "sid")

    def __init__(self, ace_type, flags, mask, sid):
        self.ace_type = ace_type
        self.flags = flags
        self.mask = mask
        self.sid = sid

    def __eq__(self, other):
        return (
            isinstance(other, Ace)
            and self.ace_type == other.ace_type
            and self.flags == other.flags
            and self.mask == other.mask
            and self.sid == other.sid
        )

    def byte_len(self):
        return _ACE_HEADER + self.sid.byte_len()

    def to_bytes(self):
        out = bytearray()
        out.append(self.ace_type)
        out.append(self.flags)
        out += struct.pack("<H", self.byte_len())
        out += struct.pack("<I", self.mask)
        out += self.sid.to_bytes()
        return bytes(out)

    @classmethod
    def parse(cls, buf, off):
        if off + _ACE_HEADER > len(buf):
            raise SddlError("ACE header out of bounds")
        ace_type = buf[off]
        flags = buf[off + 1]
        size = struct.unpack_from("<H", buf, off + 2)[0]
        if size < _ACE_HEADER or off + size > len(buf):
            raise SddlError("ACE body out of bounds")
        mask = struct.unpack_from("<I", buf, off + 4)[0]
        sid = Sid.parse(buf, off + _ACE_HEADER)
        return cls(ace_type, flags, mask, sid), size

    def to_string(self):
        ty = {ACCESS_ALLOWED: "A", ACCESS_DENIED: "D"}.get(self.ace_type)
        if ty is None:
            raise SddlError(f"unsupported ACE type {self.ace_type:#x}")
        return "({};{};{};;;{})".format(
            ty, _flags_to_string(self.flags), _mask_to_string(self.mask),
            sid_to_string(self.sid),
        )

    @classmethod
    def from_string(cls, inner):
        f = inner.split(";")
        if len(f) < 6:
            raise SddlError(f"malformed ACE: ({inner})")
        ace_type = {"A": ACCESS_ALLOWED, "D": ACCESS_DENIED}.get(f[0].strip().upper())
        if ace_type is None:
            raise SddlError(f"unsupported ACE type: {f[0]}")
        flags = _flags_from_string(f[1].strip())
        mask = _mask_from_string(f[2].strip())
        sid = sid_from_string(f[5].strip())
        return cls(ace_type, flags, mask, sid)


# --- ACL -------------------------------------------------------------------


class Acl:
    __slots__ = ("aces",)

    def __init__(self, aces):
        self.aces = list(aces)

    def byte_len(self):
        return _ACL_HEADER + sum(a.byte_len() for a in self.aces)

    def to_bytes(self):
        out = bytearray()
        out.append(ACL_REVISION)
        out.append(0)  # Sbz1
        out += struct.pack("<H", self.byte_len())
        out += struct.pack("<H", len(self.aces))
        out += struct.pack("<H", 0)  # Sbz2
        for ace in self.aces:
            out += ace.to_bytes()
        return bytes(out)

    @classmethod
    def parse(cls, buf, off):
        if off + _ACL_HEADER > len(buf):
            raise SddlError("ACL header out of bounds")
        size = struct.unpack_from("<H", buf, off + 2)[0]
        ace_count = struct.unpack_from("<H", buf, off + 4)[0]
        if off + size > len(buf):
            raise SddlError("ACL body out of bounds")
        aces = []
        cursor = off + _ACL_HEADER
        for _ in range(ace_count):
            ace, ace_size = Ace.parse(buf, cursor)
            cursor += ace_size
            aces.append(ace)
        return cls(aces)


# --- SecurityDescriptor ----------------------------------------------------


class SecurityDescriptor:
    __slots__ = ("control", "owner", "group", "dacl", "sacl")

    def __init__(self, control=0, owner=None, group=None, dacl=None, sacl=None):
        self.control = control
        self.owner = owner
        self.group = group
        self.dacl = dacl
        self.sacl = sacl

    def to_bytes(self):
        control = self.control | SE_SELF_RELATIVE
        if self.dacl is not None:
            control |= SE_DACL_PRESENT
        if self.sacl is not None:
            control |= SE_SACL_PRESENT

        # Bodies follow the header in the order SACL, DACL, owner, group, to
        # match offreg / RtlAbsoluteToSelfRelativeSD byte for byte.
        cursor = _SD_HEADER
        sacl_off = dacl_off = owner_off = group_off = 0
        if self.sacl is not None:
            sacl_off = cursor
            cursor += self.sacl.byte_len()
        if self.dacl is not None:
            dacl_off = cursor
            cursor += self.dacl.byte_len()
        if self.owner is not None:
            owner_off = cursor
            cursor += self.owner.byte_len()
        if self.group is not None:
            group_off = cursor
            cursor += self.group.byte_len()

        out = bytearray()
        out.append(SD_REVISION)
        out.append(0)  # Sbz1
        out += struct.pack("<H", control)
        out += struct.pack("<I", owner_off)
        out += struct.pack("<I", group_off)
        out += struct.pack("<I", sacl_off)
        out += struct.pack("<I", dacl_off)
        if self.sacl is not None:
            out += self.sacl.to_bytes()
        if self.dacl is not None:
            out += self.dacl.to_bytes()
        if self.owner is not None:
            out += self.owner.to_bytes()
        if self.group is not None:
            out += self.group.to_bytes()
        return bytes(out)

    @classmethod
    def parse(cls, buf):
        if len(buf) < _SD_HEADER:
            raise SddlError(f"security descriptor truncated: {len(buf)} bytes")
        control = struct.unpack_from("<H", buf, 0x02)[0]
        owner_off = struct.unpack_from("<I", buf, 0x04)[0]
        group_off = struct.unpack_from("<I", buf, 0x08)[0]
        sacl_off = struct.unpack_from("<I", buf, 0x0C)[0]
        dacl_off = struct.unpack_from("<I", buf, 0x10)[0]
        owner = Sid.parse(buf, owner_off) if owner_off else None
        group = Sid.parse(buf, group_off) if group_off else None
        dacl = Acl.parse(buf, dacl_off) if (control & SE_DACL_PRESENT and dacl_off) else None
        sacl = Acl.parse(buf, sacl_off) if (control & SE_SACL_PRESENT and sacl_off) else None
        return cls(control, owner, group, dacl, sacl)


# --- top level -------------------------------------------------------------


def to_sddl(raw):
    """Convert a binary self-relative security descriptor to its SDDL string."""
    desc = SecurityDescriptor.parse(bytes(raw))
    out = []
    if desc.owner is not None:
        out.append("O:" + sid_to_string(desc.owner))
    if desc.group is not None:
        out.append("G:" + sid_to_string(desc.group))
    if desc.dacl is not None:
        out.append("D:" + "".join(ace.to_string() for ace in desc.dacl.aces))
    return "".join(out)


def from_sddl(sddl):
    """Parse an SDDL string into a binary self-relative security descriptor."""
    desc = SecurityDescriptor()
    for letter, body in _split_components(sddl):
        if letter == "O":
            desc.owner = sid_from_string(body.strip())
        elif letter == "G":
            desc.group = sid_from_string(body.strip())
        elif letter == "D":
            desc.dacl = Acl([Ace.from_string(inner) for inner in _split_aces(body)])
        elif letter == "S":
            pass  # SACL accepted but dropped (see module docstring)
    return desc.to_bytes()


def _split_components(s):
    """Split into (letter, body) for each top-level O:/G:/D:/S: marker,
    respecting parenthesis depth so an ACE body is not mistaken for a marker."""
    depth = 0
    starts = []
    for i, ch in enumerate(s):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and ch in "OGDS" and i + 1 < len(s) and s[i + 1] == ":":
            starts.append(i)
    out = []
    for k, start in enumerate(starts):
        end = starts[k + 1] if k + 1 < len(starts) else len(s)
        out.append((s[start], s[start + 2 : end]))
    return out


def _split_aces(body):
    """Split a DACL/SACL body into its parenthesized ACE inner strings."""
    out = []
    i = 0
    while i < len(body):
        if body[i] == "(":
            j = body.find(")", i + 1)
            if j == -1:
                break
            out.append(body[i + 1 : j])
            i = j + 1
        else:
            i += 1
    return out
