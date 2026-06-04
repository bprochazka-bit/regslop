"""Build the CONTRACTS.md canonical JSON form from a hive, Python-side.

The C ABI deliberately does not serialize canonical JSON (that would be a
second implementation of the harness's semantic oracle, which could drift; see
`docs/ffi-abi.md`). Instead it exposes enumeration primitives, and this module
assembles them into the same structure `agents/linux/src/canonical.rs` emits, so
the result can be compared semantically against the agent's ``/hive/dump``.

Rules mirrored from `canonical.rs`:

- ``subkeys`` and ``values`` are sorted by name using a case-insensitive
  comparison (uppercased), original casing preserved.
- ``class_name`` is the class string, or ``null`` when absent (length 0).
- each value is ``{name, type, data}`` with ``data`` in the canonical encoding
  (base64 for binary, decimal string for a QWORD above 2^53, etc.).
- ``security`` is ``{"sddl": ...}``.

The C ABI does not expose ``last_write`` (the semantic differ ignores
timestamps), so a fixed placeholder is emitted to keep the schema identical.
"""

from .types import canonical_data, type_name

FORMAT_VERSION = "0.1.0"

#: Emitted for every key's ``last_write``: the C ABI does not expose timestamps,
#: and the semantic differ ignores this field. Not a real hive timestamp.
LAST_WRITE_PLACEHOLDER = "1601-01-01T00:00:00Z"


def _name_key(name):
    """Sort key matching `canonical.rs::name_cmp` (uppercased, then original)."""
    return (name.upper(), name)


def build_dump(hive, include_last_write=True):
    """Return ``{"format_version", "root": <key>}`` for ``hive``."""
    return {
        "format_version": FORMAT_VERSION,
        "root": _dump_key(hive, "", "", include_last_write),
    }


def _dump_key(hive, path, name, include_last_write):
    value_names = sorted(hive.list_values(path), key=_name_key)
    values = []
    for vn in value_names:
        type_code, raw = hive.get_value_raw(path, vn)
        values.append({
            "name": vn,
            "type": type_name(type_code),
            "data": canonical_data(type_code, raw),
        })

    subkeys = []
    for sub in sorted(hive.list_subkeys(path), key=_name_key):
        child_path = f"{path}\\{sub}" if path else sub
        subkeys.append(_dump_key(hive, child_path, sub, include_last_write))

    cls = hive.key_class(path)
    key = {
        "name": name,
        "class_name": cls if cls else None,
        "security": {"sddl": hive.get_security(path)},
        "values": values,
        "subkeys": subkeys,
    }
    if include_last_write:
        key["last_write"] = LAST_WRITE_PLACEHOLDER
    return key
