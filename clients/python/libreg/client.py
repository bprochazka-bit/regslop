"""Pythonic surface over the libreg C ABI: :class:`Library` and :class:`Hive`.

This is a native, in-process binding: it links ``liblibreg.so`` directly
through :mod:`ctypes`, with no HTTP agent and no third-party packages. It
exposes every registry operation libreg offers (hive lifecycle, keys, values,
security, validation) plus a Python-side canonical :meth:`Hive.dump`.

    import libreg
    lib = libreg.Library()
    with lib.create("/tmp/demo.hive") as hive:
        hive.create_key("Software\\\\Example")
        hive.set_value("Software\\\\Example", "Count", libreg.RegType.DWORD, 7)
        hive.save()

Paths use the contract separator ``\\`` (a literal backslash), never start
with a separator, and ``""`` means the hive root. The default value is the
value named ``""``.
"""

import ctypes
from dataclasses import dataclass, field
from typing import Any, List, Optional

from . import _ffi, canonical, sddl
from .types import RegType, decode_value, encode_value


@dataclass(frozen=True)
class KeyListing:
    subkeys: List[str] = field(default_factory=list)
    values: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class KeyInfo:
    subkey_count: int
    value_count: int


@dataclass(frozen=True)
class ValueData:
    """A value read back: ``type`` (:class:`RegType` or raw int) and decoded
    native ``data``."""

    type: Any
    data: Any


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    problems: List[str] = field(default_factory=list)


class Library:
    """A loaded ``liblibreg.so``. Reusable; create one and open many hives."""

    def __init__(self, path=None):
        self._dll = _ffi.load_library(path)

    def __repr__(self):
        return f"Library(version={self.version()!r})"

    def version(self):
        """The backend id string, e.g. ``"libreg-0.1.0"``."""
        return self._dll.libreg_version().decode("utf-8")

    def create(self, path):
        """Create a new in-memory hive bound to ``path``; return its :class:`Hive`."""
        handle = ctypes.c_uint64(0)
        _ffi.check(self._dll, self._dll.libreg_hive_create(_ffi.enc(path), ctypes.byref(handle)))
        return Hive(self, handle.value, path)

    def load(self, path):
        """Load the hive file at ``path``; return its :class:`Hive`."""
        handle = ctypes.c_uint64(0)
        _ffi.check(self._dll, self._dll.libreg_hive_load(_ffi.enc(path), ctypes.byref(handle)))
        return Hive(self, handle.value, path)


class Hive:
    """An open hive handle. Obtain from :meth:`Library.create` / :meth:`Library.load`.

    Usable as a context manager (the handle is closed on exit). :meth:`save` is
    explicit, so call it before leaving the block to persist changes. Handles
    are not thread-safe: do not use one :class:`Hive` from two threads at once.
    """

    def __init__(self, lib, handle, path=None):
        self._lib = lib
        self._dll = lib._dll
        self._handle = handle
        self.path = path
        self._closed = False

    def __repr__(self):
        state = "closed" if self._closed else "open"
        return f"Hive(handle={self._handle}, path={self.path!r}, {state})"

    @property
    def handle(self):
        return self._handle

    @property
    def closed(self):
        return self._closed

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self._closed:
            self.close()
        return False

    def _check(self, status):
        _ffi.check(self._dll, status)

    def _guard(self):
        if self._closed:
            raise ValueError("operation on a closed hive handle")

    # --- lifecycle ---

    def save(self):
        """Write the hive (with transaction logs) back to its bound path."""
        self._guard()
        self._check(self._dll.libreg_hive_save(self._handle))

    def close(self):
        """Close the handle and free the hive on the library side. Idempotent."""
        if self._closed:
            return
        self._check(self._dll.libreg_hive_close(self._handle))
        self._closed = True

    # --- keys ---

    def create_key(self, path):
        """Create ``path``, materializing missing intermediates (RegCreateKeyEx)."""
        self._guard()
        self._check(self._dll.libreg_key_create(self._handle, _ffi.enc(path)))

    def delete_key(self, path, recursive=False):
        """Delete ``path``; without ``recursive`` a key with subkeys raises
        ``KEY_HAS_CHILDREN``."""
        self._guard()
        self._check(self._dll.libreg_key_delete(self._handle, _ffi.enc(path), 1 if recursive else 0))

    def rename_key(self, path, new_name):
        """Rename the key at ``path`` to ``new_name`` (single component), keeping
        its values, security, and subtree."""
        self._guard()
        self._check(self._dll.libreg_key_rename(self._handle, _ffi.enc(path), _ffi.enc(new_name)))

    def list_subkeys(self, path=""):
        """Return the immediate subkey names of ``path`` (root by default)."""
        return self._list(self._dll.libreg_key_list_subkeys, path)

    def list_values(self, path=""):
        """Return the value names of ``path`` (the default value is ``""``)."""
        return self._list(self._dll.libreg_key_list_values, path)

    def _list(self, fn, path):
        self._guard()
        ptr = _ffi._U8P()
        length = ctypes.c_size_t(0)
        count = ctypes.c_size_t(0)
        self._check(fn(self._handle, _ffi.enc(path), ctypes.byref(ptr), ctypes.byref(length), ctypes.byref(count)))
        buf = _ffi.take_buffer(self._dll, ptr, length.value)
        return _ffi.split_names(buf, count.value)

    def list_key(self, path=""):
        """Convenience: a :class:`KeyListing` of ``path``'s subkeys and values."""
        return KeyListing(subkeys=self.list_subkeys(path), values=self.list_values(path))

    def key_info(self, path=""):
        """Return :class:`KeyInfo` (subkey and value counts) for ``path``."""
        self._guard()
        subs = ctypes.c_uint64(0)
        vals = ctypes.c_uint64(0)
        self._check(self._dll.libreg_key_info(self._handle, _ffi.enc(path), ctypes.byref(subs), ctypes.byref(vals)))
        return KeyInfo(subkey_count=subs.value, value_count=vals.value)

    def key_class(self, path=""):
        """Return the class name of ``path`` as ``str``, or ``None`` if absent."""
        self._guard()
        ptr = _ffi._U8P()
        length = ctypes.c_size_t(0)
        self._check(self._dll.libreg_key_class(self._handle, _ffi.enc(path), ctypes.byref(ptr), ctypes.byref(length)))
        buf = _ffi.take_buffer(self._dll, ptr, length.value)
        return buf.decode("utf-8", "replace") if length.value else None

    # --- values ---

    def set_value(self, key, name, reg_type, data):
        """Set value ``name`` on ``key`` to ``data`` of type ``reg_type``.

        ``data`` is a native Python value (``str`` for string types, ``int``
        for DWORD/QWORD, ``bytes`` for binary types, ``list[str]`` for
        MULTI_SZ, ``None`` for REG_NONE); it is encoded to the on-disk bytes.
        """
        self._guard()
        rt = RegType.from_name(reg_type)
        raw = encode_value(rt, data)
        self._check(self._dll.libreg_value_set(self._handle, _ffi.enc(key), _ffi.enc(name), int(rt), raw, len(raw)))

    def get_value_raw(self, key, name):
        """Return ``(type_code:int, raw_bytes)`` for value ``name`` on ``key``."""
        self._guard()
        vt = ctypes.c_uint32(0)
        ptr = _ffi._U8P()
        length = ctypes.c_size_t(0)
        self._check(self._dll.libreg_value_get(
            self._handle, _ffi.enc(key), _ffi.enc(name),
            ctypes.byref(vt), ctypes.byref(ptr), ctypes.byref(length),
        ))
        return vt.value, _ffi.take_buffer(self._dll, ptr, length.value)

    def get_value(self, key, name):
        """Return the :class:`ValueData` (type + decoded native data) for ``name``."""
        type_code, raw = self.get_value_raw(key, name)
        try:
            rt = RegType(type_code)
        except ValueError:
            rt = type_code  # unknown code: keep the raw int, data stays bytes
        return ValueData(type=rt, data=decode_value(type_code, raw))

    def delete_value(self, key, name):
        """Delete value ``name`` from ``key`` (``name=""`` is the default value)."""
        self._guard()
        self._check(self._dll.libreg_value_delete(self._handle, _ffi.enc(key), _ffi.enc(name)))

    # --- security ---

    def get_security_bytes(self, path=""):
        """Return the raw binary self-relative security descriptor of ``path``."""
        self._guard()
        ptr = _ffi._U8P()
        length = ctypes.c_size_t(0)
        self._check(self._dll.libreg_key_security_get(self._handle, _ffi.enc(path), ctypes.byref(ptr), ctypes.byref(length)))
        return _ffi.take_buffer(self._dll, ptr, length.value)

    def set_security_bytes(self, path, desc):
        """Set the raw binary security descriptor of ``path``."""
        self._guard()
        desc = bytes(desc)
        self._check(self._dll.libreg_key_security_set(self._handle, _ffi.enc(path), desc, len(desc)))

    def get_security(self, path=""):
        """Return the SDDL string for ``path`` (converted from the binary form)."""
        return sddl.to_sddl(self.get_security_bytes(path))

    def set_security(self, path, sddl_string):
        """Set the security descriptor for ``path`` from an SDDL string."""
        self.set_security_bytes(path, sddl.from_sddl(sddl_string))

    # --- diagnostics ---

    def validate(self):
        """Run libreg's structural validation; return a :class:`ValidationResult`."""
        self._guard()
        ptr = _ffi._U8P()
        length = ctypes.c_size_t(0)
        count = ctypes.c_size_t(0)
        self._check(self._dll.libreg_validate(self._handle, ctypes.byref(ptr), ctypes.byref(length), ctypes.byref(count)))
        buf = _ffi.take_buffer(self._dll, ptr, length.value)
        problems = _ffi.split_names(buf, count.value)
        return ValidationResult(valid=(count.value == 0), problems=problems)

    def dump(self, include_last_write=True):
        """Return the CONTRACTS canonical JSON form of the hive as a ``dict``.

        Built Python-side from the enumeration primitives (the C ABI does not
        serialize canonical JSON itself), matching `agents/linux/src/canonical.rs`.
        The C ABI does not expose ``last_write`` (the semantic differ ignores
        timestamps), so a fixed placeholder is emitted; pass
        ``include_last_write=False`` to omit the field entirely.
        """
        return canonical.build_dump(self, include_last_write=include_last_write)
