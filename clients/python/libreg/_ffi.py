"""Low-level ctypes binding to ``liblibreg.so`` (the libreg C ABI).

This module locates and loads the shared library, declares the signatures of
the 20 ``libreg_*`` symbols from `libreg/include/libreg.h`, and provides thin
helpers that check the ``libreg_status`` return and read the library-owned
``(pointer, length)`` out-buffers (freeing them with ``libreg_free``). The
Pythonic surface lives in :mod:`libreg.client`.
"""

import ctypes
import os

from .errors import ErrorCode, LibraryNotFound, RegError

_U8 = ctypes.c_uint8
_U8P = ctypes.POINTER(_U8)
_SIZE = ctypes.c_size_t


def _candidate_paths():
    """Where to look for the shared library, in priority order."""
    env = os.environ.get("LIBREG_LIBRARY")
    if env:
        yield env
    # Repo-relative build outputs, resolved from this file's location
    # (clients/python/libreg/_ffi.py -> repo root is three levels up).
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    for profile in ("release", "debug"):
        yield os.path.join(repo, "libreg", "target", profile, "liblibreg.so")
    # Finally, let the dynamic loader search (LD_LIBRARY_PATH / system paths).
    yield "liblibreg.so"


def load_library(path=None):
    """Load ``liblibreg.so`` and return a configured ``ctypes.CDLL``.

    Tries ``path`` if given, else ``$LIBREG_LIBRARY``, the repo build outputs,
    and the dynamic loader's search path. Raises :class:`LibraryNotFound` if
    none load.
    """
    candidates = [path] if path else list(_candidate_paths())
    last = None
    for cand in candidates:
        if not cand:
            continue
        try:
            dll = ctypes.CDLL(cand)
        except OSError as exc:
            last = exc
            continue
        _declare(dll)
        return dll
    raise LibraryNotFound(
        "could not load liblibreg.so. Build it with "
        "`cd libreg && cargo build --release`, or set $LIBREG_LIBRARY. "
        f"Tried: {[c for c in candidates if c]}. Last error: {last}"
    )


def _declare(dll):
    """Set argtypes/restype for every exported symbol."""
    c = ctypes
    dll.libreg_version.argtypes = []
    dll.libreg_version.restype = c.c_char_p
    dll.libreg_last_error.argtypes = []
    dll.libreg_last_error.restype = c.c_char_p
    dll.libreg_free.argtypes = [_U8P, _SIZE]
    dll.libreg_free.restype = None

    U64 = c.c_uint64
    U64P = c.POINTER(U64)
    STR = c.c_char_p
    INT = c.c_int
    STATUS = c.c_int

    dll.libreg_hive_create.argtypes = [STR, U64P]
    dll.libreg_hive_load.argtypes = [STR, U64P]
    dll.libreg_hive_save.argtypes = [U64]
    dll.libreg_hive_close.argtypes = [U64]

    dll.libreg_key_create.argtypes = [U64, STR]
    dll.libreg_key_delete.argtypes = [U64, STR, INT]
    dll.libreg_key_rename.argtypes = [U64, STR, STR]
    dll.libreg_key_list_subkeys.argtypes = [U64, STR, c.POINTER(_U8P), c.POINTER(_SIZE), c.POINTER(_SIZE)]
    dll.libreg_key_list_values.argtypes = [U64, STR, c.POINTER(_U8P), c.POINTER(_SIZE), c.POINTER(_SIZE)]
    dll.libreg_key_info.argtypes = [U64, STR, U64P, U64P]
    dll.libreg_key_class.argtypes = [U64, STR, c.POINTER(_U8P), c.POINTER(_SIZE)]

    dll.libreg_value_set.argtypes = [U64, STR, STR, c.c_uint32, STR, _SIZE]
    dll.libreg_value_get.argtypes = [U64, STR, STR, c.POINTER(c.c_uint32), c.POINTER(_U8P), c.POINTER(_SIZE)]
    dll.libreg_value_delete.argtypes = [U64, STR, STR]

    dll.libreg_key_security_get.argtypes = [U64, STR, c.POINTER(_U8P), c.POINTER(_SIZE)]
    dll.libreg_key_security_set.argtypes = [U64, STR, STR, _SIZE]

    dll.libreg_validate.argtypes = [U64, c.POINTER(_U8P), c.POINTER(_SIZE), c.POINTER(_SIZE)]

    for name in (
        "hive_create", "hive_load", "hive_save", "hive_close",
        "key_create", "key_delete", "key_rename", "key_list_subkeys",
        "key_list_values", "key_info", "key_class",
        "value_set", "value_get", "value_delete",
        "key_security_get", "key_security_set", "validate",
    ):
        getattr(dll, "libreg_" + name).restype = STATUS


def enc(s):
    """Encode a Python str path/name to a UTF-8 C string (None -> None)."""
    if s is None:
        return None
    if isinstance(s, bytes):
        return s
    return s.encode("utf-8")


def check(dll, status):
    """Raise :class:`RegError` if ``status`` is non-zero."""
    if status != 0:
        detail = dll.libreg_last_error() or b""
        raise RegError(ErrorCode.from_int(status), detail.decode("utf-8", "replace"), status)


def take_buffer(dll, ptr, length):
    """Copy a library-owned ``(ptr, len)`` buffer to ``bytes`` and free it."""
    if not ptr:
        return b""
    try:
        return ctypes.string_at(ptr, length)
    finally:
        dll.libreg_free(ptr, length)


def split_names(buf, count):
    """Split a ``name0\\0name1\\0...`` buffer into ``count`` UTF-8 strings."""
    if not buf:
        return []
    parts = buf.split(b"\x00")
    return [p.decode("utf-8", "replace") for p in parts[:count]]
