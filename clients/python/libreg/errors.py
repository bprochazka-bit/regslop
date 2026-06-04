"""Exceptions and error codes for the libreg native binding.

The C ABI reports every outcome as a `libreg_status` integer that maps 1:1 to
the CONTRACTS.md error-code table (see `docs/ffi-abi.md`). A non-zero status is
raised here as :class:`RegError`, carrying both the stable code name and the
thread-local detail string from ``libreg_last_error()``.

Failing to load the shared library itself (it is missing, or not the expected
ABI) is a different class of problem and raises :class:`LibraryNotFound`.
"""


class ErrorCode:
    """Stable error-code names, indexed by the C ABI's integer values.

    The integers are fixed by `docs/ffi-abi.md` (success 0, then the
    CONTRACTS.md error table in order). Compare ``RegError.code`` against these
    name constants rather than the message text.
    """

    OK = "OK"
    HIVE_NOT_FOUND = "HIVE_NOT_FOUND"
    HIVE_CORRUPT = "HIVE_CORRUPT"
    HANDLE_INVALID = "HANDLE_INVALID"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    KEY_EXISTS = "KEY_EXISTS"
    VALUE_NOT_FOUND = "VALUE_NOT_FOUND"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    ACCESS_DENIED = "ACCESS_DENIED"
    LOG_CORRUPT = "LOG_CORRUPT"
    KEY_HAS_CHILDREN = "KEY_HAS_CHILDREN"
    BAD_REQUEST = "BAD_REQUEST"
    INTERNAL = "INTERNAL"

    #: Index by libreg_status integer -> code name (ffi-abi.md section 1).
    BY_INT = {
        0: OK,
        1: HIVE_NOT_FOUND,
        2: HIVE_CORRUPT,
        3: HANDLE_INVALID,
        4: KEY_NOT_FOUND,
        5: KEY_EXISTS,
        6: VALUE_NOT_FOUND,
        7: TYPE_MISMATCH,
        8: ACCESS_DENIED,
        9: LOG_CORRUPT,
        10: KEY_HAS_CHILDREN,
        11: BAD_REQUEST,
        12: INTERNAL,
    }

    @classmethod
    def from_int(cls, value):
        """Map a ``libreg_status`` integer to its code name (unknown -> INTERNAL)."""
        return cls.BY_INT.get(value, cls.INTERNAL)


class LibregError(Exception):
    """Base class for every error this binding raises."""


class LibraryNotFound(LibregError):
    """The libreg shared library could not be located or loaded."""


class RegError(LibregError):
    """A registry operation the library rejected (non-zero ``libreg_status``).

    ``code`` is one of :class:`ErrorCode`; ``code_int`` is the raw status;
    ``message`` is the library's thread-local detail string. ``str(err)`` is
    ``"CODE: message"``.
    """

    def __init__(self, code, message, code_int=None):
        self.code = code
        self.message = message
        self.code_int = code_int
        super().__init__(f"{code}: {message}")


class SddlError(LibregError, ValueError):
    """An SDDL string or binary security descriptor could not be converted."""
