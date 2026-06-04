"""Exceptions and error codes for the libreg Python client.

The agent returns a uniform envelope (CONTRACTS.md): on failure it carries a
stable ``code`` field drawn from the contract's error table plus a human
readable ``error`` message. We surface that as :class:`RegError`, keyed by the
same code strings so callers can match programmatically without parsing text.

Transport problems (connection refused, a truncated or non JSON body) are a
different class of failure: the agent never spoke a valid envelope, so they
raise :class:`TransportError`, not :class:`RegError`.
"""


class ErrorCode:
    """Stable error code strings from the CONTRACTS.md error table.

    These are the exact values the agent puts in the envelope ``code`` field.
    Compare against ``RegError.code`` rather than the message text.
    """

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

    #: All codes the contract defines, for validation and iteration.
    ALL = (
        HIVE_NOT_FOUND,
        HIVE_CORRUPT,
        HANDLE_INVALID,
        KEY_NOT_FOUND,
        KEY_EXISTS,
        VALUE_NOT_FOUND,
        TYPE_MISMATCH,
        ACCESS_DENIED,
        LOG_CORRUPT,
        KEY_HAS_CHILDREN,
        BAD_REQUEST,
        INTERNAL,
    )


class LibregError(Exception):
    """Base class for every error this client raises."""


class TransportError(LibregError):
    """The agent could not be reached or did not return a valid envelope.

    This is a connection level problem (refused, timed out, truncated body,
    non JSON payload), distinct from a registry operation that the agent
    processed and rejected (which is a :class:`RegError`).
    """


class RegError(LibregError):
    """A registry operation the agent processed and rejected.

    ``code`` is one of :class:`ErrorCode`; ``message`` is the agent's human
    readable explanation. ``str(err)`` is ``"CODE: message"``.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
