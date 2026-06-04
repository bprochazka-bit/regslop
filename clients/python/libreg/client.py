"""HTTP client for a libreg agent.

The Linux agent (``agents/linux``) wraps libreg behind the HTTP protocol in
CONTRACTS.md and exposes every registry operation the library offers: hive
lifecycle, key and value operations, security descriptors, and diagnostics.
This client speaks that protocol with nothing but the Python standard library,
so it installs and runs on a stock Debian box without pip or a compiler.

The same protocol is implemented by the Windows agent (``agents/windows``), so
this client drives either side interchangeably; point it at whichever port the
agent you want is listening on.

Typical use::

    from libreg import Agent, RegType

    agent = Agent(port=7878)
    with agent.create("/tmp/demo.hiv") as hive:
        hive.create_key("Software\\\\Example")
        hive.set_value("Software\\\\Example", "Greeting", RegType.SZ, "hello")
        hive.save()

Reads are GET and writes are POST, both carrying a JSON body, exactly as the
contract specifies (a GET request therefore carries a body; this is
intentional, see ADR 0001).
"""

import http.client
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .errors import RegError, TransportError
from .types import RegType, decode_data, encode_data

#: Default ports from CONTRACTS.md (Linux agent 7878, Windows agent 7879).
DEFAULT_LINUX_PORT = 7878
DEFAULT_WINDOWS_PORT = 7879


@dataclass(frozen=True)
class Handshake:
    """Result of ``GET /version``."""

    agent: str
    protocol: str
    backend: str


@dataclass(frozen=True)
class KeyListing:
    """Result of ``GET /key/list``: immediate child names of a key."""

    subkeys: List[str] = field(default_factory=list)
    values: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class KeyInfo:
    """Result of ``GET /key/info``."""

    last_write: str
    class_name: Optional[str]
    subkey_count: int
    value_count: int


@dataclass(frozen=True)
class ValueData:
    """A typed value read back from ``GET /value/get``.

    ``type`` is a :class:`RegType`; ``data`` is the decoded native Python value
    (``bytes`` for binary types, ``int`` for DWORD/QWORD, ``list[str]`` for
    MULTI_SZ, ``str`` for string types, ``None`` for REG_NONE).
    """

    type: RegType
    data: Any


@dataclass(frozen=True)
class Checksums:
    """Result of ``GET /hive/checksum``."""

    sha256_file: str
    sha256_canonical: str


@dataclass(frozen=True)
class ValidationResult:
    """Result of ``GET /hive/validate``."""

    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class Agent:
    """A connection to one libreg HTTP agent.

    An ``Agent`` is cheap and stateless: each call opens a short lived HTTP
    connection, so a single instance is safe to reuse across many operations.
    Use :meth:`create` or :meth:`load` to obtain a :class:`Hive`.
    """

    def __init__(self, host="127.0.0.1", port=DEFAULT_LINUX_PORT, timeout=30.0):
        self.host = host
        self.port = int(port)
        self.timeout = timeout

    def __repr__(self):
        return f"Agent(host={self.host!r}, port={self.port})"

    # --- transport ---

    def request(self, method, path, body=None):
        """Send one request and return the envelope ``data`` payload.

        Raises :class:`~libreg.errors.RegError` when the agent rejects the
        operation (envelope ``ok: false``) and
        :class:`~libreg.errors.TransportError` for connection level failures or
        a malformed envelope. Mostly used internally, but exposed so callers can
        reach an endpoint this client does not yet wrap.
        """
        payload = json.dumps(body or {}).encode("utf-8")
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request(
                method,
                path,
                body=payload,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(payload)),
                },
            )
            resp = conn.getresponse()
            raw = resp.read()
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError(
                f"{method} {path} to {self.host}:{self.port} failed: {exc}"
            ) from exc
        finally:
            conn.close()

        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise TransportError(
                f"{method} {path}: response was not valid JSON: {exc}"
            ) from exc

        if not isinstance(envelope, dict) or "ok" not in envelope:
            raise TransportError(f"{method} {path}: malformed envelope: {raw!r}")

        if not envelope.get("ok", False):
            code = envelope.get("code") or "INTERNAL"
            message = envelope.get("error") or "unspecified error"
            raise RegError(code, message)

        return envelope.get("data")

    # --- handshake ---

    def version(self):
        """Return the agent :class:`Handshake` (``GET /version``)."""
        data = self.request("GET", "/version")
        return Handshake(
            agent=data["agent"], protocol=data["protocol"], backend=data["backend"]
        )

    # --- hive lifecycle ---

    def create(self, path):
        """Create a new hive at ``path`` on the agent and return its :class:`Hive`."""
        data = self.request("POST", "/hive/create", {"path": path})
        return Hive(self, data["handle"], path)

    def load(self, path):
        """Load an existing hive at ``path`` and return its :class:`Hive`."""
        data = self.request("POST", "/hive/load", {"path": path})
        return Hive(self, data["handle"], path)


class Hive:
    """An open hive handle on an agent.

    Obtain one from :meth:`Agent.create` or :meth:`Agent.load`. All paths use
    the contract separator ``\\`` (a literal backslash), never start with a
    separator, and the empty string ``""`` means the hive root. Mutations are
    in memory on the agent until :meth:`save` writes them to disk.

    Usable as a context manager; the handle is closed on exit. ``save()`` is
    not automatic, so call it before leaving the block if you want the changes
    persisted.
    """

    def __init__(self, agent, handle, path=None):
        self._agent = agent
        self._handle = handle
        self.path = path
        self._closed = False

    def __repr__(self):
        state = "closed" if self._closed else "open"
        return f"Hive(handle={self._handle!r}, path={self.path!r}, {state})"

    @property
    def handle(self):
        """The opaque handle string the agent assigned to this hive."""
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

    def _call(self, method, path, body):
        if self._closed:
            raise ValueError("operation on a closed hive handle")
        merged = {"handle": self._handle}
        merged.update(body)
        return self._agent.request(method, path, merged)

    # --- lifecycle ---

    def save(self):
        """Write the hive (with transaction logs) to disk; return bytes written."""
        data = self._call("POST", "/hive/save", {})
        return data["bytes_written"]

    def close(self):
        """Release the handle on the agent. Idempotent."""
        if self._closed:
            return
        self._call("POST", "/hive/close", {})
        self._closed = True

    # --- key operations ---

    def create_key(self, path):
        """Create ``path``, materializing every missing intermediate component.

        Mirrors ``RegCreateKeyEx``: existing intermediates are reused, and only
        a pre existing leaf raises ``KEY_EXISTS``.
        """
        self._call("POST", "/key/create", {"path": path})

    def delete_key(self, path, recursive=False):
        """Delete ``path``. Without ``recursive`` a key with subkeys raises
        ``KEY_HAS_CHILDREN``."""
        self._call("POST", "/key/delete", {"path": path, "recursive": recursive})

    def rename_key(self, path, new_name):
        """Rename the key at ``path`` to ``new_name``, preserving its subtree."""
        self._call("POST", "/key/rename", {"path": path, "new_name": new_name})

    def list_key(self, path=""):
        """Return the immediate :class:`KeyListing` of ``path`` (root by default)."""
        data = self._call("GET", "/key/list", {"path": path})
        return KeyListing(
            subkeys=list(data.get("subkeys", [])),
            values=list(data.get("values", [])),
        )

    def key_info(self, path=""):
        """Return :class:`KeyInfo` for ``path`` (root by default)."""
        data = self._call("GET", "/key/info", {"path": path})
        return KeyInfo(
            last_write=data["last_write"],
            class_name=data.get("class_name"),
            subkey_count=data["subkey_count"],
            value_count=data["value_count"],
        )

    # --- value operations ---

    def set_value(self, key, name, reg_type, data):
        """Set value ``name`` on ``key`` to ``data`` of type ``reg_type``.

        ``data`` is a native Python value encoded per :func:`libreg.encode_data`
        (``bytes`` for binary types, ``int`` for DWORD/QWORD, ``list[str]`` for
        MULTI_SZ, ``str`` for string types, ``None`` for REG_NONE). The default
        value is ``name=""``.
        """
        reg_type = RegType.from_wire(reg_type)
        self._call(
            "POST",
            "/value/set",
            {
                "key": key,
                "name": name,
                "type": reg_type.value,
                "data": encode_data(reg_type, data),
            },
        )

    def get_value(self, key, name):
        """Return the :class:`ValueData` for value ``name`` on ``key``."""
        data = self._call("GET", "/value/get", {"key": key, "name": name})
        reg_type = RegType.from_wire(data["type"])
        return ValueData(type=reg_type, data=decode_data(reg_type, data["data"]))

    def delete_value(self, key, name):
        """Delete value ``name`` from ``key`` (``name=""`` is the default value)."""
        self._call("POST", "/value/delete", {"key": key, "name": name})

    # --- security ---

    def get_security(self, path=""):
        """Return the SDDL security descriptor string for ``path``."""
        data = self._call("GET", "/key/security", {"path": path})
        return data["sddl"]

    def set_security(self, path, sddl):
        """Set the security descriptor for ``path`` from an SDDL string."""
        self._call("POST", "/key/security", {"path": path, "sddl": sddl})

    # --- diagnostics ---

    def dump(self):
        """Return the canonical JSON form of the whole hive (a ``dict``)."""
        data = self._call("GET", "/hive/dump", {})
        return data["canonical_json"]

    def checksum(self):
        """Return the file and canonical :class:`Checksums` for the hive."""
        data = self._call("GET", "/hive/checksum", {})
        return Checksums(
            sha256_file=data["sha256_file"],
            sha256_canonical=data["sha256_canonical"],
        )

    def validate(self):
        """Run the agent's structural validation and return a :class:`ValidationResult`."""
        data = self._call("GET", "/hive/validate", {})
        return ValidationResult(
            valid=data["valid"],
            errors=list(data.get("errors", [])),
            warnings=list(data.get("warnings", [])),
        )

    # --- test mode (Linux/libreg agent only) ---

    def crash_save(self, point):
        """Drive a recoverable, truncated save for the ``recovery`` tests.

        Only the Linux/libreg agent implements ``POST /test/crash_save``; the
        Windows (offreg) agent does not. ``point`` is one of
        ``after_log_before_primary``, ``after_first_log``, ``after_primary``.
        Returns the raw ``{"bytes_written", "crashed_at"}`` payload. The handle
        may be consumed by this call, so treat the hive as needing a reload by
        path afterward.
        """
        return self._call("POST", "/test/crash_save", {"point": point})
