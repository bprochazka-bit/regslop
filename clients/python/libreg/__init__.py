"""libreg: a pure standard library Python client for the libreg registry agent.

This package talks to the libreg HTTP agent (``agents/linux``, or the symmetric
Windows agent) over the protocol defined in CONTRACTS.md, exposing every
registry operation libreg offers: hive lifecycle, key and value operations,
security descriptors, and diagnostics. It depends on nothing outside the Python
standard library, so it runs on a stock Debian box with no pip install and no
compiler.

Quick start::

    from libreg import Agent, RegType

    agent = Agent(port=7878)            # the Linux agent's default port
    print(agent.version())             # handshake: agent, protocol, backend

    with agent.create("/tmp/demo.hiv") as hive:
        hive.create_key("Software\\\\Example")
        hive.set_value("Software\\\\Example", "Count", RegType.DWORD, 7)
        hive.save()
"""

from .client import (
    DEFAULT_LINUX_PORT,
    DEFAULT_WINDOWS_PORT,
    Agent,
    Checksums,
    Handshake,
    Hive,
    KeyInfo,
    KeyListing,
    ValidationResult,
    ValueData,
)
from .errors import ErrorCode, LibregError, RegError, TransportError
from .types import RegType, decode_data, encode_data

__version__ = "0.1.0"

__all__ = [
    "Agent",
    "Hive",
    "RegType",
    "Handshake",
    "KeyListing",
    "KeyInfo",
    "ValueData",
    "Checksums",
    "ValidationResult",
    "RegError",
    "TransportError",
    "LibregError",
    "ErrorCode",
    "encode_data",
    "decode_data",
    "DEFAULT_LINUX_PORT",
    "DEFAULT_WINDOWS_PORT",
    "__version__",
]
