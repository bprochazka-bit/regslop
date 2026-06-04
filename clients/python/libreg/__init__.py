"""libreg: a native Python binding for the libreg registry library.

This package links ``liblibreg.so`` (the libreg C ABI, `libreg/include/libreg.h`,
governed by `docs/ffi-abi.md`) directly through :mod:`ctypes`. It exposes every
registry operation libreg offers, in process, with no HTTP agent and nothing
outside the Python standard library. Build the shared object first:

    cd libreg && cargo build --release

Then:

    import libreg
    lib = libreg.Library()
    with lib.create("/tmp/demo.hive") as hive:
        hive.create_key("Software\\\\Example")
        hive.set_value("Software\\\\Example", "Greeting", libreg.RegType.SZ, "hi")
        hive.save()
"""

from . import sddl
from .client import (
    Hive,
    KeyInfo,
    KeyListing,
    Library,
    ValidationResult,
    ValueData,
)
from .errors import (
    ErrorCode,
    LibraryNotFound,
    LibregError,
    RegError,
    SddlError,
)
from .types import (
    RegType,
    canonical_data,
    decode_value,
    encode_value,
    type_name,
)

__version__ = "0.1.0"

__all__ = [
    "Library",
    "Hive",
    "RegType",
    "KeyListing",
    "KeyInfo",
    "ValueData",
    "ValidationResult",
    "RegError",
    "SddlError",
    "LibraryNotFound",
    "LibregError",
    "ErrorCode",
    "encode_value",
    "decode_value",
    "canonical_data",
    "type_name",
    "sddl",
    "__version__",
]
