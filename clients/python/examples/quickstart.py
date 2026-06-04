#!/usr/bin/env python3
"""End-to-end demo of the native libreg Python binding.

Build the shared library first:

    cd libreg && cargo build --release

Then run:

    python3 clients/python/examples/quickstart.py

It links liblibreg.so directly (no server), writes values of several types,
reads them back, sets an SDDL descriptor, validates, dumps the canonical form,
and saves.
"""

import json
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import libreg  # noqa: E402
from libreg import Library, RegType  # noqa: E402

HIVE_PATH = "/tmp/libreg-quickstart.hive"
KEY = "Software\\Example\\App"


def main():
    try:
        lib = Library()
    except libreg.LibraryNotFound as exc:
        print(exc)
        return 1

    print(f"Loaded {lib.version()}")

    with lib.create(HIVE_PATH) as hive:
        hive.create_key(KEY)
        hive.set_value(KEY, "Greeting", RegType.SZ, "hello world")
        hive.set_value(KEY, "Count", RegType.DWORD, 42)
        hive.set_value(KEY, "Big", RegType.QWORD, 2 ** 60)
        hive.set_value(KEY, "Names", RegType.MULTI_SZ, ["alice", "bob"])
        hive.set_value(KEY, "Blob", RegType.BINARY, b"\x00\xff\x10\x20")
        hive.set_value(KEY, "", RegType.SZ, "the default value")

        print(f"\nValues under {KEY}:")
        for name in hive.list_key(KEY).values:
            v = hive.get_value(KEY, name)
            shown = name or "(Default)"
            type_label = v.type.name if hasattr(v.type, "name") else v.type
            print(f"  {shown:12} {type_label:10} {v.data!r}")

        info = hive.key_info(KEY)
        print(f"\nKey info: {info.value_count} values, {info.subkey_count} subkeys")

        print(f"Default security (SDDL): {hive.get_security(KEY)}")
        hive.set_security(KEY, "O:SYG:SYD:(A;;KA;;;SY)(A;;KR;;;BU)")
        print(f"Updated security (SDDL): {hive.get_security(KEY)}")

        result = hive.validate()
        print(f"\nValidation: valid={result.valid} problems={result.problems}")

        hive.save()
        print(f"Saved to {HIVE_PATH}")

    with lib.load(HIVE_PATH) as hive:
        dump = hive.dump()
    print("\nCanonical dump (first 400 chars):")
    print(json.dumps(dump, indent=2, sort_keys=True)[:400] + " ...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
