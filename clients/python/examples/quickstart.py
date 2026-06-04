#!/usr/bin/env python3
"""End to end demo of the libreg Python client against a running agent.

Start the Linux agent first (it listens on 7878 by default):

    cd agents/linux && cargo run --release

Then run this script:

    python3 clients/python/examples/quickstart.py

It creates a hive, writes a few values of different types, reads them back,
inspects the key, dumps the canonical form, validates, and saves.
"""

import sys

# Allow running straight from the repo without installing the package.
sys.path.insert(0, __file__.rsplit("/", 2)[0])

from libreg import Agent, RegError, RegType, TransportError  # noqa: E402

HIVE_PATH = "/tmp/libreg-quickstart.hiv"
KEY = "Software\\Example\\App"


def main():
    agent = Agent(port=7878)

    try:
        handshake = agent.version()
    except TransportError as exc:
        print(f"Could not reach the agent on port 7878: {exc}")
        print("Start it with: cd agents/linux && cargo run --release")
        return 1

    print(f"Connected: agent={handshake.agent} backend={handshake.backend}")

    with agent.create(HIVE_PATH) as hive:
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
            print(f"  {shown:12} {v.type.value:14} {v.data!r}")

        info = hive.key_info(KEY)
        print(f"\nKey info: {info.value_count} values, {info.subkey_count} subkeys")
        print(f"Security: {hive.get_security(KEY)}")

        result = hive.validate()
        print(f"\nValidation: valid={result.valid} "
              f"errors={len(result.errors)} warnings={len(result.warnings)}")

        written = hive.save()
        print(f"Saved {written} bytes to {HIVE_PATH}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RegError as exc:
        print(f"Registry error [{exc.code}]: {exc.message}")
        raise SystemExit(1)
