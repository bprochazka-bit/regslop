"""End-to-end tests against the built ``liblibreg.so``.

Skipped automatically if the library cannot be loaded (build it with
``cd libreg && cargo build --release``, or set ``$LIBREG_LIBRARY``).
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import libreg  # noqa: E402
from libreg import ErrorCode, Library, RegError, RegType  # noqa: E402

try:
    _LIB = Library()
    _LOAD_ERROR = None
except libreg.LibraryNotFound as exc:  # pragma: no cover
    _LIB = None
    _LOAD_ERROR = exc

DEFAULT_SDDL = "O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)"


@unittest.skipIf(_LIB is None, f"liblibreg.so not loadable: {_LOAD_ERROR}")
class FfiTest(unittest.TestCase):
    def setUp(self):
        self.lib = _LIB
        fd, self.path = tempfile.mkstemp(suffix=".hive")
        os.close(fd)
        os.unlink(self.path)  # create() binds the path; file appears on save()

    def tearDown(self):
        for p in (self.path, self.path + ".LOG1", self.path + ".LOG2"):
            try:
                os.unlink(p)
            except OSError:
                pass

    def test_version(self):
        self.assertTrue(self.lib.version().startswith("libreg-"))

    def test_all_value_types_round_trip(self):
        key = "Software\\Example"
        cases = [
            (RegType.SZ, "hello world", "hello world"),
            (RegType.EXPAND_SZ, "%PATH%", "%PATH%"),
            (RegType.LINK, "\\Registry\\X", "\\Registry\\X"),
            (RegType.DWORD, 0xDEADBEEF, 0xDEADBEEF),
            (RegType.DWORD_BE, 0x01020304, 0x01020304),
            (RegType.QWORD, (1 << 60) + 7, (1 << 60) + 7),
            (RegType.MULTI_SZ, ["a", "bb", "ccc"], ["a", "bb", "ccc"]),
            (RegType.BINARY, bytes(range(8)), bytes(range(8))),
            (RegType.NONE, None, None),
        ]
        with self.lib.create(self.path) as hive:
            hive.create_key(key)
            for rt, value, _ in cases:
                hive.set_value(key, rt.name, rt, value)
            hive.save()

        with self.lib.load(self.path) as hive:
            for rt, _, expected in cases:
                got = hive.get_value(key, rt.name)
                self.assertEqual(got.type, rt, rt)
                self.assertEqual(got.data, expected, rt)

    def test_default_value_and_listing(self):
        with self.lib.create(self.path) as hive:
            hive.create_key("A\\B")
            hive.set_value("A", "", RegType.SZ, "default")
            hive.set_value("A", "named", RegType.DWORD, 1)
            listing = hive.list_key("A")
            self.assertIn("B", listing.subkeys)
            self.assertIn("", listing.values)
            self.assertIn("named", listing.values)
            info = hive.key_info("A")
            self.assertEqual(info.subkey_count, 1)
            self.assertEqual(info.value_count, 2)
            self.assertEqual(hive.get_value("A", "").data, "default")

    def test_create_existing_is_key_exists(self):
        with self.lib.create(self.path) as hive:
            hive.create_key("Dup")
            with self.assertRaises(RegError) as ctx:
                hive.create_key("Dup")
            self.assertEqual(ctx.exception.code, ErrorCode.KEY_EXISTS)

    def test_delete_with_children_requires_recursive(self):
        with self.lib.create(self.path) as hive:
            hive.create_key("P\\C")
            with self.assertRaises(RegError) as ctx:
                hive.delete_key("P", recursive=False)
            self.assertEqual(ctx.exception.code, ErrorCode.KEY_HAS_CHILDREN)
            hive.delete_key("P", recursive=True)
            self.assertNotIn("P", hive.list_subkeys(""))

    def test_value_not_found(self):
        with self.lib.create(self.path) as hive:
            hive.create_key("K")
            with self.assertRaises(RegError) as ctx:
                hive.get_value("K", "nope")
            self.assertEqual(ctx.exception.code, ErrorCode.VALUE_NOT_FOUND)

    def test_rename_preserves_values(self):
        with self.lib.create(self.path) as hive:
            hive.create_key("Old\\Child")
            hive.set_value("Old", "v", RegType.SZ, "keep")
            hive.rename_key("Old", "New")
            self.assertIn("New", hive.list_subkeys(""))
            self.assertNotIn("Old", hive.list_subkeys(""))
            self.assertEqual(hive.get_value("New", "v").data, "keep")
            self.assertIn("Child", hive.list_subkeys("New"))

    def test_security_sddl_round_trip(self):
        with self.lib.create(self.path) as hive:
            hive.create_key("Sec")
            # A freshly created key carries the ratified default descriptor.
            self.assertEqual(hive.get_security("Sec"), DEFAULT_SDDL)
            custom = "O:SYG:SYD:(A;;KA;;;SY)(A;;KR;;;BU)"
            hive.set_security("Sec", custom)
            self.assertEqual(hive.get_security("Sec"), custom)

    def test_security_bytes_match_python_codec(self):
        # The library is the oracle: the raw default descriptor it stores must
        # equal what our Python SDDL->binary codec produces for the same SDDL.
        from libreg import sddl as sddl_mod
        with self.lib.create(self.path) as hive:
            hive.create_key("Sec")
            self.assertEqual(hive.get_security_bytes("Sec"), sddl_mod.from_sddl(DEFAULT_SDDL))

    def test_validate_clean(self):
        with self.lib.create(self.path) as hive:
            hive.create_key("Software\\X")
            hive.set_value("Software\\X", "v", RegType.DWORD, 5)
            result = hive.validate()
            self.assertTrue(result.valid, result.problems)

    def test_dump_canonical_shape(self):
        with self.lib.create(self.path) as hive:
            hive.create_key("Software\\App")
            hive.set_value("Software\\App", "Greeting", RegType.SZ, "hi")
            hive.set_value("Software\\App", "Count", RegType.DWORD, 7)
            hive.set_value("Software\\App", "Blob", RegType.BINARY, b"\x00\xff")
            dump = hive.dump()

        self.assertEqual(dump["format_version"], "0.1.0")
        root = dump["root"]
        self.assertEqual(root["name"], "")
        self.assertEqual(root["security"]["sddl"], DEFAULT_SDDL)
        software = next(k for k in root["subkeys"] if k["name"] == "Software")
        app = next(k for k in software["subkeys"] if k["name"] == "App")
        # values are sorted by name (case-insensitive): Blob, Count, Greeting
        self.assertEqual([v["name"] for v in app["values"]], ["Blob", "Count", "Greeting"])
        by_name = {v["name"]: v for v in app["values"]}
        self.assertEqual(by_name["Greeting"], {"name": "Greeting", "type": "REG_SZ", "data": "hi"})
        self.assertEqual(by_name["Count"]["type"], "REG_DWORD")
        self.assertEqual(by_name["Count"]["data"], 7)
        self.assertEqual(by_name["Blob"]["type"], "REG_BINARY")
        self.assertEqual(by_name["Blob"]["data"], "AP8=")  # base64 of 00 ff

    def test_closed_handle_rejects_ops(self):
        hive = self.lib.create(self.path)
        hive.close()
        self.assertTrue(hive.closed)
        hive.close()  # idempotent
        with self.assertRaises(ValueError):
            hive.create_key("X")


if __name__ == "__main__":
    unittest.main()
