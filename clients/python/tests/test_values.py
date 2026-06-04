"""Tests for the value codec (no library needed).

These pin the binary-native encodings against the byte layouts in
`agents/linux/src/valuec.rs`, and the canonical view against `canonical.rs`.
"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from libreg import RegType, canonical_data, decode_value, encode_value, type_name  # noqa: E402


class ValueCodecTest(unittest.TestCase):
    def test_dword_endianness(self):
        self.assertEqual(encode_value(RegType.DWORD, 0x12345678), bytes([0x78, 0x56, 0x34, 0x12]))
        self.assertEqual(encode_value(RegType.DWORD_BE, 0x12345678), bytes([0x12, 0x34, 0x56, 0x78]))
        self.assertEqual(decode_value(RegType.DWORD, bytes([0x78, 0x56, 0x34, 0x12])), 0x12345678)
        self.assertEqual(decode_value(RegType.DWORD_BE, bytes([0x12, 0x34, 0x56, 0x78])), 0x12345678)

    def test_dword_range(self):
        with self.assertRaises(ValueError):
            encode_value(RegType.DWORD, 2 ** 32)
        with self.assertRaises(TypeError):
            encode_value(RegType.DWORD, True)

    def test_qword_native_and_canonical(self):
        raw = encode_value(RegType.QWORD, 0x1122334455667788)
        self.assertEqual(raw, bytes([0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]))
        self.assertEqual(decode_value(RegType.QWORD, raw), 0x1122334455667788)
        # canonical: <= 2^53 stays int, > 2^53 becomes a string
        small = encode_value(RegType.QWORD, 4294967296)
        self.assertEqual(canonical_data(RegType.QWORD, small), 4294967296)
        big = (1 << 60) + 7
        self.assertEqual(canonical_data(RegType.QWORD, encode_value(RegType.QWORD, big)), str(big))
        # native decode keeps full precision as an int
        self.assertEqual(decode_value(RegType.QWORD, encode_value(RegType.QWORD, big)), big)

    def test_sz_utf16le_round_trip(self):
        raw = encode_value(RegType.SZ, "hi")
        self.assertEqual(raw, "hi\x00".encode("utf-16-le"))
        self.assertEqual(decode_value(RegType.SZ, raw), "hi")
        self.assertEqual(decode_value(RegType.SZ, encode_value(RegType.SZ, "")), "")
        self.assertEqual(canonical_data(RegType.SZ, raw), "hi")

    def test_multi_sz(self):
        raw = encode_value(RegType.MULTI_SZ, ["a", "bb"])
        self.assertEqual(raw, "a\x00bb\x00\x00".encode("utf-16-le"))
        self.assertEqual(decode_value(RegType.MULTI_SZ, raw), ["a", "bb"])
        self.assertEqual(decode_value(RegType.MULTI_SZ, encode_value(RegType.MULTI_SZ, [])), [])
        with self.assertRaises(TypeError):
            encode_value(RegType.MULTI_SZ, "not a list")

    def test_binary_native_vs_canonical(self):
        data = bytes(range(5))
        raw = encode_value(RegType.BINARY, data)
        self.assertEqual(raw, data)
        self.assertEqual(decode_value(RegType.BINARY, raw), data)
        self.assertEqual(canonical_data(RegType.BINARY, raw), base64.b64encode(data).decode())

    def test_none(self):
        self.assertEqual(encode_value(RegType.NONE, None), b"")
        self.assertIsNone(decode_value(RegType.NONE, b""))
        self.assertIsNone(canonical_data(RegType.NONE, b""))

    def test_type_name_unknown_falls_back_to_binary(self):
        self.assertEqual(type_name(RegType.DWORD_BE), "REG_DWORD_BE")
        self.assertEqual(type_name(999), "REG_BINARY")
        # an unknown code is treated as opaque base64 in canonical form
        self.assertEqual(canonical_data(999, b"\x01"), base64.b64encode(b"\x01").decode())

    def test_from_name(self):
        self.assertIs(RegType.from_name("REG_QWORD"), RegType.QWORD)
        self.assertIs(RegType.from_name(4), RegType.DWORD)


if __name__ == "__main__":
    unittest.main()
