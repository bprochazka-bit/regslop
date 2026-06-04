"""Tests for the SDDL <-> binary security descriptor codec (no library needed)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from libreg import sddl  # noqa: E402
from libreg.errors import SddlError  # noqa: E402

# The ratified default key descriptor (CONTRACTS Security section, issue #11).
DEFAULT_SDDL = "O:BAG:BAD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)"

# The exact on-disk bytes libreg's default_key_security_descriptor() produces,
# captured from the Rust security_descriptor.rs layout (header SACL/DACL/owner/
# group order). This pins byte parity, not just SDDL parity.
DEFAULT_BYTES = bytes(
    [0x01, 0x00, 0x04, 0x80,            # rev, sbz, control = SELF_RELATIVE|DACL_PRESENT
     0x70, 0x00, 0x00, 0x00,            # owner offset = 0x70 (after the 0x5C DACL)
     0x80, 0x00, 0x00, 0x00,            # group offset = 0x80
     0x00, 0x00, 0x00, 0x00,            # sacl offset = 0
     0x14, 0x00, 0x00, 0x00]            # dacl offset = 0x14
    # DACL: rev 2, sbz, size = 0x5C (8 + 20+24+20+20), count 4, sbz
    + [0x02, 0x00, 0x5C, 0x00, 0x04, 0x00, 0x00, 0x00]
    # ACE 0: allow CI KA SY (S-1-5-18)
    + [0x00, 0x02, 0x14, 0x00, 0x3F, 0x00, 0x0F, 0x00,
       0x01, 0x01, 0, 0, 0, 0, 0, 0x05, 0x12, 0, 0, 0]
    # ACE 1: allow CI KA BA (S-1-5-32-544)
    + [0x00, 0x02, 0x18, 0x00, 0x3F, 0x00, 0x0F, 0x00,
       0x01, 0x02, 0, 0, 0, 0, 0, 0x05, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0]
    # ACE 2: allow CI KR WD (S-1-1-0)
    + [0x00, 0x02, 0x14, 0x00, 0x19, 0x00, 0x02, 0x00,
       0x01, 0x01, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0]
    # ACE 3: allow CI KR RC (S-1-5-12)
    + [0x00, 0x02, 0x14, 0x00, 0x19, 0x00, 0x02, 0x00,
       0x01, 0x01, 0, 0, 0, 0, 0, 0x05, 0x0C, 0, 0, 0]
    # owner BA, group BA
    + [0x01, 0x02, 0, 0, 0, 0, 0, 0x05, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0]
    + [0x01, 0x02, 0, 0, 0, 0, 0, 0x05, 0x20, 0, 0, 0, 0x20, 0x02, 0, 0]
)


class SddlTest(unittest.TestCase):
    def test_default_descriptor_bytes_to_sddl(self):
        self.assertEqual(sddl.to_sddl(DEFAULT_BYTES), DEFAULT_SDDL)

    def test_default_sddl_to_bytes_matches_libreg(self):
        # SDDL -> binary must reproduce libreg's exact on-disk default bytes.
        self.assertEqual(sddl.from_sddl(DEFAULT_SDDL), DEFAULT_BYTES)

    def test_round_trip_stable(self):
        self.assertEqual(sddl.to_sddl(sddl.from_sddl(DEFAULT_SDDL)), DEFAULT_SDDL)

    def test_custom_descriptor(self):
        s = "O:BAG:BAD:(A;;KA;;;SY)(A;;KR;;;BU)"
        self.assertEqual(sddl.to_sddl(sddl.from_sddl(s)), s)

    def test_generic_sid_and_hex_mask(self):
        s = "O:BAG:BAD:(A;;0x1;;;S-1-5-21-7-8-9)"
        out = sddl.to_sddl(sddl.from_sddl(s))
        self.assertIn("S-1-5-21-7-8-9", out)
        self.assertIn("0x1", out)

    def test_deny_ace_and_inherit_flags(self):
        s = "O:SYG:SYD:(D;OICI;KA;;;WD)"
        self.assertEqual(sddl.to_sddl(sddl.from_sddl(s)), s)

    def test_unknown_alias_raises(self):
        with self.assertRaises(SddlError):
            sddl.from_sddl("O:ZZG:BAD:")

    def test_truncated_descriptor_raises(self):
        with self.assertRaises(SddlError):
            sddl.to_sddl(b"\x01\x00\x04")


if __name__ == "__main__":
    unittest.main()
