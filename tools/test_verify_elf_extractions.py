import pathlib
import struct
import tempfile
import unittest

from verify_elf_extractions import RawX64, expected_plan


class ELFOracleTests(unittest.TestCase):
    def test_raw_page_walk_partial_capture_and_noncanonical_address(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'memory.raw'
            raw = bytearray(0x6007)
            for at, value in ((0x1000, 0x2003), (0x2000, 0x3003), (0x3000, 0x4003), (0x4000, 0x5003), (0x4008, 0x6003)):
                struct.pack_into('<Q', raw, at, value)
            raw[0x5000:0x6000] = b'A' * 4096
            raw[0x6000:] = b'prefix!'
            path.write_bytes(raw)
            space = RawX64(path, 0x1000)
            try:
                data, gaps = space.read(0xffe, 16, pad=True)
                self.assertEqual(data, b'AAprefix!' + bytes(7))
                self.assertEqual(gaps, [(9, 0x1007, 7)])
                with self.assertRaises(ValueError):
                    space.read(0x1000, 8)
                with self.assertRaises(ValueError):
                    space.translate(1 << 48)
                with self.assertRaises(ValueError):
                    space.read(1 << 64, 1, pad=True)
            finally:
                space.close()

    def test_huge_pages_and_missing_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'huge.raw'
            raw = bytearray(0x4000)
            struct.pack_into('<Q', raw, 0x1000, 0x2003)
            struct.pack_into('<Q', raw, 0x2000, 0x40000083)
            path.write_bytes(raw)
            space = RawX64(path, 0x1000)
            try:
                self.assertEqual(space.translate(0x12345), 0x40012345)
                self.assertEqual(space.read(1 << 39, 4, pad=True), (bytes(4), [(0, 1 << 39, 4)]))
            finally:
                space.close()

    def test_high_vdso_anchor_and_reference_overflow(self):
        raw = bytearray(120)
        raw[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQ', raw, 16, 3, 62, 1, 0xffffffffff700700, 64)
        struct.pack_into('<HHH', raw, 52, 64, 56, 1)
        struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0xffffffffff700000, 0, 120, 120, 4096)

        class CapturedHeader:
            def read(self, address, length):
                return bytes(raw[address - 0x7fff00000000:address - 0x7fff00000000 + length]), []

        plan = expected_plan(CapturedHeader(), 0x7fff00000000, 'mapped')
        self.assertEqual(plan['segments'][0]['source'], '0x7fff00000000')
        with self.assertRaisesRegex(ValueError, 'cannot be represented'):
            expected_plan(CapturedHeader(), 0x7fff00000000, 'reference')


if __name__ == '__main__':
    unittest.main()
