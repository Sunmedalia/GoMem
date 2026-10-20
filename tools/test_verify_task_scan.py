import pathlib
import tempfile
import unittest

from verify_task_scan import scan_offsets


class IndependentPointerSearchTests(unittest.TestCase):
    def test_carry_multiple_patterns_and_unaligned_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'bytes.raw'
            path.write_bytes(b'xyzabcdefghZZ12345678abcdefgh')
            self.assertEqual(list(scan_offsets(path, [b'abcdefgh', b'12345678'], 9)), [(3, b'abcdefgh'), (13, b'12345678'), (21, b'abcdefgh')])

    def test_overlap_is_emitted_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'zeros.raw'
            path.write_bytes(bytes(20))
            self.assertEqual(list(scan_offsets(path, [bytes(8)], 3)), [(i, bytes(8)) for i in range(13)])


if __name__ == '__main__':
    unittest.main()
