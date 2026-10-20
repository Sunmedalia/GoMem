import unittest
from verify_sockstat import abstract_display


class UnixNameIndependentOracle(unittest.TestCase):
    def test_abstract_and_pathname(self):
        self.assertEqual(abstract_display(b'\0a\0b\0\xff'), r'@a\x00b\x00\xff')
        self.assertEqual(abstract_display(b'/tmp/a\0tail'), '/tmp/a')
        self.assertEqual(abstract_display(b'\0'), '@')
        self.assertEqual(abstract_display(bytes([0, 92, 32, 127])), r'@\x5c\x20\x7f')


if __name__ == '__main__':
    unittest.main()
