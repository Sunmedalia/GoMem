import unittest
from verify_pagecache import page_physical, reconstruct

class PageCacheOracleTests(unittest.TestCase):
    def test_sparse_gaps_and_partial_physical_prefix(self):
        data, gaps = reconstruct([(3, 0x30000), (1, 0x10000)], 3 * 4096 + 5,
            lambda a, n: b'A' * n if a == 0x10000 else b'BC', 'logical', 'physical')
        self.assertEqual(data, bytes(4096) + b'A' * 4096 + bytes(4096) + b'BC' + bytes(3))
        self.assertEqual(gaps, [(0, 4096, 0, 'logical'), (8192, 4096, 8192, 'logical'), (12290, 3, 0x30002, 'physical')])

    def test_empty_uncached_and_invalid_entries(self):
        self.assertEqual(reconstruct([], 0, None, 'logical', 'physical'), (b'', []))
        self.assertEqual(reconstruct([], 5, None, 'logical', 'physical'), (bytes(5), [(0, 5, 0, 'logical')]))
        for pages, size in [([(0, 0), (0, 1)], 4096), ([(1, 0)], 4096), ([(-1, 0)], 4096), ([], 1 << 30)]:
            with self.assertRaises(ValueError):
                reconstruct(pages, size, lambda a, n: bytes(n), 'logical', 'physical')

    def test_pfns_include_zero_and_require_exact_alignment(self):
        base = 0xffffea0000000000
        self.assertEqual(page_physical(base, base, 56, 100), 0)
        self.assertEqual(page_physical(base + 56, base, 56, 100), 4096)
        for address in (base - 1, base + 8, base + 5600):
            with self.assertRaises(ValueError):
                page_physical(address, base, 56, 100)

if __name__ == '__main__':
    unittest.main()
