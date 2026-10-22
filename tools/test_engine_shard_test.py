"""Prove sharding preserves the entire Go test inventory."""
import unittest

from test_engine_shard import partitions, test_names


class EngineShardTests(unittest.TestCase):
    def test_all_tests_fuzz_seeds_and_examples_once(self):
        names = test_names('TestB\nTestA\nFuzzParser\nExample_reader\nExample\nBenchmarkA\nok package 0.1s\n')
        groups = partitions(names, 4)
        self.assertCountEqual([name for group in groups for name in group], names)
        for name in names:
            self.assertEqual(sum(name in group for group in groups), 1)
        self.assertEqual(groups, partitions(names, 4))
        extended = partitions(sorted(names + ['TestAdded']), 4)
        for index, group in enumerate(groups):
            self.assertTrue(set(group) <= set(extended[index]))

    def test_invalid_or_duplicate_inventory_fails(self):
        for output in ('ok package\n', 'TestA\nTestA\n', 'TestA/subtest\n'):
            with self.assertRaises(ValueError):
                test_names(output)
        for count in (0, -1, 4097):
            with self.assertRaises(ValueError):
                partitions(['TestA'], count)


if __name__ == '__main__':
    unittest.main()
