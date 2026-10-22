"""Prove sharding preserves the entire Go test inventory."""
import unittest
from unittest.mock import patch

from test_engine_shard import ENGINE, main, partitions, test_names


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

    def test_go_override_applies_to_discovery_and_execution(self):
        executable = '/tmp/Go tool with spaces'
        with patch('sys.argv', ['test_engine_shard.py', '--go', executable, '--other-packages']), \
                patch('test_engine_shard.subprocess.check_output', return_value=ENGINE + '\nexample/other\n') as discover, \
                patch('test_engine_shard.subprocess.run') as run:
            main()
            discover.assert_called_once_with([executable, 'list', './...'], text=True)
            self.assertEqual(run.call_args.args[0], [executable, 'test', '-race', '-timeout', '30m', 'example/other'])
            self.assertTrue(run.call_args.kwargs['check'])
        names = ['TestA', 'TestB', 'FuzzParser']
        index = next(i for i, group in enumerate(partitions(names, 4)) if group)
        with patch('sys.argv', ['test_engine_shard.py', '--go', executable, '--shard', str(index)]), \
                patch('test_engine_shard.subprocess.check_output', return_value='\n'.join(names)) as discover, \
                patch('test_engine_shard.subprocess.run') as run:
            main()
            discover.assert_called_once_with([executable, 'test', '-list', '.', ENGINE], text=True)
            command = run.call_args.args[0]
            self.assertEqual(command[0], executable)
            self.assertEqual(command[-1], ENGINE)
            self.assertIn('-race', command)
            self.assertTrue(run.call_args.kwargs['check'])


if __name__ == '__main__':
    unittest.main()
