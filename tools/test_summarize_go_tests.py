import json
import unittest

from summarize_go_tests import summarize


def events(*items):
    return [json.dumps(dict(Package='p', **item)) for item in items]


class ExecutionTests(unittest.TestCase):
    def test_skip_and_failure_are_not_passes(self):
        for action, want in [('pass', 'passed'), ('skip', 'completed_with_skips'), ('fail', 'failed')]:
            result = summarize(events(dict(Action='start'), dict(Action='run', Test='TestExample'),
                                      dict(Action=action, Test='TestExample'), dict(Action='pass')))
            self.assertEqual(result['state'], want)
            self.assertEqual(result['top_level'][action], 1)

    def test_empty_or_truncated_execution_rejected(self):
        for log in ([], events(dict(Action='start')),
                    events(dict(Action='start'), dict(Action='run', Test='TestExample'), dict(Action='pass'))):
            with self.assertRaises(ValueError):
                summarize(log)

    def test_subtest_skip_remains_visible(self):
        result = summarize(events(dict(Action='start'), dict(Action='run', Test='TestExample'),
                                  dict(Action='run', Test='TestExample/optional'),
                                  dict(Action='skip', Test='TestExample/optional'),
                                  dict(Action='pass', Test='TestExample'), dict(Action='pass')))
        self.assertEqual(result['state'], 'completed_with_skips')
        self.assertEqual(len(result['skipped_subtests']), 1)


if __name__ == '__main__':
    unittest.main()
