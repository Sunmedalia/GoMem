from pathlib import Path
import tempfile
import unittest

from run_v01_corpus import DIRECTORIES, FILES, PREFIXES, inputs


class CorpusInputTests(unittest.TestCase):
    def test_missing_or_unknown_keys_cannot_silently_skip(self):
        with self.assertRaises(ValueError):
            inputs({}, Path('.'))
        with self.assertRaises(ValueError):
            inputs({'PATH': '/tmp'}, Path('.'))

    def test_all_local_inputs_required_before_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'dir').mkdir()
            (root / 'file').write_text('data')
            (root / 'prefix.manifest.json').write_text('{}')
            profile = {key: 'dir' for key in DIRECTORIES}
            profile.update({key: 'file' for key in FILES})
            profile.update({key: 'prefix' for key in PREFIXES})
            result = inputs(profile, root)
            self.assertEqual(set(profile), set(result))
            self.assertTrue(all(Path(path).is_absolute() for path in result.values()))
            (root / 'prefix.manifest.json').unlink()
            with self.assertRaises(ValueError):
                inputs(profile, root)


if __name__ == '__main__':
    unittest.main()
