import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import reference


class ReferenceLayerSelectionTests(unittest.TestCase):
    def test_explicit_stackers_are_bounded_and_recorded(self):
        for stackers in [[], ['LimeStacker'], ['LimeStacker', 'AVMLStacker']]:
            with self.subTest(stackers=stackers), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root/'baseline.lock.json').write_text(json.dumps({'python_tree_sha256':'locked'}))
                image=root/'memory.raw'
                image.write_bytes(b'test image')
                output=root/'reference.json'
                argv=['reference.py','--source',str(root),'--image',str(image),'--symbols',str(root),'--plugin','linux.vmcoreinfo.VMCoreInfo','--output',str(output)]
                for stacker in stackers:
                    argv += ['--stacker',stacker]
                def run(command,stdout,check):
                    self.assertTrue(check)
                    if stackers:
                        start=command.index('--stackers')
                        self.assertEqual(command[start+1:],stackers+['--','linux.vmcoreinfo.VMCoreInfo'])
                    else:
                        self.assertNotIn('--stackers',command)
                    Path(command[command.index('--save-config')+1]).write_text('{}')
                    stdout.write('[]\n')
                with patch.object(reference,'ROOT',root), patch.object(reference,'tree_digest',return_value='locked'), patch.object(reference.subprocess,'run',side_effect=run), patch.object(sys,'argv',argv), contextlib.redirect_stdout(io.StringIO()):
                    reference.main()
                meta=json.loads(output.with_suffix('.manifest.json').read_text())
                self.assertEqual(meta.get('stackers',[]),stackers)
                self.assertEqual(meta['image_sha256'],reference.digest(image))
                self.assertEqual(meta['output_sha256'],reference.digest(output))


if __name__=='__main__':
    unittest.main()
