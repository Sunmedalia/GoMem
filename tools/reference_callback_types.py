#!/usr/bin/env python3
"""Run the pinned reference CLI with an output-only callback absent-type renderer.

After `make baseline`, use the normal Volatility CLI arguments, including
-r typedcallbackjson windows.callbacks.Callbacks. Analysis methods are unchanged.
This development helper does not certify complete acquisition or native errors.
"""
import json
import sys

from baseline_matrix import ROOT, tree_digest

source = ROOT / '.cache/volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75'
lock = json.loads((ROOT / 'baseline.lock.json').read_text())
if tree_digest(source) != lock['python_tree_sha256']:
    raise ValueError('typed callback reference requires the locked unmodified source')
sys.path.insert(0, str(source))
from volatility3.cli import text_renderer
from volatility3.framework import interfaces
import volatility3.cli


class TypedCallbackJSON(text_renderer.JsonRenderer):
    """Preserve actual missing classes in the five callback columns."""
    name = 'TypedCallbackJSON'
    _type_renderers = {
        **text_renderer.JsonRenderer._type_renderers,
        'default': lambda value: {'__absent': type(value).__name__}
        if isinstance(value, interfaces.renderers.BaseAbsentValue) else value,
    }


if __name__ == '__main__':
    volatility3.cli.main()
