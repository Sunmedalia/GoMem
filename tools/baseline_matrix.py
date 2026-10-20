#!/usr/bin/env python3
"""Development-only AST inventory; never imports or executes upstream plugins.

The locked source tree digest prevents using a different release accidentally.
Requirements preserve literal values and tag expressions for manual semantic review.
"""
import argparse
import ast
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def tree_digest(source):
    digest = hashlib.sha256()
    for path in sorted((source / "volatility3").rglob("*.py")):
        digest.update(path.relative_to(source).as_posix().encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def value(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return {"expression": ast.unparse(node)}


def generate(source):
    lock = json.loads((ROOT / "baseline.lock.json").read_text())
    actual = tree_digest(source)
    if actual != lock["python_tree_sha256"]:
        raise ValueError(f"baseline source digest mismatch: {actual}")
    base = source / "volatility3/framework/plugins"
    classes = {}
    for path in sorted(base.rglob("*.py")):
        module = path.relative_to(base).with_suffix("").as_posix().replace("/", ".")
        if module.endswith(".__init__"):
            module = module[:-9]
        tree = ast.parse(path.read_text())
        imports = {}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imports[alias.asname or alias.name] = node.module + "." + alias.name
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue

            def resolve(expr):
                text = ast.unparse(expr)
                first, dot, rest = text.partition(".")
                text = imports.get(first, module + "." + first if not dot else first)
                if dot:
                    text += "." + rest
                return text.removeprefix("volatility3.plugins.").removeprefix("volatility3.framework.plugins.")

            identifier = module + "." + node.name
            requirements = []
            for method in node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name == "get_requirements":
                    for call in ast.walk(method):
                        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr.endswith("Requirement"):
                            requirements.append({"kind": call.func.attr, **{k.arg: value(k.value) for k in call.keywords if k.arg}})
            alias = next((resolve(k.value) for k in node.keywords if k.arg == "replacement_class"), None)
            classes[identifier] = {"id": identifier, "source": path.relative_to(source).as_posix(), "line": node.lineno,
                                   "bases": [resolve(b) for b in node.bases], "requirements": requirements,
                                   "alias_target": alias}

    def is_plugin(identifier, seen=None):
        seen = set() if seen is None else seen
        if identifier in seen:
            return False
        seen = seen | {identifier}
        c = classes[identifier]
        return any(b.endswith("PluginInterface") or b.endswith("PluginRenameClass") or
                   b in classes and is_plugin(b, seen) for b in c["bases"])

    partial = {"banners.Banners": "banners", "windows.pslist.PsList": "windows.pslist",
               "linux.pslist.PsList": "linux.pslist", "windows.modules.Modules": "windows.modules",
               "linux.lsmod.Lsmod": "linux.lsmod"}

    def requirements(identifier, seen=None):
        seen = set() if seen is None else seen
        if identifier in seen or identifier not in classes:
            return []
        c = classes[identifier]
        if c["requirements"]:
            return c["requirements"]
        targets = [c["alias_target"]] if c["alias_target"] else c["bases"]
        return [r for b in targets for r in requirements(b, seen | {identifier})]

    plugins = []
    validation_path = ROOT / "docs/validation.json"
    validations = json.loads(validation_path.read_text())["results"] if validation_path.exists() else []
    for identifier, c in sorted(classes.items()):
        if not is_plugin(identifier):
            continue
        native = partial.get(identifier)
        plugins.append({"id": identifier, "platform": identifier.split(".")[0] if identifier.split(".")[0] in ("windows", "linux", "mac") else "generic",
                        "source": c["source"], "line": c["line"], "alias_target": c["alias_target"],
                        "requirements": requirements(identifier), "applicability": "All declared module, architecture, version and optional-library requirements must be satisfied; parameter semantics require differential acceptance.",
                        "native": native, "status": "partial" if native else "missing", "accepted": False,
                        "corpora": ["synthetic-linux-x64", "synthetic-windows-x64"] if native else [],
                        "comparison": "not_run", "gaps": ["Official-corpus differential acceptance pending"] if native else ["Native implementation and validation pending"]})
        matching = [v for v in validations if v["id"] == identifier and v["report"]["matched"]]
        if matching:
            plugins[-1]["corpora"] += sorted({v["corpus"] for v in matching})
            plugins[-1]["comparison"] = "selected_fields_match"
            plugins[-1]["validation_record"] = "docs/validation.json"
    infrastructure = []
    for group, directory in [("layers", "volatility3/framework/layers"), ("symbols", "volatility3/framework/symbols"),
                             ("renderers", "volatility3/cli"), ("automagic", "volatility3/framework/automagic")]:
        for path in sorted((source / directory).rglob("*.py")):
            if path.name == "__init__.py":
                continue
            if group == "renderers" and path.name not in ("text_renderer.py", "volshell.py") and "volshell" not in path.parts:
                continue
            module = path.relative_to(source).with_suffix("").as_posix().replace("/", ".")
            infrastructure.append({"id": module, "category": group, "source": path.relative_to(source).as_posix(),
                                   "status": "partial" if path.stem in ("physical", "intel", "lime", "elf", "crash", "intermed", "text_renderer") else "missing",
                                   "accepted": False, "applicability": "See locked source; source-module inventory includes support modules.",
                                   "corpora": [], "comparison": "not_run"})
            if module == "volatility3.framework.automagic.linux":
                infrastructure[-1].update(status="partial", corpora=["synthetic-linux-x64", "official-linux-sample-1"],
                                          comparison="selected_kernel_identity_only", validation_record="docs/linux-discovery.md")
            if module in ("volatility3.framework.automagic.windows", "volatility3.framework.automagic.pdbscan"):
                infrastructure[-1].update(status="partial", corpora=["synthetic-windows-crash-x86-pae-x64", "official-windows-10-19041"],
                                          applicability="Windows complete/bitmap dumps with usable header root/list anchors; KDBG or validated module-list/PE/symbol discovery.",
                                          comparison="selected_kernel_identity_and_entities_only", validation_record="docs/windows-discovery.md")
            if module in ("volatility3.framework.layers.msf", "volatility3.framework.symbols.windows.pdbconv"):
                infrastructure[-1].update(status="partial", corpora=["synthetic-pdb-x86-x64", "official-windows-10-19041"],
                                          comparison="selected_types_and_entities_only", validation_record="docs/pdb-symbols.md")
    for identifier in ("source.file", "source.http", "source.https", "source.ftp", "source.s3", "source.gs", "source.leechcore",
                       "symbols.pdb-msf", "symbols.dwarf", "symbols.local-index", "symbols.pdb-conversion-cache", "symbols.isf.zip", "symbols.isf.gzip", "symbols.isf.xz", "symbols.auto-download",
                       "exploration.address-space", "exploration.types", "exploration.search", "exploration.disassembly", "paging.swap",
                       "export.extracted-files", "extension.yara", "extension.capstone", "renderer.arrow", "renderer.mermaid"):
        infrastructure.append({"id": identifier, "category": "acceptance", "status": "partial" if identifier in ("source.file", "symbols.pdb-msf", "symbols.dwarf", "symbols.local-index", "symbols.pdb-conversion-cache", "symbols.auto-download", "symbols.isf.zip", "symbols.isf.gzip", "symbols.isf.xz", "exploration.types", "exploration.address-space", "exploration.search") else "missing",
                               "accepted": False, "applicability": "Baseline prerequisites and exact semantics must be verified on official or reproducible VM corpus.", "corpora": [], "comparison": "not_run"})
        if identifier == "symbols.dwarf":
            infrastructure[-1].update(corpora=["synthetic-dwarf-c-elf-macho"], comparison="selected_layouts_only",
                                      validation_record="docs/native-symbols.md")
        if identifier == "symbols.local-index":
            infrastructure[-1].update(corpora=["synthetic-linux-x64", "synthetic-windows-x64"], comparison="kernel_identity_tests_only",
                                      validation_record="docs/native-symbols.md")
        if identifier == "symbols.pdb-msf":
            infrastructure[-1].update(corpora=["synthetic-pdb-x86-x64", "official-windows-10-19041"], comparison="selected_types_and_entities_only",
                                      validation_record="docs/pdb-symbols.md")
        if identifier in ("symbols.auto-download", "symbols.pdb-conversion-cache"):
            infrastructure[-1].update(corpora=["synthetic-pdb-x86-x64", "official-windows-10-19041"],
                                      applicability="Windows only; explicit or verified crash-discovered DTB/kernel base and resident exact PE CodeView identity; HTTPS uncompressed PDB transport.",
                                      comparison="selected_entities_and_cache_failures_only", validation_record="docs/pdb-symbols.md")
    return {"schema": "gomem.capabilities/v1", "baseline": lock, "release": "development-preview", "plugin_count": len(plugins),
            "accepted_plugins": 0, "plugins": plugins, "infrastructure": infrastructure}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = json.dumps(generate(args.source), ensure_ascii=False, indent=2) + "\n"
    target = ROOT / "docs/capabilities.json"
    if args.check:
        if target.read_text() != data:
            sys.exit("capability inventory differs; regenerate it")
    else:
        target.parent.mkdir(exist_ok=True)
        target.write_text(data)
    print(f"{json.loads(data)['plugin_count']} upstream plugin classes inventoried; none certified complete")


if __name__ == "__main__":
    main()
