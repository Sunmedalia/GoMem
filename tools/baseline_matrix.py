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
               "linux.lsmod.Lsmod": "linux.lsmod", "windows.threads.Threads": "windows.threads",
               "windows.vadinfo.VadInfo": "windows.vadinfo", "linux.proc.Maps": "linux.maps",
               "windows.dlllist.DllList": "windows.dlllist", "windows.pedump.PEDump": "windows.pedump"}

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
                        "corpora": ([f"synthetic-{identifier.split('.')[0]}-x64"] if identifier.startswith(("linux.", "windows.")) else ["synthetic-linux-x64", "synthetic-windows-x64"]) if native else [],
                        "comparison": "not_run", "gaps": ["Official-corpus differential acceptance pending"] if native else ["Native implementation and validation pending"]})
        matching = [v for v in validations if v["id"] == identifier and v["report"]["matched"]]
        if matching:
            plugins[-1]["corpora"] += sorted({v["corpus"] for v in matching})
            plugins[-1]["comparison"] = "selected_fields_match"
            plugins[-1]["validation_record"] = "docs/validation.json"
        if identifier == "windows.pslist.PsList":
            plugins[-1].update(applicability="Active process list with exact EPROCESS, handle/session types and independent PEB address spaces; virtual or physical offset display, PID sets and main PE extraction.",
                              comparison="selected_extended_fields_and_physical_offsets_match_main_PE_bytes_match", validation_record="docs/windows-process-modules.md",
                              gaps=["Full version/architecture and parameter/failure coverage pending", "Opaque session layouts are not guessed; handle count requires a declared HandleCount field", "Bidirectional damaged-list recovery, timeline and full PE extraction acceptance pending"])
        if identifier == "windows.modules.Modules":
            plugins[-1].update(applicability="Loaded kernel list, exact base and case-sensitive base-name substring filters. PE extraction tries kernel then typed per-session process roots, with bounded attempts recorded.",
                              comparison="selected_core_fields_and_157_paths_match_19_read_errors_preserved_PE_ImageBase_difference_explained", validation_record="docs/windows-process-modules.md",
                              gaps=["Full version/architecture, session mapping and failure/parameter acceptance pending", "19 path errors remain distinct from reference nulls in the selected image", "PE files retain canonical ImageBase high bits; explicit byte differences and filename mapping remain recorded"])
        if identifier == "windows.threads.Threads":
            plugins[-1].update(applicability="Active process thread lists; exact ETHREAD/EPROCESS types. Start paths currently require modern RTL_AVL_TREE VAD layout. External swap/prototype pages are unresolved.",
                              gaps=["Full version/architecture and parameter coverage pending", "ExitTime signed union differences explicitly preserved; see docs/windows-threads.md", "No thread pool scan or extracted artifacts"])
        if identifier == "windows.vadinfo.VadInfo":
            plugins[-1].update(applicability="Modern RTL_AVL_TREE VADs with exact MMVAD_SHORT types and native MmProtectToValue table; PID sets and inclusive address filtering.",
                              gaps=["Old VAD layouts and complete version/architecture coverage pending", "Extraction has selected x64 region byte comparisons only; full failure/version/parameter acceptance pending", "Path read errors remain distinct from baseline nulls; see docs/windows-vad.md"])
        if identifier == "linux.proc.Maps":
            plugins[-1].update(applicability="mmap lists or typed Maple Tree nodes; exact VMA/filesystem symbols. Full view retains page offsets beyond positive inode size; include-past-eof=false selects the baseline heuristic view.",
                              gaps=["Maple Tree has synthetic ABI tests only; real modern kernels, pivot/meta validation and complete versions pending", "Extraction has selected legacy x64 region byte comparisons only; full parameter/version acceptance pending", "Full parameter combinations and scoped/raw path semantics need complete acceptance; see docs/linux-maps.md"])
        if identifier == "windows.dlllist.DllList":
            plugins[-1].update(applicability="Active process PEB load-order lists in independent process spaces; native symbol layouts and minimal declared WoW64 loader fields. Read failures remain diagnostics.",
                              gaps=["Full Windows version/architecture and Python regex semantics pending", "WoW64 LoadTime/LoadCount deliberately unavailable until verified 32-bit layouts exist", "Physical offset process scanning, full PE dump acceptance and timeline export pending"])
        if identifier == "windows.pedump.PEDump":
            plugins[-1].update(applicability="Mapped Intel PE32/PE32+ images with resident, bounded headers. Explicit process roots or kernel/typed session roots; 256MiB image limit. Independent PID extraction failures retain rows and allow remaining selected processes.",
                              corpora=["synthetic-windows-x64","synthetic-pe32-pe32plus","official-windows-10-19041"],
                              comparison="selected_process_PE_bytes_match_kernel_ImageBase_difference_explained",validation_record="docs/pe-reconstruction.md",
                              gaps=["Kernel/session ImageBase retains canonical high bits; differs explicitly from pinned baseline", "Full architecture/version/session mapping and failure/parameter coverage pending", "Uncaptured or invalid headers fail rather than producing empty PE files; see docs/pe-session-validation.json"])
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
        if identifier == "export.extracted-files":
            infrastructure[-1].update(status="partial",corpora=["synthetic-artifact-lifecycle","official-linux-sample-1","official-windows-10-19041"],
                                      applicability="Task-bound extraction sink, case schema v2, padding logs, bundle v2 and Windows modern VAD/Linux VMA dumps; selected x64 regions only.",
                                      comparison="selected_region_bytes_and_storage_tests_only",validation_record="docs/artifacts.md")
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
