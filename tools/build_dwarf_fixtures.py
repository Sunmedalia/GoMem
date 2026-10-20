#!/usr/bin/env python3
"""Development-only clang/LLD corpus builder. Tests use the resulting fixtures.

The runtime converter never executes these tools. Separate DWARF versions cover
legacy and data-bit offsets; the Mach-O object covers native symbol naming.
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
directory = ROOT / "pkg/symbols/testdata"
source = directory / "kernel.c"
clang = os.environ.get("CLANG") or shutil.which("clang")
linker = shutil.which("ld.lld")
if not clang or not linker:
    raise SystemExit("fixture regeneration requires clang and ld.lld")
outputs = []
with tempfile.TemporaryDirectory() as temporary:
    for arch, dwarf_version in (("x86_64", 2), ("x86_64", 4), ("x86_64", 5), ("i386", 4), ("powerpc64", 4)):
        obj = pathlib.Path(temporary) / "kernel.o"
        subprocess.run([clang, f"--target={arch}-linux-gnu", f"-gdwarf-{dwarf_version}", "-O0", "-ffreestanding", "-fno-pie", f"-ffile-prefix-map={ROOT}=/gomem",
                        "-fno-eliminate-unused-debug-types", "-c", str(source), "-o", str(obj)], check=True)
        target = directory / f"dwarf-{arch}-v{dwarf_version}.elf"
        subprocess.run([linker, "--build-id=sha1", "--image-base=0x100000", "-e", "_start", str(obj), "-o", str(target)], check=True)
        outputs.append(target)
    for arch, platform in (("x86_64", "x86_64-apple-macos10.13"), ("arm64", "arm64-apple-macos11")):
        target = directory / f"dwarf-{arch}.macho"
        subprocess.run([clang, f"--target={platform}", "-gdwarf-4", "-O0", "-ffreestanding", f"-ffile-prefix-map={ROOT}=/gomem",
                        "-fno-eliminate-unused-debug-types", "-c", str(source), "-o", str(target)], check=True)
        outputs.append(target)
manifest = {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "clang": subprocess.check_output([clang, "--version"], text=True).splitlines()[0],
            "files": [{"name": output.name, "sha256": hashlib.sha256(output.read_bytes()).hexdigest()} for output in outputs]}
(directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
