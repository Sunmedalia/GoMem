#!/usr/bin/env python3
"""Development-only CodeView fixture builder; GoMem never executes LLVM."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
directory = ROOT / "pkg/symbols/testdata"
source = directory / "pdb_kernel.c"
clang = os.environ.get("CLANG") or shutil.which("clang")
linker = shutil.which("lld-link")
if not clang or not linker:
    raise SystemExit("fixture regeneration requires clang and lld-link")
outputs = []
work = pathlib.Path("/tmp" if os.name == "posix" else tempfile.gettempdir()) / "gomem-pdb-fixture-build"
work.mkdir(mode=0o700)  # exclusive, so concurrent builders cannot share object files
temp = str(work)
try:
    shutil.copyfile(source, pathlib.Path(temp) / source.name)
    for arch, target, machine in (("x64", "x86_64-pc-windows-msvc", "x64"), ("x86", "i686-pc-windows-msvc", "x86")):
        subprocess.run([clang, f"--target={target}", "-g", "-gcodeview", "-O0", "-ffreestanding", "-fno-stack-protector",
                        "-gno-codeview-command-line", "-fdebug-compilation-dir=/gomem", "-fcoverage-compilation-dir=/gomem",
                        "-c", source.name, "-o", "kernel.obj"], cwd=temp, check=True)
        pdb, exe = [directory / f"native-{arch}.{suffix}" for suffix in ("pdb", "exe")]
        subprocess.run([linker, "/debug:full", "/brepro", "/nodefaultlib", "/entry:entry", "/subsystem:native", "/fixed",
                        "/machine:"+machine, "/pdb:"+pdb.name, "/pdbaltpath:"+pdb.name, "/out:"+exe.name,
                        "/pdbsourcepath:/gomem", "kernel.obj"], cwd=temp, check=True)
        for p in (pdb,exe): shutil.copyfile(pathlib.Path(temp)/p.name,p)
        outputs.extend((pdb, exe))
finally:
    shutil.rmtree(work)
manifest = {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "clang": subprocess.check_output([clang, "--version"], text=True).splitlines()[0],
            "linker": subprocess.check_output([linker, "--version"], text=True).strip(),
            "files": [{"name": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in outputs]}
(directory / "pdb-manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
