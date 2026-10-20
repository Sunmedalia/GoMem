#!/usr/bin/env python3
"""Cross-build explicitly labeled development previews with capability metadata."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    version = re.search(r'const Version = "([^"]+)"', (ROOT / "internal/version/version.go").read_text()).group(1)
    matrix = json.loads((ROOT / "docs/capabilities.json").read_text())
    if "-" not in version:
        for entry in matrix["plugins"] + matrix["infrastructure"]:
            if not entry["accepted"] or entry["status"] != "complete" or entry["comparison"] != "passed" or not entry["corpora"]:
                raise ValueError("formal release blocked by incomplete capability acceptance")
    directory = ROOT / "dist" / version
    directory.mkdir(parents=True, exist_ok=True)
    binaries = []
    for target in ("windows/amd64", "windows/arm64", "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"):
        goos, arch = target.split("/")
        name = f"gomem-{version}-{goos}-{arch}" + (".exe" if goos == "windows" else "")
        output = directory / name
        env = dict(os.environ, CGO_ENABLED="0", GOOS=goos, GOARCH=arch)
        subprocess.run(["go", "build", "-trimpath", "-o", str(output), "./cmd/gomem"], cwd=ROOT, env=env, check=True)
        with output.open("rb") as src:
            checksum = hashlib.file_digest(src, "sha256").hexdigest()
        binaries.append({"name": name, "sha256": checksum, "target": target})
        print(name, flush=True)
    (directory / "SHA256SUMS").write_text("".join(f"{b['sha256']}  {b['name']}\n" for b in binaries))
    (directory / "build-manifest.json").write_text(json.dumps({"version": version, "release": "development-preview" if "-" in version else "formal",
        "extensions": {"yara": False, "capstone": False, "leechcore": False}, "binaries": binaries}, indent=2) + "\n")
    for name in ("baseline.lock.json", "README.md", "docs/capabilities.json", "docs/corpus.json"):
        shutil.copyfile(ROOT / name, directory / pathlib.Path(name).name)
    shutil.copytree(ROOT / "docs", directory / "docs", dirs_exist_ok=True, ignore=shutil.ignore_patterns("*.go"))


if __name__ == "__main__":
    main()
