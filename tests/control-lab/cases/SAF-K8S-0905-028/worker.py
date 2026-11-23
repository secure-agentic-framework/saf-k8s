"""Create and inspect harmless local metadata-only wheels; no package code is present."""
import base64
import csv
import hashlib
import importlib.metadata as metadata
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

DIRECT = "saf-ml-fixture"
TRANSITIVE = "saf-fixture-core"
ADVISORY = {"id": "SAF-FAB-2026-0905-028-001", "package": TRANSITIVE, "version": "0.4.0"}


def wheel(directory, name, version, requires=()):
    normalized = name.replace("-", "_")
    dist_info = f"{normalized}-{version}.dist-info"
    files = {
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {name}\nVersion: {version}\n"
            + "".join(f"Requires-Dist: {req}\n" for req in requires)
            + "\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: saf-k8s-fixture\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n"
        ).encode(),
    }
    record = []
    for path, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        record.append((path, "sha256=" + digest, str(len(content))))
    record.append((f"{dist_info}/RECORD", "", ""))
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(record)
    files[f"{dist_info}/RECORD"] = output.getvalue().encode()
    path = directory / f"{normalized}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for file_name, content in sorted(files.items()):
            archive.writestr(file_name, content)
    return path


def install(wheelhouse, target):
    target.mkdir(parents=True)
    env = dict(os.environ, PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1",
               PIP_NO_CACHE_DIR="1", PIP_CONFIG_FILE=os.devnull)
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-index",
                    "--find-links", str(wheelhouse), "--only-binary=:all:", "--no-cache-dir", "--disable-pip-version-check",
                    "--target", str(target), DIRECT + "==1.0.0"],
                   check=True, env=env, stdout=subprocess.DEVNULL)


def installed(target):
    found = {}
    for dist in metadata.distributions(path=[str(target)]):
        name = dist.metadata["Name"].lower().replace("_", "-")
        found[name] = {"version": dist.version, "requires": dist.requires or []}
    return found


def make_house(name, core_version, root):
    house = root / name
    house.mkdir(parents=True)
    wheel(house, DIRECT, "1.0.0", ("saf-fixture-core>=0.4,<1",))
    wheel(house, TRANSITIVE, core_version)
    return house


def release(inventory, enforcement, destination):
    matches = []
    component = inventory.get(ADVISORY["package"], {})
    if component.get("version") == ADVISORY["version"]:
        matches.append(ADVISORY)
    allowed = not enforcement or not matches
    if allowed:
        destination.write_text(json.dumps({"installed": inventory}, sort_keys=True) + "\n")
    record = json.loads(destination.read_text()) if destination.is_file() else None
    return {"installed": inventory, "matches": matches, "enforced": enforcement,
            "decision": "accepted" if allowed else "blocked", "promoted_record": record}


def main():
    with tempfile.TemporaryDirectory(prefix="saf-dependency-") as scratch:
        root = Path(scratch)
        old_house = make_house("original-wheelhouse", "0.4.0", root)
        new_house = make_house("patched-wheelhouse", "0.4.1", root)
        old_target = root / "original-install"
        new_target = root / "patched-install"
        install(old_house, old_target)
        original = installed(old_target)
        install(new_house, new_target)
        patched = installed(new_target)

        observations = {
            "disabled": release(original, False, root / "disabled-promotion.json"),
            "blocked": release(original, True, root / "blocked-promotion.json"),
            "patched": release(patched, True, root / "patched-promotion.json"),
        }
        print(json.dumps(observations, sort_keys=True))


if __name__ == "__main__":
    main()
