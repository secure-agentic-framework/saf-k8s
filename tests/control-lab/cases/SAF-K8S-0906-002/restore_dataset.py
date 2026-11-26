"""Copy only case-owned synthetic partitions and verify the approved commitment."""
import json
from pathlib import Path
import shutil
import sys

from dataset_fixture import verify
from manifest_auth import read_verified_manifest

MANIFEST = read_verified_manifest(Path("/manifest/manifest.json"))
if MANIFEST is None:
    raise SystemExit("Dataset recovery requires a trusted manifest signature")
DATASET = Path("/data/recovered")
BACKUP = Path("/backup/approved")


def copy_partitions(source, target):
    target.mkdir(exist_ok=True)
    for part in sorted(MANIFEST["partitions"]):
        shutil.copyfile(source / part, target / part)


def checked_copy(source, target):
    before = verify(source, MANIFEST)
    if not before["accepted"]:
        return {"source": before, "target": None}
    copy_partitions(source, target)
    return {"source": before, "target": verify(target, MANIFEST)}


if sys.argv[1:] == ["snapshot"]:
    report = checked_copy(Path("/original/consumer-approved"), BACKUP)
    if report["target"] and report["target"]["accepted"]:
        copy_partitions(Path("/original/consumer-altered"), DATASET)
elif sys.argv[1:] == ["restore"]:
    report = checked_copy(BACKUP, DATASET)
else:
    raise SystemExit("Expected snapshot or restore")

print(json.dumps(report, sort_keys=True))
