"""Create, verify, corrupt, omit, and restore only the inert fixture marker."""
import base64
import hashlib
import json
import os
from pathlib import Path
import tarfile

root = Path("/data")
source = root / "source" / os.environ["MARKER_NAME"]
backup = root / "backup" / "workload.tar"
expected = base64.b64decode(os.environ["MARKER_B64"], validate=True)
source.parent.mkdir(parents=True, exist_ok=True)
(root / "backup").mkdir(parents=True, exist_ok=True)
source.write_bytes(expected)
with tarfile.open(backup, "w") as archive:
    archive.add(source, arcname=os.environ["MARKER_NAME"])

def verify(path):
    try:
        with tarfile.open(path, "r") as archive:
            members = archive.getmembers()
            names = [item.name for item in members if item.isfile()]
            if names != [os.environ["MARKER_NAME"]]:
                return {"valid": False, "reason": "incomplete-or-unexpected-members", "members": names}
            fileobj = archive.extractfile(members[0])
            data = fileobj.read() if fileobj else b""
            return {"valid": data == expected,
                    "reason": "ok" if data == expected else "marker-mismatch",
                    "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    except (OSError, tarfile.TarError) as error:
        return {"valid": False, "reason": type(error).__name__}

good = verify(backup)
(root / "restore").mkdir(parents=True, exist_ok=True)
with tarfile.open(backup, "r") as archive:
    extracted = archive.extractfile(os.environ["MARKER_NAME"])
    restored = extracted.read() if extracted else b""
(root / "restore" / os.environ["MARKER_NAME"]).write_bytes(restored)

bad_bytes = bytearray(backup.read_bytes())
with tarfile.open(backup, "r") as archive:
    marker_member = archive.getmember(os.environ["MARKER_NAME"])
    bad_bytes[marker_member.offset_data] ^= 1
(root / "backup" / "corrupt.tar").write_bytes(bad_bytes)
with tarfile.open(root / "backup" / "incomplete.tar", "w"):
    pass
result = {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
          "expected_sha256": hashlib.sha256(expected).hexdigest(),
          "valid_backup": good,
          "corrupt_backup": verify(root / "backup" / "corrupt.tar"),
          "incomplete_backup": verify(root / "backup" / "incomplete.tar"),
          "restored_sha256": hashlib.sha256(restored).hexdigest(),
          "restored_exact": restored == expected}
print(json.dumps(result, sort_keys=True))
