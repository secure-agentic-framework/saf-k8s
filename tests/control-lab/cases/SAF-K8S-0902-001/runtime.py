import hashlib
import json
import os
from pathlib import Path


def write_probe(path, marker):
    path = Path(path)
    try:
        path.write_text(marker)
    except OSError as error:
        return error.errno, None
    return None, path.read_text()


mounts = {fields[4]: fields[5] for line in Path("/proc/self/mountinfo").read_text().splitlines()
          if len(fields := line.split()) > 5}
model = Path("/opt/model/model.json").read_bytes()
model_error, _ = write_probe("/opt/model/case-owned-write-probe", "synthetic")
root_error, root_readback = write_probe("/tmp/case-owned-rootfs-write-probe", "synthetic")
scratch_error, scratch_readback = write_probe("/case-work/case-owned-write-probe", "synthetic-write-ok")
if scratch_error is not None:
    raise OSError(scratch_error, "the owned scratch volume must permit writes")
print(json.dumps({"uid": os.getuid(), "model_sha256": hashlib.sha256(model).hexdigest(),
                  "model_mountpoint": "/opt/model", "model_mount_options": mounts["/opt/model"],
                  "model_write_errno": model_error, "rootfs_readonly": "ro" in mounts["/"].split(","),
                  "rootfs_write_errno": root_error, "rootfs_write_readback": root_readback,
                  "scratch_readback": scratch_readback}, sort_keys=True))
