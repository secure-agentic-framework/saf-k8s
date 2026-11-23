"""Read and compare harmless files on the image root and an approved volume."""

import errno
import hashlib
import json
from pathlib import Path


image_file = Path("/baseline/drift-marker.txt")
state_file = Path("/state/approved-marker.txt")
before = hashlib.sha256(image_file.read_bytes()).hexdigest()
write_result = "ok"
try:
    with image_file.open("ab") as stream:
        stream.write(b"Observed fixture change\n")
except OSError as error:
    if error.errno != errno.EROFS:
        raise
    write_result = "readonly"
after = hashlib.sha256(image_file.read_bytes()).hexdigest()
state_file.write_bytes(b"Approved state\n")
print(json.dumps({"initial_sha256": before, "observed_sha256": after,
                  "root_write": write_result, "approved_volume_writable": state_file.read_bytes() == b"Approved state\n"}))
