"""Measure actual content and write results for the fixture-owned paths."""

import errno
import hashlib
import json
from pathlib import Path

image_file = Path("/baseline/drift-marker.txt")
state_file = Path("/state/approved-marker.txt")
original = image_file.read_bytes()
before = hashlib.sha256(original).hexdigest()
write_result = "ok"
try:
    image_file.write_bytes(original)
    same_content = hashlib.sha256(image_file.read_bytes()).hexdigest()
    with image_file.open("ab") as stream:
        stream.write(b"Observed fixture change\n")
except OSError as error:
    if error.errno != errno.EROFS:
        raise
    write_result = "readonly"
    same_content = hashlib.sha256(image_file.read_bytes()).hexdigest()
after = hashlib.sha256(image_file.read_bytes()).hexdigest()
state_file.write_bytes(b"Approved initial state\n")
state_before = hashlib.sha256(state_file.read_bytes()).hexdigest()
state_file.write_bytes(b"Approved changed state\n")
state_after = hashlib.sha256(state_file.read_bytes()).hexdigest()
print(json.dumps({"path": str(image_file), "initial_sha256": before, "same_content_sha256": same_content,
                  "observed_sha256": after, "root_write": write_result,
                  "state_path": str(state_file), "state_initial_sha256": state_before, "state_sha256": state_after}))
