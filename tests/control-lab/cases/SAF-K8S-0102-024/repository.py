"""Serve one public backup marker and log the kernel-supplied peer identity."""

from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import struct

ROOT = Path("/repo")
TARGET = "fixture-backup-marker"
PATH = ROOT / "read.sock"
APPROVED_UID = 1002

marker = ROOT / TARGET
marker.touch(mode=0o600, exist_ok=False)
marker.write_bytes(b"public backup fixture")
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
    server.bind(str(PATH))
    PATH.chmod(0o666)
    server.listen(4)
    while True:
        connection, _ = server.accept()
        with connection:
            size = struct.calcsize("3i")
            _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))
            operation = connection.recv(16)
            allowed = uid == APPROVED_UID and operation == b"read"
            print(json.dumps({"source": "repository", "peer_uid": uid, "operation": "read" if operation == b"read" else "unknown",
                              "target": TARGET, "outcome": "allowed" if allowed else "denied",
                              "time": datetime.now(timezone.utc).isoformat()}), flush=True)
            connection.sendall(marker.read_bytes() if allowed else b"denied")
