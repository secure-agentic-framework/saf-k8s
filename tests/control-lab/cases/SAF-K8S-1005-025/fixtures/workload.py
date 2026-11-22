"""Emit the fixture records and metadata for one verified loopback TCP exchange."""
import json
from pathlib import Path
import socket


def read_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise RuntimeError("Fixture socket closed before the marker was complete")
        result.extend(chunk)
    return bytes(result)


fixture = json.loads(Path("/fixture/workload-log.json").read_text())
for row in fixture["records"]:
    print(json.dumps(row, sort_keys=True))
marker = b"saf-1005-025-synthetic"
response = b"saf-1005-025-confirmed"
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.settimeout(5)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    with socket.create_connection(listener.getsockname(), timeout=5) as client:
        accepted, client_address = listener.accept()
        with accepted:
            accepted.settimeout(5)
            client.sendall(marker)
            if read_exact(accepted, len(marker)) != marker:
                raise RuntimeError("Fixture marker did not arrive")
            accepted.sendall(response)
            if read_exact(client, len(response)) != response:
                raise RuntimeError("Fixture response did not arrive")
            print(json.dumps({"kind": "fixture-connection", "protocol": "tcp",
                              "source": client_address[0], "destination": accepted.getsockname()[0],
                              "requests": 1, "responses": 1, "marker_verified": True},
                             sort_keys=True))
