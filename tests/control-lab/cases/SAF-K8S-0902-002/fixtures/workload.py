"""Harmless mock serving and independent readback workload for SAF-K8S-0902-002."""
import hashlib
import http.server
import json
from pathlib import Path
import sys


MODEL = Path("/model/marker.txt")
MARKER = MODEL.read_bytes()


def mount_is_readonly():
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 5 and fields[4] == "/model":
            return "ro" in fields[5].split(",")
    return False


if sys.argv[1] == "readback":
    print(json.dumps({"event": "independent_readback", "marker": MARKER.decode(),
                      "sha256": hashlib.sha256(MARKER).hexdigest()}, sort_keys=True), flush=True)
    raise SystemExit(0)

if sys.argv[1] != "serve":
    raise SystemExit("unsupported synthetic fixture mode")

try:
    with MODEL.open("wb") as output:
        output.write(b"SYNTHETIC_WRITE_PROBE\n")
except OSError as error:
    write_denied = True
    write_errno = error.errno
else:
    write_denied = False
    write_errno = None

receipt = {"event": "mock_startup", "marker": MARKER.decode().rstrip("\n"),
           "digest": "sha256:" + hashlib.sha256(MARKER).hexdigest(),
           "mount_readonly": mount_is_readonly(), "write_denied": write_denied,
           "write_errno": write_errno}
print(json.dumps(receipt, sort_keys=True), flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in {"/ready", "/marker"}:
            self.send_error(404)
            return
        body = b"ready\n" if self.path == "/ready" else MARKER
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
