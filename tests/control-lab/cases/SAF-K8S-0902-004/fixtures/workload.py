"""Fixed synthetic model endpoint and Linux isolation/accounting probe."""
import http.server
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit


PORT = 8443
HEALTH_MARKER = "SYNTH-SAF-0902-004-HEALTH-OK"


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def cgroup_memory():
    """Read memory counters from this process's own cgroup, never a guessed peer."""
    rows = Path("/proc/self/cgroup").read_text().splitlines()
    v2_path = next((row.split("::", 1)[1] for row in rows if row.startswith("0::")), None)
    if v2_path is not None:
        base = Path("/sys/fs/cgroup") / v2_path.lstrip("/")
        current_file, limit_file = base / "memory.current", base / "memory.max"
        if current_file.is_file() and limit_file.is_file():
            raw_limit = limit_file.read_text().strip()
            metrics = dict(line.split() for line in (base / "memory.stat").read_text().splitlines())
            return {"supported": raw_limit.isdigit(), "version": 2, "shmem_bytes": int(metrics["shmem"]),
                    "current_bytes": int(current_file.read_text().strip()),
                    "limit_bytes": int(raw_limit) if raw_limit.isdigit() else None,
                    "counter": "memory.current", "limit_counter": "memory.max"}
    v1_path = next((row.split(":", 2)[2] for row in rows
                    if ":memory:" in row or row.split(":", 2)[1].endswith(",memory")), None)
    if v1_path is not None:
        base = Path("/sys/fs/cgroup/memory") / v1_path.lstrip("/")
        current_file, limit_file = base / "memory.usage_in_bytes", base / "memory.limit_in_bytes"
        if current_file.is_file() and limit_file.is_file():
            current, limit = int(current_file.read_text().strip()), int(limit_file.read_text().strip())
            # cgroup v1 uses a very large sentinel for an unlimited value.
            return {"supported": limit < (1 << 60), "version": 1,
                    "current_bytes": current, "limit_bytes": limit,
                    "counter": "memory.usage_in_bytes", "limit_counter": "memory.limit_in_bytes"}
    return {"supported": False, "reason": "own-cgroup-memory-files-unavailable"}


def scratch_observation(filename):
    path = Path("/dev/shm") / filename
    observed = path.read_text(encoding="ascii").strip()
    mount = None
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 9 and fields[4].replace("\\040", " ") == "/dev/shm":
            split = fields.index("-")
            mount = {"mount_id": int(fields[0]), "filesystem": fields[split + 1],
                     "source": fields[split + 2], "options": fields[split + 3]}
            break
    stats = os.statvfs("/dev/shm")
    return {"path": str(path), "own_marker": observed,
            "capacity_bytes": stats.f_frsize * stats.f_blocks,
            "free_bytes": stats.f_frsize * stats.f_bavail,
            "mount_namespace": os.readlink("/proc/self/ns/mnt"), **(mount or {})}


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        peer = self.connection.getpeercert()
        common_names = [value for subject in peer.get("subject", ())
                        for key, value in subject if key == "commonName"]
        event = {"event": "authenticated-health", "path": self.path,
                 "peer_cn": common_names[0] if common_names else "missing"}
        print(json.dumps(event, sort_keys=True), flush=True)
        body = HEALTH_MARKER.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        # Suppress request lines, headers, client addresses, and error details.
        return


class ModelServer(http.server.ThreadingHTTPServer):
    def get_request(self):
        try:
            return super().get_request()
        except ssl.SSLError as error:
            if error.reason == "PEER_DID_NOT_RETURN_A_CERTIFICATE":
                emit({"event": "client-certificate-required"})
            raise


def serve(role):
    Path("/dev/shm/model-cache.marker").write_text(os.environ["SYNTHETIC_MARKER"] + "\n", encoding="ascii")
    if role == "model-a":
        while True:
            time.sleep(30)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    context.load_verify_locations(cafile="/tls/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server = ModelServer(("0.0.0.0", PORT), HealthHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True).start()
    Path("/dev/shm/model-server.ready").write_text("ready\n", encoding="ascii")
    while True:
        time.sleep(30)


def request(url, identity):
    context = ssl.create_default_context(cafile="/tls/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    if identity == "client-cert":
        context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    target = urlsplit(url)
    if target.hostname != "model-b.saf-0902-004.svc.cluster.local" or target.port != PORT or target.path != "/healthz":
        raise ValueError("Only the owned model Service's fixed health path is supported")
    connection = http.client.HTTPSConnection(target.hostname, PORT, timeout=4, context=context)
    try:
        connection.connect()
        tls_version = connection.sock.version()
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        body = response.read(256).decode("ascii")
        emit({"result": "response", "status": response.status, "body": body,
              "tls_version": tls_version})
    except (ssl.SSLError, ConnectionResetError) as error:
        emit({"result": "tls-rejected", "failure_class": type(error).__name__,
              "reason": getattr(error, "reason", None)})
    finally:
        connection.close()


def main():
    action = sys.argv[1]
    if action == "ready":
        marker = "/dev/shm/model-cache.marker" if sys.argv[2] == "model-a" else "/dev/shm/model-server.ready"
        if not Path(marker).is_file():
            raise SystemExit(1)
        emit({"ready": True})
    elif action == "serve":
        serve(sys.argv[2])
    elif action == "allocate":
        marker = b"a" * (1024 * 1024)
        Path("/dev/shm/owned-accounting-sample").write_bytes(marker)
        emit({"allocated_bytes": len(marker)})
    elif action == "observe":
        emit({"scratch": scratch_observation(sys.argv[2]), "cgroup": cgroup_memory()})
    elif action == "request":
        request(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("unsupported fixed fixture action")


if __name__ == "__main__":
    main()
