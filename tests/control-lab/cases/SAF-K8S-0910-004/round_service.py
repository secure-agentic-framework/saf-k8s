"""Synthetic mTLS FL coordinator used only by SAF-K8S-0910-004."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import sys
import threading


ROUND = "toy-round-2026-11-23-01"
PROTOCOL = "toy-vector-counts-v1"
PARTICIPANTS = {
    "spiffe://saf.test/ns/saf-test/sa/toy-participant-a": "cluster-a",
    "spiffe://saf.test/ns/saf-test/sa/toy-participant-b": "cluster-b",
}
ADMIN = "spiffe://saf.test/ns/saf-test/sa/toy-round-admin"
OBSERVER = "spiffe://saf.test/ns/saf-test/sa/toy-round-observer"
MAX_COUNT = 100
WIDTH = 3

STATE = {"contributions": [], "aggregate": None}
POLICY = {"enabled": False, "round": None, "members": []}
LOCK = threading.Lock()


def identity(cert):
    values = [value for kind, value in cert.get("subjectAltName", ()) if kind == "URI"]
    return values[0] if len(values) == 1 else None


def reply(status, decision, **fields):
    return status, {"status": status, "decision": decision, **fields}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *_args):
        return

    def do_GET(self):
        if self.path != "/v1/state" or identity(self.connection.getpeercert()) != OBSERVER:
            self._send(*reply(403, "observer_read_refused"))
            return
        with LOCK:
            snapshot = json.loads(json.dumps(STATE, sort_keys=True))
        self._send(200, snapshot)

    def do_POST(self):
        caller = identity(self.connection.getpeercert())
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > 2048:
            self._send(*reply(400, "fixture_request_size_refused"))
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, TypeError):
            self._send(*reply(400, "fixture_json_refused"))
            return

        if self.path == "/v1/admin/enforce":
            if caller != ADMIN:
                self._send(*reply(403, "admin_identity_refused"))
                return
            if body != {"round": ROUND, "members": sorted(PARTICIPANTS.values()), "protocol": PROTOCOL}:
                self._send(*reply(400, "fixture_policy_refused"))
                return
            with LOCK:
                POLICY.update(enabled=True, round=ROUND, members=sorted(PARTICIPANTS.values()))
            self._send(*reply(200, "round_policy_enabled", round=ROUND))
            return

        if self.path != "/v1/contributions" or caller not in PARTICIPANTS:
            self._send(*reply(403, "participant_identity_refused"))
            return
        cluster = PARTICIPANTS[caller]
        expected_shape = {"round", "protocol", "cluster", "counts"}
        if not isinstance(body, dict) or set(body) != expected_shape:
            self._send(*reply(400, "contribution_shape_refused"))
            return
        counts = body.get("counts")
        if (not isinstance(counts, list) or len(counts) != WIDTH or
                any(type(item) is not int or item < 0 or item > MAX_COUNT for item in counts)):
            self._send(*reply(400, "toy_count_vector_refused"))
            return

        with LOCK:
            if POLICY["enabled"]:
                if body["round"] != POLICY["round"]:
                    self._send(*reply(409, "round_mismatch", expected=POLICY["round"],
                                      received=body["round"]))
                    return
                if body["protocol"] != PROTOCOL:
                    self._send(*reply(409, "protocol_mismatch", expected=PROTOCOL,
                                      received=body["protocol"]))
                    return
                if body["cluster"] != cluster or cluster not in POLICY["members"]:
                    self._send(*reply(403, "round_member_refused", cluster=cluster))
                    return
            if any(row["round"] == body["round"] and row["cluster"] == cluster
                   for row in STATE["contributions"]):
                self._send(*reply(409, "duplicate_contribution_refused", round=body["round"],
                                  cluster=cluster))
                return
            contribution = {"round": body["round"], "protocol": body["protocol"],
                            "cluster": cluster, "counts": counts}
            STATE["contributions"].append(contribution)
            round_rows = [row for row in STATE["contributions"] if row["round"] == ROUND]
            if POLICY["enabled"] and len(round_rows) == len(PARTICIPANTS):
                sums = [sum(row["counts"][idx] for row in round_rows) for idx in range(WIDTH)]
                STATE["aggregate"] = {"round": ROUND, "protocol": PROTOCOL,
                                       "members": sorted(row["cluster"] for row in round_rows),
                                       "sum_counts": sums,
                                       "mean_counts": [value // len(round_rows) for value in sums]}
        self._send(*reply(200, "contribution_recorded", round=body["round"], cluster=cluster))

    def _send(self, status, payload):
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def serve():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/pki/server.crt", "/pki/server.key")
    context.load_verify_locations("/pki/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def client(host, port, server_name, cert, key, ca, method, path, payload=None):
    import http.client
    import socket
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.load_cert_chain(cert, key)
    raw = socket.create_connection((host, int(port)), timeout=8)
    try:
        tls = context.wrap_socket(raw, server_hostname=server_name)
        request = method + " " + path + " HTTP/1.0\r\nHost: " + server_name + "\r\n"
        data = b""
        if payload is not None:
            data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            request += "Content-Type: application/json\r\nContent-Length: " + str(len(data)) + "\r\n"
        tls.sendall((request + "\r\n").encode("ascii") + data)
        response = http.client.HTTPResponse(tls)
        response.begin()
        return json.loads(response.read())
    finally:
        raw.close()


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "serve":
        serve()
    elif len(sys.argv) == 11 and sys.argv[1] == "client":
        _, _, host, port, server_name, cert, key, ca, method, path, raw_payload = sys.argv
        print(json.dumps(client(host, port, server_name, cert, key, ca, method, path,
                                None if raw_payload == "-" else json.loads(raw_payload)),
                         sort_keys=True))
    else:
        raise SystemExit("invalid bounded fixture invocation")
