"""Accept one synthetic Tetragon event over fixture-only mTLS and persist a receipt."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import urllib.request


NAMESPACE = os.environ["FIXTURE_NAMESPACE"]
EXPECTED_POD = os.environ["FIXTURE_POD"]
EXPECTED_POLICY = os.environ["FIXTURE_POLICY"]
EXPECTED_PATH = os.environ["FIXTURE_PATH"]
RECEIPT = "saf-tetragon-event-receipt"
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
API_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TLS_CERT = "/tls/tls.crt"
TLS_KEY = "/tls/tls.key"
CLIENT_SAN = "spiffe://saf.example/0606-007/exporter"


def write_receipt(receipt):
    token = TOKEN.read_text(encoding="utf-8").strip()
    payload = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": RECEIPT, "labels": {
            "saf.example/tetragon-receipt": "true",
            "saf.example/source": "case-owned-exporter",
        }},
        "immutable": True,
        "data": {"receipt.json": json.dumps(receipt, sort_keys=True, separators=(",", ":"))},
    }
    request = urllib.request.Request(
        f"https://kubernetes.default.svc/api/v1/namespaces/{NAMESPACE}/configmaps",
        data=json.dumps(payload, sort_keys=True).encode(),
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    context = ssl.create_default_context(cafile=API_CA)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=5) as response:
            if response.status != 201:
                raise RuntimeError("receipt API write failed")
    except Exception:
        raise RuntimeError("receipt API write failed") from None


def valid_payload(payload, peer_sans):
    event = payload.get("event")
    process_exec = payload.get("process_exec")
    if not isinstance(event, dict) or not isinstance(process_exec, dict):
        return None
    process = event.get("process", {})
    pod = process.get("pod", {})
    exec_process = process_exec.get("process", {})
    exec_pod = exec_process.get("pod", {})
    args = event.get("args", [])
    path_match = any(isinstance(arg, dict)
                     and arg.get("file_arg", {}).get("path") == EXPECTED_PATH
                     for arg in args)
    valid = (
        payload.get("event_type") == "process_kprobe"
        and event.get("function_name") == "security_file_permission"
        and event.get("policy_name") == EXPECTED_POLICY
        and process.get("exec_id")
        and process.get("exec_id") == exec_process.get("exec_id")
        and exec_process.get("arguments") == f"cat {EXPECTED_PATH}"
        and pod.get("namespace") == NAMESPACE and pod.get("name") == EXPECTED_POD
        and exec_pod.get("namespace") == NAMESPACE and exec_pod.get("name") == EXPECTED_POD
        and path_match
        and ("URI", CLIENT_SAN) in peer_sans
    )
    if not valid:
        return None
    canonical_event = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    return {
        "accepted": True,
        "event_type": "process_kprobe",
        "policy_match": True,
        "path_match": True,
        "fixture_process_correlated": True,
        "fixture_pod_match": True,
        "authenticated_client": True,
        "client_identity": "fixture-exporter",
        "event_sha256": hashlib.sha256(canonical_event).hexdigest(),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        # Do not write headers, payloads, event identifiers, or certificate data.
        return

    def do_POST(self):
        if self.path != "/events":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 262144:
                self.send_error(413)
                return
            payload = json.loads(self.rfile.read(length))
            peer = self.connection.getpeercert()
            peer_sans = peer.get("subjectAltName", [])
            receipt = valid_payload(payload, peer_sans)
            if receipt is None:
                self.send_error(422)
                return
            write_receipt(receipt)
            body = b'{"accepted":true}'
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            self.send_error(400)


class ReceiverServer(ThreadingHTTPServer):
    def handle_error(self, _request, _client_address):
        # A client-certificate refusal is expected; suppress the default traceback.
        return


def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(TLS_CERT, TLS_KEY)
    context.load_verify_locations(cafile="/tls/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server = ReceiverServer(("0.0.0.0", 8443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    main()
