"""TLS admission webhook for the local, synthetic 0801-006 Kind fixture."""
import http.client
import http.server
import json
import os
import re
import ssl
import time
from urllib.parse import urlsplit


DENIAL_BINDING = "fixture reuse evidence binding mismatch"
DENIAL_INVALID = "fixture reuse evidence has invalid validity"
DENIAL_EARLY = "fixture reuse evidence is not yet valid"
DENIAL_EXPIRED = "fixture reuse evidence expired"
MAX_BODY = 65536
MAX_API_BODY = 2 * 1024 * 1024
FIELDS = ("allocation", "transition", "target-trust")


class EvidenceReadError(Exception):
    """The live API evidence could not be read or decoded safely."""


def read_record():
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
    port_text = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS") or os.environ.get("KUBERNETES_SERVICE_PORT", "")
    if not host or not re.fullmatch(r"[A-Za-z0-9.:-]+", host) or not port_text.isascii() or not port_text.isdigit():
        raise EvidenceReadError
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise EvidenceReadError
    try:
        with open("/identity/token", "rb") as token_file:
            token = token_file.read(16385)
        if not token or len(token) > 16384 or b"\n" in token or b"\r" in token:
            raise EvidenceReadError
        context = ssl.create_default_context(cafile="/identity/ca.crt")
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        conn = http.client.HTTPSConnection(host, port, timeout=3, context=context)
        try:
            # Fixed path and no proxy handler: credentials go only to the API server.
            conn.request("GET", "/api/v1/namespaces/saf-test/configmaps/fixture-platform-record",
                         headers={"Authorization": "Bearer " + token.decode("ascii"),
                                  "Accept": "application/json"})
            response = conn.getresponse()
            if response.status != 200:
                raise EvidenceReadError
            raw = response.read(MAX_API_BODY + 1)
            if len(raw) > MAX_API_BODY:
                raise EvidenceReadError
        finally:
            conn.close()
        parsed = json.loads(raw)
        if (not isinstance(parsed, dict) or parsed.get("kind") != "ConfigMap"
                or parsed.get("metadata", {}).get("name") != "fixture-platform-record"
                or parsed.get("metadata", {}).get("namespace") != "saf-test"
                or not isinstance(parsed.get("data"), dict)
                or any(not isinstance(value, str) for value in parsed["data"].values())):
            raise EvidenceReadError
        return parsed["data"]
    except EvidenceReadError:
        raise
    except Exception as exc:
        raise EvidenceReadError from exc


def validity(data, now):
    issued_text = data.get("issued-at")
    expires_text = data.get("expires-at")
    if (not isinstance(issued_text, str) or not isinstance(expires_text, str)
            or len(issued_text) > 12 or len(expires_text) > 12
            or not re.fullmatch(r"[0-9]+", issued_text)
            or not re.fullmatch(r"[0-9]+", expires_text)):
        return DENIAL_INVALID
    issued, expires = int(issued_text), int(expires_text)
    if issued >= expires or expires - issued > 300:
        return DENIAL_INVALID
    if now < issued:
        return DENIAL_EARLY
    if now >= expires:
        return DENIAL_EXPIRED
    return None


def admission_denial(data, obj, now):
    if (data.get("state") != "approved"
            or data.get("evidence-kind") != "reviewed-device-attestation"
            or data.get("workload") != "guarded-approved"
            or not isinstance(data.get("evidence-id"), str)
            or not data["evidence-id"].strip()):
        return DENIAL_BINDING
    annotations = obj.get("metadata", {}).get("annotations")
    if not isinstance(annotations, dict):
        return DENIAL_BINDING
    for field in FIELDS:
        key = "fixture.example/" + field
        if not isinstance(data.get(field), str) or not data[field] or annotations.get(key) != data[field]:
            return DENIAL_BINDING
    return validity(data, now)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if urlsplit(self.path).path != "/validate":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise ValueError
            envelope = json.loads(self.rfile.read(length))
            if not isinstance(envelope, dict) or envelope.get("apiVersion") != "admission.k8s.io/v1" or envelope.get("kind") != "AdmissionReview":
                raise ValueError
            request = envelope["request"]
            if not isinstance(request, dict):
                raise ValueError
            obj = request["object"]
            metadata = obj["metadata"]
            if (not isinstance(request.get("uid"), str) or request["uid"] == ""
                    or request.get("operation") != "CREATE"
                    or request.get("namespace") != "saf-test"
                    or request.get("kind") != {"group": "", "version": "v1", "kind": "Pod"}
                    or request.get("resource") != {"group": "", "version": "v1", "resource": "pods"}
                    or not isinstance(obj, dict) or obj.get("kind") != "Pod"
                    or not isinstance(metadata, dict) or metadata.get("name") != "guarded-approved"
                    or metadata.get("namespace", "saf-test") != "saf-test"):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            self.send_error(400)
            return

        try:
            record = read_record()
        except EvidenceReadError:
            self.send_error(503, "fixture evidence unavailable")
            print(json.dumps({"event": "admission", "allowed": False, "response_code": 503}), flush=True)
            return
        denial = admission_denial(record, obj, int(time.time()))
        allowed = denial is None
        response = {
            "apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
            "response": {"uid": request["uid"], "allowed": allowed,
                         **({} if allowed else {"status": {
                             "code": 403, "reason": "Forbidden", "message": denial}})},
        }
        print(json.dumps({"event": "admission", "allowed": allowed,
                          "response_code": None if allowed else 403,
                          "response_message": denial}), flush=True)
        payload = json.dumps(response, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return


server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
