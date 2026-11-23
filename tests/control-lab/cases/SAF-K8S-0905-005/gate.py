"""Small inert promotion gate; evidence is submitted only after TokenReview."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request


TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
API = "https://kubernetes.default.svc"
NAMESPACE = "saf-test"
EVIDENCE_NAME = "promotion-evidence"
AUDIENCE = os.environ["PROMOTION_AUDIENCE"]
REPORTER = os.environ["REPORTER_USERNAME"]
MODEL_BYTES = b"SAF inert model fixture v1\n"
MODEL_DIGEST = hashlib.sha256(MODEL_BYTES).hexdigest()
GATES = ("security", "bias", "performance", "robustness")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _api(method, path, body=None):
    token = TOKEN_PATH.read_text().strip()
    payload = None if body is None else json.dumps(body, sort_keys=True).encode()
    request = urllib.request.Request(
        API + path, data=payload, method=method,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile=CA_PATH)
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as response:
        try:
            return response.code, json.load(response)
        except (ValueError, OSError):
            raise RuntimeError("Kubernetes API returned a non-JSON error") from None
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        raise RuntimeError("Kubernetes API request failed") from None


def _review(token):
    status, result = _api("POST", "/apis/authentication.k8s.io/v1/tokenreviews", {
        "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
        "spec": {"token": token, "audiences": [AUDIENCE]}})
    if status != 201:
        raise RuntimeError("TokenReview failed")
    state = result.get("status", {})
    return {"authenticated": state.get("authenticated") is True,
            "username": state.get("user", {}).get("username"),
            "audiences": sorted(state.get("audiences", []))}


def _store_and_read(name, evidence):
    if name != EVIDENCE_NAME:
        raise ValueError("invalid-evidence-name")
    path = f"/api/v1/namespaces/{NAMESPACE}/configmaps/{name}"
    status, current = _api("GET", path)
    if status != 200:
        raise RuntimeError("evidence ConfigMap lookup failed")
    resource = {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": name, "namespace": NAMESPACE,
                             "labels": {"saf.example/evidence": "promotion-gate"},
                             "resourceVersion": current["metadata"]["resourceVersion"]},
                "data": {"evidence.json": json.dumps(evidence, sort_keys=True)}}
    status, _ = _api("PUT", path, resource)
    if status != 200:
        raise RuntimeError("evidence ConfigMap update failed")
    status, stored = _api("GET", path)
    if status != 200:
        raise RuntimeError("evidence ConfigMap read-back failed")
    return json.loads(stored["data"]["evidence.json"])


def _evaluate(evidence):
    results = evidence.get("gates", {})
    gate_results = {gate: results.get(gate, {}).get("status", "missing")
                    for gate in GATES}
    artifact = evidence.get("artifact", {})
    artifact_matches = (artifact.get("name") == "saf-fixture-model-v1" and
                        artifact.get("sha256") == MODEL_DIGEST)
    predicate = {"artifact": artifact, "gates": results}
    predicate_digest = hashlib.sha256(_canonical(predicate)).hexdigest()
    attestation = evidence.get("attestation", {})
    provenance_matches = (
        attestation.get("builder") == "fixture://saf-k8s/0905-005" and
        attestation.get("subject_sha256") == MODEL_DIGEST and
        attestation.get("predicate_sha256") == predicate_digest)
    signature_verification = "unverified"
    allowed = (all(gate_results[name] == "pass" for name in GATES) and
               artifact_matches and provenance_matches)
    return {"accepted": allowed, "gate_results": gate_results,
            "model_sha256": MODEL_DIGEST, "artifact_matches": artifact_matches,
            "predicate_sha256": predicate_digest,
            "provenance_matches": provenance_matches,
            "signature_verification": signature_verification}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def _reply(self, code, payload):
        encoded = json.dumps(payload, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"ready": True})
        else:
            self._reply(404, {"error": "not-found"})

    def do_POST(self):
        if self.path != "/evaluate":
            self._reply(404, {"error": "not-found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 16384:
                self._reply(413, {"error": "invalid-request-size"})
                return
            request = json.loads(self.rfile.read(length))
            evidence = request["evidence"]
            evidence_name = request["evidence_name"]
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            self._reply(400, {"error": "invalid-request"})
            return
        if os.environ.get("ENFORCE_GATES") != "true":
            # Deliberate baseline: same fixture artifact, gates not consulted.
            self._reply(200, {"accepted": True, "reason": "enforcement-disabled"})
            return
        bearer = self.headers.get("Authorization", "")
        token = bearer[7:] if bearer.startswith("Bearer ") else ""
        if not token:
            self._reply(403, {"accepted": False, "reason": "missing-reporter-token"})
            return
        try:
            identity = _review(token)
            if (not identity["authenticated"] or identity["username"] != REPORTER or
                    AUDIENCE not in identity["audiences"]):
                self._reply(403, {"accepted": False, "reason": "reporter-not-authorized"})
                return
            stored = _store_and_read(evidence_name, evidence)
            result = _evaluate(stored)
        except (RuntimeError, ValueError):
            self._reply(503, {"error": "evidence-processing-unavailable"})
            return
        self._reply(200 if result["accepted"] else 403,
                    {**result, "reporter": identity["username"],
                     "evidence_name": evidence_name, "evidence_read_back": True})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
