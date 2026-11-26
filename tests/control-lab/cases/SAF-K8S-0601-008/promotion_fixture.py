"""Validate scan evidence and write the exact bytes to the local test registry."""
from datetime import datetime, timedelta
import base64
from http.client import HTTPConnection
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

from image_fixture import DISTRIBUTION, digest, image

NAME = "fixture-scan-registry"
REPO = "fixtures/prerelease"
NOW = datetime.fromisoformat("2026-11-23T12:00:00+00:00")
BLOCKING = {"HIGH", "CRITICAL"}
SEVERITIES = BLOCKING | {"MEDIUM", "LOW", "NONE"}


def request(method, path, body=None, media=None):
    connection = HTTPConnection(NAME + ".saf-test.svc", 5000, timeout=4)
    try:
        headers = {"Accept": DISTRIBUTION}
        if media is not None:
            headers["Content-Type"] = media
        connection.request(method, path, headers=headers, body=body)
        response = connection.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        connection.close()


def ready():
    deadline = time.monotonic() + 20
    while True:
        try:
            if request("GET", "/v2/")[0] == 200:
                return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError("Registry service is unreachable")
        time.sleep(0.25)


def timestamp(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.utcoffset() != timedelta(0):
        raise ValueError("Timestamp must be UTC")
    return dt


def exception_covers(exception, subject, findings):
    if not exception or exception.get("approval") != "fixture-security-reviewer":
        return False
    try:
        return (exception["repository"] == REPO and exception["subject"] == subject
                and set(exception["finding_ids"]) == findings
                and timestamp(exception["start"]) <= NOW < timestamp(exception["end"]))
    except (TypeError, ValueError, KeyError):
        return False


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def verify_report_envelope(envelope):
    """Verify the exact canonical report under the separately mounted case trust policy."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get("report"), dict):
        return "report-malformed", None
    try:
        policy = json.loads(Path("/trust/report-policy.json").read_text())
    except (OSError, ValueError):
        return "report-trust-policy-unavailable", None
    if envelope.get("signer_id") != policy["trusted_signer_id"]:
        return "report-untrusted-signer", None
    try:
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
        payload = canonical(envelope["report"])
        from report_crypto import verify
        if not verify(Path(policy["trusted_public_key"]).read_text(), signature, payload):
            return "report-signature-invalid", None
        return None, {"signer_id": policy["trusted_signer_id"],
                      "signature_verified": True,
                      "payload_sha256": hashlib.sha256(payload).hexdigest()}
    except (KeyError, TypeError, ValueError, OSError):
        return "report-signature-invalid", None


def decide(report, subject, exception):
    if report is None:
        return "report-absent"
    envelope_error, _ = verify_report_envelope(report)
    if envelope_error:
        return envelope_error
    report = report["report"]
    if not isinstance(report, dict):
        return "report-malformed"
    if report.get("state") != "completed":
        return "scanner-error"
    if report.get("artifact") != subject or report.get("repository") != REPO:
        return "report-subject-mismatch"
    try:
        age = NOW - timestamp(report["time"])
        if not timedelta(0) <= age <= timedelta(hours=24):
            return "report-stale"
    except (TypeError, ValueError, KeyError, AttributeError):
        return "report-malformed"
    items = report.get("findings")
    if not isinstance(items, list) or not all(isinstance(item, dict)
            and item.get("id") and item.get("severity") in SEVERITIES for item in items):
        return "report-malformed"
    blocked = {item["id"] for item in items if item["severity"] in BLOCKING}
    if not blocked:
        return "allowed-clear"
    return "allowed-exception" if exception_covers(exception, subject, blocked) else "blocked-severity"


def publish(tag, artifact):
    prefix = f"/v2/{REPO}/"
    for blob in (artifact["config.json"], artifact["layer.tar.gz"]):
        status, _, headers = request("POST", prefix + "blobs/uploads/", b"")
        if status != 202:
            raise RuntimeError(f"Registry refused upload initialization: {status}")
        location = urlsplit(headers["Location"])
        if not location.path.startswith(prefix + "blobs/uploads/"):
            raise RuntimeError("Unexpected owned registry upload location")
        query = urlencode([*parse_qsl(location.query), ("digest", digest(blob))])
        status, _, _ = request("PUT", location.path + "?" + query, blob, "application/octet-stream")
        if status != 201:
            raise RuntimeError(f"Registry refused upload: {status}")
    status, _, _ = request("PUT", prefix + "manifests/" + tag, artifact["manifest.json"], DISTRIBUTION)
    if status != 201:
        raise RuntimeError(f"Registry refused manifest: {status}")


def inspect(tag):
    path = f"/v2/{REPO}/manifests/{tag}"
    status, data, headers = request("GET", path)
    if status == 404:
        return {"status": status, "digest": None, "blobs_available": False}
    if status != 200 or headers.get("Docker-Content-Digest") != digest(data):
        raise RuntimeError(f"Unexpected manifest response: {status}")
    manifest = json.loads(data)
    entries = [manifest["config"], *manifest["layers"]]
    present = all(request("HEAD", f"/v2/{REPO}/blobs/{item['digest']}")[0] == 200 for item in entries)
    return {"status": status, "digest": digest(data), "blobs_available": present}


def promote(proposal):
    tag, variant = proposal["tag"], proposal["version"]
    artifact = image(variant)
    subject = digest(artifact["manifest.json"])
    if proposal["mode"] == "baseline":
        reason = "unchecked-baseline"
    else:
        reason = decide(proposal["report"], subject, proposal["exception"])
    publish_allowed = reason in {"unchecked-baseline", "allowed-clear", "allowed-exception"}
    if publish_allowed:
        publish(tag, artifact)
    return {"tag": tag, "subject": subject, "decision": reason, "manifest_written": publish_allowed}


if __name__ == "__main__":
    operation = sys.argv[1]
    if operation == "ready":
        ready()
    elif operation == "inspect":
        print(json.dumps(inspect(sys.argv[2]), sort_keys=True))
    elif operation == "promote":
        print(json.dumps(promote(json.load(sys.stdin)), sort_keys=True))
