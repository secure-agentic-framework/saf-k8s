"""Fetch fixed local feed routes over verified TLS, then use the existing evaluator."""
import hashlib
from http.client import HTTPSConnection
import json
import os
import ssl
import time
from pathlib import Path

from worker import evaluate


ROOT = Path("/case")
HOST = "saf-1004-004-feed.saf-test.svc.cluster.local"
EXPECTED_BUNDLE_SHA256 = "99b0a2d0515a4551e9038413265e1c0b972ccf20f294e6ed38c03327cc29917b"


def get(path, cafile):
    context = ssl.create_default_context(cafile=cafile)
    deadline = time.monotonic() + 15
    while True:
        connection = HTTPSConnection(HOST, context=context, timeout=6)
        try:
            connection.request("GET", "/" + path)
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError("unexpected_status")
            body = response.read(16385)
            if len(body) > 16384:
                raise ValueError("case feed response exceeds bound")
            return body
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
        finally:
            connection.close()


def main():
    ca = (ROOT / "tls-ca.crt").read_bytes()
    ca_digest = hashlib.sha256(ca).hexdigest()
    if ca_digest != os.environ["EXPECTED_CA_SHA256"]:
        print(json.dumps({"ready": False, "reason": "pinned_ca_mismatch"}, sort_keys=True))
        return
    observations = json.loads((ROOT / "observations.json").read_text())
    approved = get("approved", ROOT / "tls-ca.crt")
    modified = get("modified", ROOT / "tls-ca.crt")
    accepted = evaluate(approved, EXPECTED_BUNDLE_SHA256, "2026-11-21T12:00:00Z", observations)
    changed = evaluate(modified, EXPECTED_BUNDLE_SHA256, "2026-11-21T12:00:00Z", observations)
    expired = evaluate(approved, EXPECTED_BUNDLE_SHA256, "2026-11-23T00:00:00Z", observations)
    wrong_ca_rejected = False
    try:
        get("approved", ROOT / "wrong-ca.crt")
    except ssl.SSLCertVerificationError:
        wrong_ca_rejected = True
    # Do not emit response bodies, certificates, or request details.
    result = {
        "ready": True,
        "ca_sha256_matches_independent_pin": True,
        "approved_fetch": {"tls_verified": True, "status": 200,
                            "byte_count": len(approved),
                            "sha256": hashlib.sha256(approved).hexdigest()},
        "approved_evaluator": {"accepted": accepted["accepted"],
                               "enrichment_count": len(accepted["enrichments"]),
                               "quiet_ids": accepted["quiet_observation_ids"]},
        "modified_evaluator": {"accepted": changed["accepted"],
                               "reason": changed["quarantine_reason"],
                               "enrichment_count": len(changed["enrichments"])},
        "expired_evaluator": {"accepted": expired["accepted"],
                              "reason": expired["quarantine_reason"]},
        "wrong_ca_certificate_rejected": wrong_ca_rejected,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
