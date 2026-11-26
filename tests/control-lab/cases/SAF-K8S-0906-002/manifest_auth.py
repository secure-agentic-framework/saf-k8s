"""Verify the exact manifest bytes against the fixture-enrolled publisher key."""
import base64
import json
from pathlib import Path

from signature_crypto_base import generate_and_sign, verify

TRUST = Path("/trust")
MANIFEST = Path("/manifest/manifest.json")


def read_verified_manifest(path):
    payload = path.read_bytes()
    key = (TRUST / "public.pem").read_text()
    signature = base64.b64decode((TRUST / "manifest.sig").read_text().strip(), validate=True)
    return json.loads(payload) if verify(key, signature, payload) else None


if __name__ == "__main__":
    payload = MANIFEST.read_bytes()
    authorized_key, signatures = generate_and_sign([payload])
    _, unrelated_signatures = generate_and_sign([payload])
    print(json.dumps({
        "authorized_key": authorized_key,
        "authorized_signature": base64.b64encode(signatures[0]).decode("ascii"),
        "unrelated_signature": base64.b64encode(unrelated_signatures[0]).decode("ascii"),
    }, sort_keys=True))
