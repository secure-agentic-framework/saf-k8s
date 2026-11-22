"""Emit receipts for exact fixture bundles using the ephemeral CI HMAC key."""
from hashlib import sha256
import hmac
import json
from pathlib import Path

payload = Path("/input")
key = Path("/authority/key").read_bytes()
claims = json.loads((payload/"claims.json").read_text())
receipts = []
for item in claims:
    manifest = payload / (item["name"]+".json")
    signed = {**item, "sha256": sha256(manifest.read_bytes()).hexdigest()}
    encoded = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    receipts.append({"claims": signed, "hmac": hmac.new(key, encoded, sha256).hexdigest()})
print(json.dumps(receipts))
