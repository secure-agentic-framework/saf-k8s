"""Generate ephemeral synthetic Ed25519 signatures using local OpenSSL only."""
import base64
import json
from pathlib import Path

from report_crypto import generate_and_sign
from signature_format import public_key_id, signing_payload


request = json.loads(Path("/fixture/signing-input.json").read_text())
names = list(request["evidence"])
payloads = [signing_payload(request["evidence"][name]) for name in names]
approved_pem, approved_signatures = generate_and_sign(payloads)
unapproved_pem, unapproved_signatures = generate_and_sign(
    [signing_payload(request["evidence"]["positive"])]
)
signatures = {
    name: base64.b64encode(signature).decode("ascii")
    for name, signature in zip(names, approved_signatures, strict=True)
}

# Output contains only public trust material and signatures over fixed inert records.
# The two private key objects remain process-local and are discarded at exit.
print(json.dumps({
    "approved_public_pem": approved_pem,
    "approved_key_id": public_key_id(approved_pem),
    "signatures": signatures,
    "unapproved_key_id": public_key_id(unapproved_pem),
    "unapproved_signature": base64.b64encode(unapproved_signatures[0]).decode("ascii"),
}, sort_keys=True))
