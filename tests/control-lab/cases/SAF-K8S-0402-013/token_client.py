"""Bounded projected-token consumer; only fingerprints and JWT timing are written."""
import base64
import hashlib
import json
import os
from pathlib import Path
import time


TOKEN_PATH = Path("/var/run/saf-token/token")
STATE_PATH = Path("/tmp/saf-0402-013-client.json")
TEMP_PATH = Path("/tmp/.saf-0402-013-client.json.part")
SAMPLE_SECONDS = 2


def _claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    audience = claims.get("aud", [])
    return {
        "iat": int(claims["iat"]),
        "exp": int(claims["exp"]),
        "audiences": audience if isinstance(audience, list) else [audience],
    }


first_fingerprint = None
first_claims = None
previous_fingerprint = None
refresh_count = 0
read_count = 0

while True:
    try:
        token = TOKEN_PATH.read_text(encoding="ascii").strip()
        if token.count(".") != 2:
            raise ValueError("invalid token shape")
        claims = _claims(token)
        fingerprint = hashlib.sha256(token.encode("ascii")).hexdigest()
        if first_fingerprint is None:
            first_fingerprint = fingerprint
            first_claims = claims
        elif fingerprint != previous_fingerprint:
            refresh_count += 1
        previous_fingerprint = fingerprint
        read_count += 1
        state = {
            "ok": True,
            "first_sha256": first_fingerprint,
            "current_sha256": fingerprint,
            "first_iat": first_claims["iat"],
            "first_exp": first_claims["exp"],
            "current_iat": claims["iat"],
            "current_exp": claims["exp"],
            "current_audiences": claims["audiences"],
            "refresh_count": refresh_count,
            "read_count": read_count,
            "observed_unix": int(time.time()),
        }
        TEMP_PATH.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        os.replace(TEMP_PATH, STATE_PATH)
    except Exception:
        # Do not print exceptions or token material; publish a bounded generic state.
        state = {"ok": False, "error": "token-read-or-parse-failed"}
        try:
            TEMP_PATH.write_text(json.dumps(state), encoding="utf-8")
            os.replace(TEMP_PATH, STATE_PATH)
        except OSError:
            pass
    time.sleep(SAMPLE_SECONDS)
