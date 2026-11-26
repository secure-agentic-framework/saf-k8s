"""Authenticated, bounded fetch of the owned API's public OIDC metadata."""
import hashlib
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

API = "https://kubernetes.default.svc"
TOKEN = Path("/var/run/kubernetes/token")
CA = "/var/run/kubernetes-ca/ca.crt"
OUT = Path("/snapshot")
EXPECTED_ISSUER = os.environ["EXPECTED_ISSUER"]


class SnapshotError(Exception):
    pass


def fetch(path, context):
    token = TOKEN.read_text().strip()
    if not token:
        raise SnapshotError("missing_projected_token")
    request = urllib.request.Request(
        API + path,
        headers={"Authorization": "Bearer " + token, "Accept": "*/*"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=8) as response:
            if response.status != 200:
                raise SnapshotError("api_status_unexpected")
            return response.read()
    except urllib.error.HTTPError as error:
        raise SnapshotError(f"api_http_{error.code}") from None


def main():
    context = ssl.create_default_context(cafile=CA)
    discovery_bytes = fetch("/.well-known/openid-configuration", context)
    discovery = json.loads(discovery_bytes)
    jwks_uri = urlsplit(discovery.get("jwks_uri", ""))
    if discovery.get("issuer") != EXPECTED_ISSUER:
        raise SnapshotError("issuer_mismatch")
    if (discovery.get("jwks_uri") != API + "/openid/v1/jwks"
            or jwks_uri.scheme != "https" or jwks_uri.path != "/openid/v1/jwks"
            or jwks_uri.query or jwks_uri.fragment):
        raise SnapshotError("jwks_uri_mismatch")

    jwks_bytes = fetch("/openid/v1/jwks", context)
    jwks = json.loads(jwks_bytes)
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise SnapshotError("public_keys_missing")
    private_names = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    if any(private_names.intersection(key) for key in keys if isinstance(key, dict)):
        raise SnapshotError("unexpected_private_fields")

    OUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    (OUT / "discovery.json").write_bytes(discovery_bytes)
    (OUT / "jwks.json").write_bytes(jwks_bytes)
    (OUT / "snapshot-status.json").write_text(json.dumps({
        "discovery_http": 200,
        "jwks_http": 200,
        "issuer_matches": True,
        "jwks_uri_path_matches": True,
        "api_tls_verified": True,
        "api_bearer_auth_used": True,
        "public_key_count": len(keys),
        "private_fields_absent": True,
        "discovery_sha256": hashlib.sha256(discovery_bytes).hexdigest(),
        "jwks_sha256": hashlib.sha256(jwks_bytes).hexdigest(),
    }, sort_keys=True) + "\n")
    # No token, key, claim value or response body is written to stdout.
    print("authenticated-public-key-snapshot-ready", flush=True)


if __name__ == "__main__":
    try:
        main()
    except SnapshotError as error:
        print("snapshot fixture " + str(error), flush=True)
        raise SystemExit(1)
    except PermissionError:
        print("snapshot fixture permission denied", flush=True)
        raise SystemExit(1)
    except Exception as error:
        print("snapshot fixture failed " + type(error).__name__, flush=True)
        raise SystemExit(1)
