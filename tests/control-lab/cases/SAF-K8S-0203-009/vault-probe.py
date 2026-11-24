"""Exercise token exchange, policy and expiry against the same-Pod Vault fixture."""

import json
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

ORIGIN = "http://127.0.0.1:8200/v1/"
CLIENT = build_opener(ProxyHandler({}))
CONTEXT = Path("/fixture")
AUDIENCE = "saf-fixture-workload"
SUBJECT = "system:serviceaccount:saf-test:fixture-workload-approved"
ROLE = "scoped-workload"
POLICY = "read-public-marker"
LEASE = 16
ALLOWED = "fixture/data/allowed"
OTHER = "fixture/data/other"
MARKER = "authorized public fixture marker"


def request(path, *, token=None, data=None, method=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    query = Request(ORIGIN + path, headers=headers,
                    data=json.dumps(data).encode() if data is not None else None, method=method)
    try:
        with CLIENT.open(query, timeout=4) as result:
            body = result.read()
            return result.status, json.loads(body) if body else {}
    except HTTPError as error:
        return error.code, {}
    except (URLError, TimeoutError):
        return 0, {}


def require(path, *, expect=200, **options):
    status, response = request(path, **options)
    if status != expect:
        raise RuntimeError(f"Unexpected Vault fixture status {status} for {path}")
    return response


def role(root, name, subject):
    require(f"auth/jwt/role/{name}", expect=204, token=root, data={
        "role_type": "jwt", "user_claim": "sub",
        "bound_subject": subject, "bound_audiences": [AUDIENCE],
        "claim_mappings": {"sub": "fixture_subject"},
        "token_policies": [POLICY], "token_no_default_policy": True,
        "token_type": "batch", "token_ttl": LEASE, "token_explicit_max_ttl": LEASE,
    })


def main():
    until = time.monotonic() + 25
    while request("sys/health")[0] != 501:
        if time.monotonic() >= until:
            raise RuntimeError("Isolated Vault fixture did not become reachable and uninitialized")
        time.sleep(0.5)

    init = require("sys/init", data={"secret_shares": 1, "secret_threshold": 1},
                   method="PUT")
    root = init["root_token"]
    require("sys/unseal", data={"key": init["keys_base64"][0]}, method="PUT")
    del init
    require("sys/auth/jwt", expect=204, token=root, data={"type": "jwt"})
    require("auth/jwt/config", expect=204, token=root, data={
        "jwt_validation_pubkeys": [(CONTEXT / "issuer.pub").read_text()],
        "bound_issuer": (CONTEXT / "issuer").read_text(),
        "jwt_supported_algs": ["RS256"],
    })
    require("sys/mounts/fixture", expect=204, token=root, data={"type": "kv", "options": {"version": "2"}})
    require("sys/policies/acl/" + POLICY, expect=204, token=root, data={
        "policy": f'path "{ALLOWED}" {{ capabilities = ["read"] }}',
    })
    require(ALLOWED, token=root, data={"data": {"marker": MARKER}})
    require(OTHER, token=root, data={"data": {"marker": "outside the granted policy"}})
    role(root, ROLE, SUBJECT)
    role(root, "other-subject", "system:serviceaccount:saf-test:fixture-workload-other")
    del root

    valid = Path("/identity/approved").read_text().strip()
    wrong_aud = Path("/identity/other-audience").read_text().strip()
    login = "auth/jwt/login"
    audience_status, _ = request(login, data={"role": ROLE, "jwt": wrong_aud})
    subject_status, _ = request(login, data={"role": "other-subject", "jwt": valid})
    started = time.monotonic()
    authenticated = require(login, data={"role": ROLE, "jwt": valid})["auth"]
    del valid, wrong_aud
    token = authenticated["client_token"]
    allowed, payload = request(ALLOWED, token=token)
    denied, _ = request(OTHER, token=token)
    write_denied, _ = request(ALLOWED, token=token, data={"data": {"marker": "disallowed replacement"}})
    expiry_at = started + LEASE
    time.sleep(max(0, expiry_at - time.monotonic()))
    expiry_status = 0
    while time.monotonic() < expiry_at + 8:
        expiry_status, _ = request(ALLOWED, token=token)
        if expiry_status == 403:
            break
        time.sleep(0.5)

    print(json.dumps({
        "audience_http": audience_status, "subject_http": subject_status,
        "allowed_read_http": allowed, "out_of_scope_read_http": denied,
        "out_of_scope_write_http": write_denied, "expired_read_http": expiry_status,
        "approved_public_marker": payload.get("data", {}).get("data", {}).get("marker") == MARKER,
        "vault_entity_assigned": bool(authenticated.get("entity_id")),
        "verified_claim_subject": authenticated["metadata"].get("fixture_subject"),
        "granted_policies": authenticated["policies"],
        "lease_seconds": authenticated["lease_duration"],
        "renewable": authenticated["renewable"],
    }))


if __name__ == "__main__":
    main()
