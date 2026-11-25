"""Issue only fixed synthetic fixture tokens and perform ordinary fixed GETs."""
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request


POLICY = json.load(open("/case/policy.json", encoding="utf-8"))
KEY = open("/run/test-key/key", "rb").read()
SCENARIOS = {
    "red-absent": ("model-alpha", None),
    "red-wrong-model": ("model-beta", "synthetic-client-a"),
    "green-absent": ("model-alpha", None),
    "green-expired": ("model-alpha", "synthetic-client-a"),
    "green-wrong-issuer": ("model-alpha", "synthetic-client-a"),
    "green-wrong-audience": ("model-alpha", "synthetic-client-a"),
    "green-wrong-algorithm": ("model-alpha", "synthetic-client-a"),
    "green-unregistered-subject": ("model-alpha", "synthetic-client-a"),
    "green-bad-signature": ("model-alpha", "synthetic-client-a"),
    "green-malformed-claims": ("model-alpha", "synthetic-client-a"),
    "green-wrong-model": ("model-beta", "synthetic-client-a"),
    "positive-alpha": ("model-alpha", "synthetic-client-a"),
    "positive-beta": ("model-beta", "synthetic-client-b"),
}


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def issue_fixed_token(identity, lifetime_seconds, *, issuer="saf-0902-008-local-issuer",
                      audience="saf-0902-008-fixture", algorithm="HS256",
                      subject=None, malformed_exp=False, bad_signature=False):
    header = b64(json.dumps({"alg": algorithm, "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"iss": issuer, "aud": audience,
              "sub": subject or identity,
              "models": POLICY["identities"].get(subject or identity,
                                                   POLICY["identities"][identity]),
              "exp": int(time.time()) + lifetime_seconds}
    if malformed_exp:
        claims["exp"] = "not-an-integer"
    payload = b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    signature = b64(hmac.new(KEY, signing_input.encode("ascii"), hashlib.sha256).digest())
    if bad_signature:
        replacement = "A" if signature[0] != "A" else "B"
        signature = replacement + signature[1:]
    return f"{signing_input}.{signature}"


if len(sys.argv) != 3 or sys.argv[1] not in SCENARIOS:
    print(json.dumps({"result": "invalid-fixed-scenario"}))
    raise SystemExit(64)
scenario, base_url = sys.argv[1], sys.argv[2].rstrip("/")
model, identity = SCENARIOS[scenario]
headers = {"X-Fixture-Event-ID": scenario}
if identity:
    negative_tokens = {
        "green-wrong-issuer": {"issuer": "saf-0902-008-unapproved-issuer"},
        "green-wrong-audience": {"audience": "saf-0902-008-unapproved-audience"},
        "green-wrong-algorithm": {"algorithm": "HS384"},
        "green-unregistered-subject": {"subject": "synthetic-unregistered-client"},
        "green-bad-signature": {"bad_signature": True},
        "green-malformed-claims": {"malformed_exp": True},
    }
    token = issue_fixed_token(
        identity, -60 if scenario == "green-expired" else 120,
        **negative_tokens.get(scenario, {}))
    headers["Authorization"] = "Bearer " + token
request = urllib.request.Request(
    f"{base_url}/v1/models/{model}/infer", headers=headers, method="GET")
try:
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as response:
        result = {"event_id": scenario, "model": model, "identity": identity or "none",
                  "status": response.status, "body": json.loads(response.read(512))}
except urllib.error.HTTPError as error:
    result = {"event_id": scenario, "model": model, "identity": identity or "none",
              "status": error.code, "body": json.loads(error.read(512))}
except (TimeoutError, OSError, urllib.error.URLError) as error:
    result = {"event_id": scenario, "model": model, "identity": identity or "none",
              "status": None, "failure_class": type(error).__name__}
print(json.dumps(result, sort_keys=True))
