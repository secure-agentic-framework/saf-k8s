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
    "green-wrong-model": ("model-beta", "synthetic-client-a"),
    "positive-alpha": ("model-alpha", "synthetic-client-a"),
    "positive-beta": ("model-beta", "synthetic-client-b"),
}


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def issue_fixed_token(identity, lifetime_seconds):
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"iss": "saf-0902-008-local-issuer", "aud": "saf-0902-008-fixture",
              "sub": identity, "models": POLICY["identities"][identity],
              "exp": int(time.time()) + lifetime_seconds}
    payload = b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    signature = hmac.new(KEY, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{b64(signature)}"


if len(sys.argv) != 3 or sys.argv[1] not in SCENARIOS:
    print(json.dumps({"result": "invalid-fixed-scenario"}))
    raise SystemExit(64)
scenario, base_url = sys.argv[1], sys.argv[2].rstrip("/")
model, identity = SCENARIOS[scenario]
headers = {"X-Fixture-Event-ID": scenario}
if identity:
    headers["Authorization"] = "Bearer " + issue_fixed_token(identity, -60 if scenario == "green-expired" else 120)
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
