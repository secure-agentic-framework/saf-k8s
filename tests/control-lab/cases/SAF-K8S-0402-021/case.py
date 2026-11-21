"""Check projected ServiceAccount token audience against the local API server."""
from pathlib import Path
import json
import time

from fixtures import pod, ready

SCOPE = (
    "Explicit audience admission, Kubernetes API audience verification, and "
    "a second local relying party using Kubernetes TokenReview."
)
NAMESPACE = "saf-test"
API_AUDIENCE = "https://kubernetes.default.svc.cluster.local"
FIXTURE = "saf-0402-021-fixture"
CURL_IMAGE = (
    "docker.io/curlimages/curl:8.17.0@sha256:"
    "935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40"
)
RP_AUDIENCE = "saf-external-relying-service"


def probe_pod(name, audience_marker):
    projected = {"path": "token", "expirationSeconds": 3600}
    if audience_marker is not None:
        projected["audience"] = audience_marker
    return pod(
        name,
        [{"name": "probe", "image": CURL_IMAGE, "command": ["sh", "-c", "sleep 3600"],
          "volumeMounts": [{"name": "projected-token", "mountPath": "/var/run/saf-token",
                            "readOnly": True}],
          "securityContext": {"allowPrivilegeEscalation": False,
                              "capabilities": {"drop": ["ALL"]},
                              "runAsNonRoot": True, "runAsUser": 100,
                              "seccompProfile": {"type": "RuntimeDefault"}}}],
        serviceAccountName="saf-0402-021",
        automountServiceAccountToken=False,
        volumes=[{"name": "projected-token", "projected": {"sources": [
            {"serviceAccountToken": projected},
            {"configMap": {"name": "kube-root-ca.crt",
                           "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
        ]}}],
    )


def api_probe(lab, name, expected_status, phase, expect_marker):
    script = r'''set -eu
umask 077
token_file=/var/run/saf-token/token
ca_file=/var/run/saf-token/ca.crt
config=/tmp/saf-api-curl.conf
body=/tmp/saf-api-response
trap 'rm -f "$config" "$body"' EXIT
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$token_file")" > "$config"
unset token_file
status=$(curl --silent --show-error --cacert "$ca_file" --config "$config" \
  --output "$body" --write-out '%{http_code}' "$1")
if grep -q 'saf-0402-021-api-audience-fixture' "$body"; then
  printf '%s marker-present' "$status"
else
  printf '%s marker-absent' "$status"
fi
'''
    url = f"https://kubernetes.default.svc/api/v1/namespaces/{NAMESPACE}/configmaps/{FIXTURE}"
    observed = lab.kubectl("exec", name, "--", "sh", "-c", script, "probe", url).stdout.strip()
    expected = f"{expected_status} marker-present" if expect_marker else f"{expected_status} marker-absent"
    lab.check(phase, f"TLS API request with projected token returns {expected}",
             observed == expected, observed)


def run(lab):
    case_dir = Path(__file__).parent
    lab.apply(case_dir / "resources.yaml")
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/explicit-token-audience=enabled")
    for name, audience in (("wrong-audience", "saf-external-relying-service"),
                           ("api-audience", API_AUDIENCE),
                           ("default-audience", None)):
        lab.create(probe_pod(name, audience))
        ready(lab, name)

    api_probe(lab, "wrong-audience", "401", "red", False)
    api_probe(lab, "api-audience", "200", "green", True)
    api_probe(lab, "default-audience", "200", "positive", True)

    # The 200 API probe above records the omitted-audience API default before
    # the namespace-scoped policy prevents that configuration.
    omitted = probe_pod("omitted-audience-policy-probe", None)
    lab.check("positive", "Omitted projected audience is accepted before policy",
              lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "name",
                          payload=json.dumps(omitted),
                          allow_failure=True).returncode == 0,
              "server dry-run accepted omitted audience before policy")
    # The verifier receives both synthetic tokens as projected files, creates
    # TokenReview requests in memory, and emits only authenticated/audience data.
    lab.apply(case_dir / "verifier.yaml")
    lab.create(verifier_pod())
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/relying-party-verifier",
                "--timeout=95s", timeout=105)
    own = verifier_result(lab, "rp-token")
    cluster = verifier_result(lab, "cluster-token")
    lab.check("green", "TokenReview accepts the relying party's own audience",
              own == "authenticated=true audience=saf-external-relying-service", own)
    lab.check("red", "TokenReview rejects the cluster-only audience for the relying party",
              cluster == "authenticated=false audience=", cluster)

    lab.apply(case_dir / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        denied = lab.create(omitted, dry_run=True, allow_failure=True)
        if "(Forbidden)" in denied.stderr or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    unapproved = lab.create(probe_pod("unapproved-audience-policy-probe", "unapproved"),
                            dry_run=True, allow_failure=True)
    for scenario, response in (("omitted", denied), ("unapproved", unapproved)):
        lab.check("green", f"Namespace CEL policy denies {scenario} projected-token audience",
                  response.returncode != 0 and "(Forbidden)" in response.stderr
                  and "explicit allowed audience" in response.stderr, response.stderr.strip())
    allowed = lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "name",
                          payload=json.dumps(probe_pod(
                              "explicit-audience-policy-probe", RP_AUDIENCE)),
                          allow_failure=True)
    lab.check("positive", "Namespace CEL policy permits an explicit allowed audience",
              allowed.returncode == 0, allowed.stderr.strip() or "server dry-run accepted")


def verifier_pod():
    return pod(
        "relying-party-verifier",
        [{"name": "verifier", "image": ("docker.io/library/python:3.13.2-alpine@sha256:"
                    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"),
          "command": ["python", "-c", VERIFIER_SCRIPT],
          "volumeMounts": [{"name": "tokens", "mountPath": "/var/run/saf-token", "readOnly": True},
                           {"name": "ca", "mountPath": "/var/run/saf-ca", "readOnly": True}],
          "securityContext": {"allowPrivilegeEscalation": False,
                              "capabilities": {"drop": ["ALL"]},
                              "runAsNonRoot": True, "runAsUser": 65532,
                              "seccompProfile": {"type": "RuntimeDefault"}}}],
        serviceAccountName="saf-0402-021-verifier",
        automountServiceAccountToken=False,
        volumes=[{"name": "tokens", "projected": {"sources": [
            {"serviceAccountToken": {"path": "reviewer-token", "audience": API_AUDIENCE,
                                      "expirationSeconds": 3600}},
            {"serviceAccountToken": {"path": "rp-token", "audience": RP_AUDIENCE,
                                      "expirationSeconds": 3600}},
            {"serviceAccountToken": {"path": "cluster-token", "audience": API_AUDIENCE,
                                      "expirationSeconds": 3600}}]}},
                  {"name": "ca", "configMap": {"name": "kube-root-ca.crt",
                      "items": [{"key": "ca.crt", "path": "ca.crt"}]}}],
    )


VERIFIER_SCRIPT = r'''import json, ssl, urllib.request
ctx = ssl.create_default_context(cafile="/var/run/saf-ca/ca.crt")
with open("/var/run/saf-token/reviewer-token") as f:
    reviewer = f.read().strip()
with open("/var/run/saf-token/rp-token") as f: own = f.read().strip()
with open("/var/run/saf-token/cluster-token") as f: cluster = f.read().strip()
def review(token, requested_audience="saf-external-relying-service"):
    body = json.dumps({"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
        "spec":{"token":token,"audiences":[requested_audience]}}).encode()
    req = urllib.request.Request("https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews",
        data=body, headers={"Authorization":"Bearer "+reviewer,"Content-Type":"application/json"})
    with urllib.request.urlopen(req, context=ctx) as response: result=json.load(response)
    status=result.get("status",{})
    authenticated=status.get("authenticated") is True
    audience=",".join(status.get("audiences",[])) if authenticated else ""
    print("authenticated="+str(authenticated).lower()+" audience="+audience, flush=True)
review(own)
review(cluster)
'''


def verifier_result(lab, token_name):
    # The script intentionally prints no request object or token-derived data.
    index = {"rp-token": 0, "cluster-token": 1}[token_name]
    deadline = time.monotonic() + 20
    result = []
    while time.monotonic() < deadline:
        result = lab.kubectl("logs", "relying-party-verifier").stdout.strip().splitlines()
        if len(result) > index:
            return result[index]
        time.sleep(0.25)
    return ""
