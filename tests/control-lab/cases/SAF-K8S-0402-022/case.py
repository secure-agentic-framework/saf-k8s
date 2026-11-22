"""Bound explicit projected ServiceAccount token lifetimes at Pod admission."""
import base64
import json
from pathlib import Path
import subprocess
import time

from fixtures import container, pod, ready

HERE = Path(__file__).parent
NAMESPACE = "saf-test"
TOKEN_PATH = "/var/run/saf-projected-token/token"
FLOOR_SECONDS = 600
CAP_SECONDS = 3600
DENIAL = (
    "serviceAccountToken expirationSeconds must be between 600 and 3600 inclusive"
)
SCOPE = (
    "Namespace policy for projected token requests and actual lifetimes from the "
    "configured Kubernetes issuer for Pod projections, default automount, and direct "
    "TokenRequest issuance for API and sample relying-party audiences."
)


def workload(name, expiration):
    return pod(
        name,
        [container("probe", volumeMounts=[
            {"name": "projected-token", "mountPath": "/var/run/saf-projected-token",
             "readOnly": True},
        ])],
        serviceAccountName="saf-0402-022",
        automountServiceAccountToken=False,
        volumes=[{"name": "projected-token", "projected": {"sources": [
            {"serviceAccountToken": {"path": "token", "expirationSeconds": expiration}},
        ]}}],
    )


def denied(result):
    return result.returncode != 0 and "(Forbidden)" in result.stderr and DENIAL in result.stderr


def read_claims(lab, name, token_path=TOKEN_PATH):
    # JWT bytes stay in the Pod: only the decoded integer claims leave via kubectl exec.
    script = r'''set -eu
token=$(cat "$1")
payload=${token#*.}
payload=${payload%%.*}
payload=$(printf '%s' "$payload" | tr '_-' '/+')
while [ $((${#payload} % 4)) -ne 0 ]; do payload="${payload}="; done
claims=$(printf '%s' "$payload" | base64 -d)
iat=$(printf '%s' "$claims" | sed -n 's/.*"iat":\([0-9][0-9]*\).*/\1/p')
exp=$(printf '%s' "$claims" | sed -n 's/.*"exp":\([0-9][0-9]*\).*/\1/p')
test -n "$iat" && test -n "$exp"
printf 'iat=%s exp=%s lifetime=%s\n' "$iat" "$exp" "$((exp - iat))"
'''
    result = lab.kubectl("exec", name, "--", "sh", "-c", script, "probe", token_path)
    values = dict(field.split("=", 1) for field in result.stdout.strip().split())
    return int(values["iat"]), int(values["exp"])


def request_lifetime(lab, seconds, audience=None):
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
            f"kind-{lab.cluster}", "--namespace", NAMESPACE, "--request-timeout=15s",
            "create", "token", "saf-0402-022", f"--duration={seconds}s"]
    if audience is not None:
        args.extend(["--audience", audience])
    # The subprocess returns a synthetic token; it goes straight to the claim parser.
    # The lab transcript and error messages contain only non-secret values.
    result = subprocess.run(args, env=lab.env, capture_output=True, text=True, timeout=20)
    if result.returncode:
        lab.block(f"Synthetic TokenRequest exited with status {result.returncode}")
    parts = result.stdout.strip().split(".")
    if len(parts) != 3:
        lab.block("TokenRequest did not return a JWT")
    payload = parts[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return claims["exp"] - claims["iat"], claims["aud"]


def run(lab):
    lab.apply(HERE / "resources.yaml")
    default_pod = pod("default-token-before-policy", [container("probe")],
                      serviceAccountName="saf-0402-022", automountServiceAccountToken=True)
    lab.create(default_pod)
    ready(lab, "default-token-before-policy")
    iat, exp = read_claims(lab, "default-token-before-policy",
                           "/var/run/secrets/kubernetes.io/serviceaccount/token")
    lab.check("positive", "The issuer caps an actual auto-injected token without extension",
              iat > 0 and 0 < exp - iat <= CAP_SECONDS, {"lifetime": exp - iat})

    excessive = workload("excessive-lifetime", 7200)
    before = lab.create(excessive, dry_run=True)
    observed = before["spec"]["volumes"][0]["projected"]["sources"][0][
        "serviceAccountToken"]["expirationSeconds"]
    lab.check("red", "Excessive explicit projection is admitted before policy",
              observed == 7200, f"expirationSeconds={observed}")

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        result = lab.create(excessive, dry_run=True, allow_failure=True)
        if denied(result) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "Admission denies excessive projection with the exact policy reason",
              denied(result) and DENIAL in result.stderr, result.stderr.strip())

    compliant = workload("bounded-lifetime", FLOOR_SECONDS)
    admitted = lab.create(compliant, dry_run=True)
    observed = admitted["spec"]["volumes"][0]["projected"]["sources"][0][
        "serviceAccountToken"]["expirationSeconds"]
    lab.check("positive", "Kubernetes minimum compliant projection is admitted",
              observed == FLOOR_SECONDS, f"expirationSeconds={observed}")
    lab.create(compliant)
    ready(lab, "bounded-lifetime")
    iat, exp = read_claims(lab, "bounded-lifetime")
    lifetime = exp - iat
    (lab.evidence / "token-lifetime.raw.json").write_text(json.dumps({
        "projected_pod_claims": {"iat": iat, "exp": exp, "lifetime": lifetime},
        "min_requested_seconds": FLOOR_SECONDS, "max_issued_seconds": CAP_SECONDS,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Ready Pod token JWT claims show the requested lifetime",
              iat > 0 and lifetime == FLOOR_SECONDS,
              {"iat_positive": iat > 0,
               "requested_lifetime": FLOOR_SECONDS,
               "observed_lifetime": lifetime,
               "within_configured_bounds": FLOOR_SECONDS <= lifetime <= CAP_SECONDS})

    expected = (
        (FLOOR_SECONDS, FLOOR_SECONDS, None),
        (7200, CAP_SECONDS, None),
        (7200, CAP_SECONDS, "saf-synthetic-relying-party"),
    )
    for requested, allowed, audience in expected:
        lifetime, audiences = request_lifetime(lab, requested, audience)
        aud_ok = bool(audiences) and (audience is None or audience in audiences)
        lab.check("green", f"Direct TokenRequest duration {requested} is bounded for {audience or 'the API'}",
                  lifetime == allowed and aud_ok,
                  {"requested": requested, "issued": lifetime, "audiences": audiences})
