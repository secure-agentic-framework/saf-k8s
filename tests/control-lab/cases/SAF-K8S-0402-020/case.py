"""Deny legacy ServiceAccount token Secret issuance in the application namespace."""
import importlib.util
import json
from pathlib import Path
import time

from fixtures import pod, ready

SCOPE = (
    "Legacy service account Secret admission and direct or projected Secret-volume "
    "references in a disposable namespace. Existing running workloads, external "
    "Secret delivery, and identity providers are outside the fixture."
)
NAMESPACE = "saf-test"
TOKEN_TYPE = "kubernetes.io/service-account-token"
DENIAL = "legacy service account token Secrets are prohibited"
FIXTURE = "saf-0402-020-fixture"
CURL_IMAGE = (
    "docker.io/curlimages/curl:8.17.0@sha256:"
    "935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40"
)


def secret(name, secret_type, data=None):
    return {"apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": name}, "type": secret_type,
            "data": data or {}}


def denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr)


def server_create(lab, resource):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(resource), allow_failure=True)



def projected_pod():
    return pod(
        "projected-token-access",
        [{"name": "probe", "image": CURL_IMAGE,
          "command": ["sh", "-c", "sleep 3600"],
          "volumeMounts": [{"name": "projected-token", "mountPath": "/var/run/saf-token",
                            "readOnly": True}],
          "securityContext": {"allowPrivilegeEscalation": False,
                              "capabilities": {"drop": ["ALL"]},
                              "runAsNonRoot": True, "runAsUser": 100,
                              "seccompProfile": {"type": "RuntimeDefault"}}}],
        serviceAccountName="saf-0402-020",
        automountServiceAccountToken=False,
        volumes=[{"name": "projected-token", "projected": {"sources": [
            {"serviceAccountToken": {"path": "token", "audience":
             "https://kubernetes.default.svc.cluster.local", "expirationSeconds": 3600}},
            {"configMap": {"name": "kube-root-ca.crt",
                           "items": [{"key": "ca.crt", "path": "ca.crt"}]}}
        ]}}],
    )


def verify_projected_access(lab):
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
if grep -q 'saf-0402-020-authorized-fixture' "$body"; then
  printf '%s marker-present' "$status"
else
  printf '%s marker-absent' "$status"
fi
'''
    url = (f"https://kubernetes.default.svc/api/v1/namespaces/{NAMESPACE}/"
           f"configmaps/{FIXTURE}")
    return lab.kubectl("exec", "projected-token-access", "--", "sh", "-c",
                       script, "probe", url).stdout.strip()


def run(lab):
    # Label the disposable namespace to make policy attachment explicit.
    lab.kubectl("label", "namespace", NAMESPACE, "saf-k8s.example/legacy-token-policy=enabled")

    # The dry-run never persists a legacy token Secret or triggers token issuance.
    probe = secret("legacy-token-create-probe", TOKEN_TYPE)
    probe["metadata"]["annotations"] = {
        "kubernetes.io/service-account.name": "synthetic-unbound-service-account",
    }
    before = server_create(lab, probe)
    lab.check("red", "Legacy token Secret create is allowed before the policy",
              before.returncode == 0, before.stderr.strip() or "server dry-run succeeded")

    case_dir = Path(__file__).parent
    lab.apply(case_dir / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        after = server_create(lab, probe)
        if denied(after) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "Policy rejects legacy token Secret creation",
              denied(after), after.stderr.strip())

    opaque = server_create(lab, secret("ordinary-opaque-probe", "Opaque", {"note": "c2FmZQ=="}))
    lab.check("positive", "Ordinary Opaque Secret server dry-run succeeds",
              opaque.returncode == 0, "server dry-run succeeded" if opaque.returncode == 0
              else opaque.stderr.strip())

    lab.apply(case_dir / "resources.yaml")
    lab.create(projected_pod())
    ready(lab, "projected-token-access")
    observed = verify_projected_access(lab)
    lab.check("positive", "Projected token authenticates to read its authorized synthetic fixture",
              observed == "200 marker-present", observed)

    mounts = Path(__file__).with_name("mount_case.py")
    spec = importlib.util.spec_from_file_location("legacy_mount_probes", mounts)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run(lab)
