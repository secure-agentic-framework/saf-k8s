"""Reject unapproved mounted Secret references in the application namespace."""
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

SCOPE = (
    "Admission of Pods in the labeled disposable namespace that reference Secrets "
    "through direct Secret volumes or projected Secret sources. Only explicitly "
    "allowlisted ordinary Secret names and serviceAccountToken projections are "
    "permitted. This does not cover environment-variable Secret references, "
    "CSI/third-party delivery, already-running Pods, or other namespaces."
)
NAMESPACE = "saf-test"
DENIAL = "Pod Secret volume references must use an approved ordinary Secret"
APPROVED_SECRET = "saf-approved-ordinary-secret"
SYNTHETIC_LEGACY_SECRET = "saf-synthetic-existing-legacy-token"


def volume_pod(name, volume):
    return pod(name, [container("probe", volumeMounts=[
                    {"name": "secret-data", "mountPath": "/var/run/saf-ordinary", "readOnly": True}
               ])],
               automountServiceAccountToken=False,
               volumes=[{"name": "secret-data", **volume}])


def direct_secret(name, secret_name):
    return volume_pod(name, {"secret": {"secretName": secret_name}})


def projected_secret(name, secret_name):
    return volume_pod(name, {"projected": {"sources": [
        {"secret": {"name": secret_name}},
    ]}})


def projected_service_account_token(name):
    return volume_pod(name, {"projected": {"sources": [
        {"serviceAccountToken": {"path": "token", "expirationSeconds": 3600}},
    ]}})


def server_create(lab, resource):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(resource), allow_failure=True)


def denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr)


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/legacy-token-mount-policy=enabled")
    case_dir = Path(__file__).parent

    # A dry-run Pod uses only a synthetic name; no Secret or Pod is created.
    probes = [
        ("direct-existing-legacy-synthetic", direct_secret(
            "mount-red-direct", SYNTHETIC_LEGACY_SECRET),
         "unapproved legacy-like name is admitted as a direct Secret volume before policy"),
        ("projected-existing-legacy-synthetic", projected_secret(
            "mount-red-projected", SYNTHETIC_LEGACY_SECRET),
         "unapproved legacy-like name is admitted as a projected Secret source before policy"),
    ]
    for label, resource, claim in probes:
        before = server_create(lab, resource)
        lab.check("red", claim, before.returncode == 0,
                  "server dry-run succeeded" if before.returncode == 0 else before.stderr.strip())

    lab.apply(case_dir / "mount-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        after = [server_create(lab, resource) for _, resource, _ in probes]
        if all(denied(result) for result in after) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    for (label, _, _), result in zip(probes, after):
        lab.check("green", f"Policy rejects {label}", denied(result), result.stderr.strip())

    lab.create({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": APPROVED_SECRET},
                "type": "Opaque", "stringData": {"fixture-marker": "ordinary-volume-fixture"}})
    lab.create(direct_secret("mount-positive-ordinary", APPROVED_SECRET))
    ready(lab, "mount-positive-ordinary")
    marker = lab.kubectl("exec", "mount-positive-ordinary", "--", "cat",
                         "/var/run/saf-ordinary/fixture-marker").stdout.strip()
    lab.check("positive", "Allowlisted ordinary Secret is readable in its running Pod",
              marker == "ordinary-volume-fixture", marker)

    token = server_create(lab, projected_service_account_token("mount-positive-token"))
    lab.check("positive", "Projected serviceAccountToken passes server dry-run",
              token.returncode == 0,
              "server dry-run succeeded" if token.returncode == 0 else token.stderr.strip())
