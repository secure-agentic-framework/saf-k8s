"""Require explicit PSA mode versions on managed production-like Namespaces."""
from pathlib import Path
import json
import time

from fixtures import container, pod

SCOPE = (
    "Admission of managed production-like Namespace PSA labels and local Pod Security "
    "Admission behavior for pinned policy versions. Does not verify managed-provider "
    "upgrade behavior, exemptions, or provider control planes."
)

NAMESPACE = "saf-0301-002-production"
VERSION = "v1.36"
MODES = ("enforce", "audit", "warn")


def namespace(name, *, versions=True):
    labels = {
        "saf-k8s.example/managed-production-like": "true",
        **{f"pod-security.kubernetes.io/{mode}": "restricted" for mode in MODES},
    }
    if versions:
        labels.update({f"pod-security.kubernetes.io/{mode}-version": VERSION
                       for mode in MODES})
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": labels}}


def server_create(lab, resource):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(resource), allow_failure=True)


def benign_pod():
    return pod("saf-0301-002-benign", [container("probe")])


def violating_dry_run_pod():
    # Deliberately submitted only as a server dry-run: no noncompliant Pod is persisted.
    obj = pod("saf-0301-002-psa-dry-run", [container(
        "probe", securityContext={"runAsNonRoot": True, "runAsUser": 65534,
                                  "seccompProfile": {"type": "RuntimeDefault"}})])
    obj["metadata"]["namespace"] = NAMESPACE
    return obj


def policy_denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and "explicit Kubernetes minor version pins" in result.stderr)


def run(lab):
    case_dir = Path(__file__).parent
    missing = namespace("saf-0301-002-missing", versions=False)
    floating = namespace("saf-0301-002-latest")
    for mode in MODES:
        floating["metadata"]["labels"][f"pod-security.kubernetes.io/{mode}-version"] = "latest"
    for label, example in (("missing", missing), ("floating", floating)):
        before = server_create(lab, example)
        lab.check("red", f"The API accepts {label} pins before the namespace policy",
                  before.returncode == 0, before.stderr.strip() or "server dry-run accepted")
    lab.apply(case_dir / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        absent_result = server_create(lab, missing)
        if policy_denied(absent_result) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    latest = server_create(lab, floating)
    for label, result in (("missing", absent_result), ("floating", latest)):
        lab.check("green", f"The policy denies {label} pins on Namespace CREATE",
                  policy_denied(result), result.stderr.strip())

    # CREATE a fixture that will be mutated with server-side UPDATE dry-runs.
    lab.kubectl("create", "-f", "-", payload=json.dumps(namespace(NAMESPACE)))
    live = json.loads(lab.kubectl("get", "namespace", NAMESPACE, "-o", "json").stdout)
    variants = [(f"missing {mode} version", f"pod-security.kubernetes.io/{mode}-version", None)
                for mode in MODES]
    variants.extend((f"floating {mode} version", f"pod-security.kubernetes.io/{mode}-version", "latest")
                    for mode in MODES)
    variants.extend([
        ("unsupported future version", "pod-security.kubernetes.io/enforce-version", "v1.99"),
        ("removed governance label", "saf-k8s.example/managed-production-like", None),
    ])
    for label, key, value in variants:
        update = json.loads(json.dumps(live))
        if value is None:
            del update["metadata"]["labels"][key]
        else:
            update["metadata"]["labels"][key] = value
        result = lab.kubectl("replace", "-f", "-", "--dry-run=server", "-o", "json",
                             payload=json.dumps(update), allow_failure=True)
        lab.check("green", f"The policy denies {label} on Namespace UPDATE",
                  policy_denied(result), result.stderr.strip())

    # A persisted, pinned production-like Namespace and a compliant workload establish
    # the accepted path. The second Pod is submitted only as dry-run to observe PSA.
    valid = lab.kubectl("get", "namespace", NAMESPACE, "-o", "json").stdout
    valid_obj = json.loads(valid)
    lab.check("positive", "Managed Namespace has explicit pins for enforce, audit, and warn",
              all(valid_obj["metadata"]["labels"].get(
                  f"pod-security.kubernetes.io/{mode}-version") == VERSION for mode in MODES),
              {mode: valid_obj["metadata"]["labels"].get(
                  f"pod-security.kubernetes.io/{mode}-version") for mode in MODES})
    lab.kubectl("-n", NAMESPACE, "wait", "--for=create", "serviceaccount/default", "--timeout=20s")
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(benign_pod()))
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/saf-0301-002-benign",
                "--timeout=95s", timeout=105)
    lab.check("positive", "Pinned Restricted namespace runs a benign workload", True, "Ready")
    args = ("-n", NAMESPACE, "create", "-f", "-", "--dry-run=server", "-o", "name")
    payload = json.dumps(violating_dry_run_pod())
    rejected = lab.kubectl(*args, payload=payload, allow_failure=True)
    lab.check("green", "Pinned Restricted enforcement denies the test Pod",
              rejected.returncode != 0 and "restricted:v1.36" in rejected.stderr,
              rejected.stderr.strip())
    lab.kubectl("label", "namespace", NAMESPACE,
                "pod-security.kubernetes.io/enforce=baseline", "--overwrite")
    warning = lab.kubectl(*args, payload=payload, allow_failure=True)
    lab.check("positive", "Separately pinned Restricted warning reports the admitted Baseline probe",
              warning.returncode == 0 and "restricted:v1.36" in warning.stderr
              and "Warning: would violate PodSecurity" in warning.stderr, warning.stderr.strip())
