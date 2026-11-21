"""Namespace-scoped no-new-privileges admission and runtime reference case."""
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).parent
NAMESPACE = "saf-test"
DENIAL = (
    "allowPrivilegeEscalation must be explicitly false for every regular, init, "
    "and ephemeral container"
)
SCOPE = (
    "Namespace-scoped ValidatingAdmissionPolicy enforcement of explicit "
    "allowPrivilegeEscalation=false for regular, init, and ephemeral containers; "
    "includes a benign live Pod NoNewPrivs runtime observation. Exceptional "
    "approval workflow and policy exception behavior are out of scope and untested."
)


def probe_container(name, value_marker):
    security_context = {}
    if value_marker is not None:
        security_context["allowPrivilegeEscalation"] = value_marker
    return {
        "name": name,
        "image": container("base")["image"],
        "command": ["sh", "-c", "sleep 3600"],
        "securityContext": security_context,
    }


def probe_pod(name, *, regular=None, init=None):
    obj = pod(name, [probe_container("regular", regular)])
    if init is not None:
        obj["spec"]["initContainers"] = [probe_container("init", init)]
    obj["metadata"]["namespace"] = NAMESPACE
    return obj


def server_create(lab, obj):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(obj), allow_failure=True)


def policy_denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr)


def patch_ephemeral(lab, pod_name, *, value, dry_run):
    entry = probe_container("ephemeral-probe", value)
    patch = {"spec": {"ephemeralContainers": [entry]}}
    args = ["patch", "pod", pod_name, "--subresource=ephemeralcontainers",
            "--type=merge", "-p", json.dumps(patch)]
    if dry_run:
        args.append("--dry-run=server")
    return lab.kubectl(*args, allow_failure=True)


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/no-new-privileges=enforced", "--overwrite")

    compliant = pod(
        "saf-0302-006-runtime",
        [container("regular", command=[
            "sh", "-c", "awk '$1 == \"NoNewPrivs:\" {print $2}' /proc/self/status; sleep 3600",
        ])],
        initContainers=[container("init", command=["sh", "-c", "exit 0"])]
    )
    compliant["metadata"]["namespace"] = NAMESPACE
    lab.kubectl("create", "-f", "-", payload=json.dumps(compliant))
    ready(lab, "saf-0302-006-runtime")

    # Safe negative probes exist only as API server dry-runs. They do not persist
    # any Pod and do not execute their deliberately noncompliant settings.
    cases = [
        ("regular", probe_pod("regular-probe", regular=True)),
        ("init", probe_pod("init-probe", regular=False, init=True)),
    ]
    for label, obj in cases:
        accepted = server_create(lab, obj)
        lab.check("red", f"API accepts inert {label} probe before policy",
                  accepted.returncode == 0, accepted.stderr.strip() or "server dry-run accepted")
    ephemeral_before = patch_ephemeral(
        lab, "saf-0302-006-runtime", value=True, dry_run=True)
    lab.check("red", "API accepts inert ephemeral probe before policy",
              ephemeral_before.returncode == 0,
              ephemeral_before.stderr.strip() or "subresource server dry-run accepted")

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        results = [(label, server_create(lab, obj)) for label, obj in cases]
        if all(policy_denied(result) for _, result in results) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    for label, result in results:
        lab.check("green", f"Policy denies the {label} probe with its exact reason",
                  policy_denied(result), result.stderr.strip())

    fresh = {**compliant, "metadata": {**compliant["metadata"], "name": "post-policy-runtime"}}
    accepted = server_create(lab, fresh)
    lab.check("positive", "Compliant regular and init containers pass server admission",
              accepted.returncode == 0, accepted.stderr.strip() or "server dry-run accepted")
    lab.create(fresh)
    ready(lab, "post-policy-runtime")
    observed = lab.kubectl("exec", "post-policy-runtime", "-c", "regular", "--",
                           "sh", "-c",
                           "awk '$1 == \"NoNewPrivs:\" {print $2}' /proc/self/status").stdout.strip()
    lab.check("positive", "Live benign container reports NoNewPrivs=1",
              observed == "1", f"NoNewPrivs={observed}")

    # The ephemeralcontainers API is a subresource UPDATE. It is exercised only
    # as a server dry-run; the baseline Pod itself is compliant and persisted.
    allowed = patch_ephemeral(lab, "saf-0302-006-runtime", value=False, dry_run=True)
    lab.check("positive", "Compliant ephemeral container passes subresource dry-run",
              allowed.returncode == 0, allowed.stderr.strip() or "server dry-run accepted")
    denied = patch_ephemeral(lab, "saf-0302-006-runtime", value=True, dry_run=True)
    lab.check("green", "Policy denies inert noncompliant ephemeral subresource dry-run",
              policy_denied(denied), denied.stderr.strip())
