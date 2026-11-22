"""Exercise workspace isolation and bounded Kubernetes workspace identities."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path


CONTROL_ID = "SAF-K8S-0904-003"
IMAGE = "quay.io/jupyter/base-notebook:2025-04-01@sha256:18691156c62dd82b69951329ee000fa0ca76f1bea6c105ac92c5754a8d92b828"
NAMESPACE = "saf-test"
SCOPE = (
    "One fresh Kind v1.36.1 cluster, two pinned upstream Jupyter base-notebook Pods, and two "
    "case-owned benign dataset endpoints. The notebook Pods have distinct non-root UIDs and "
    "tokenless service accounts, configured CPU/RAM bounds and restrictive security contexts. "
    "Native NetworkPolicy limits each to its labeled endpoint, and native admission enforces "
    "the approved image reference. Each real Jupyter kernel executes a fixed harmless cell "
    "after policy is active. Kernel exposure, optional extensions, JupyterHub authentication, "
    "full provenance and dataset policy, and deployed controls require separate evidence."
)

ROOT = Path(__file__).resolve().parent


def pod_json(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)


def wait_ready(lab, name, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pod = pod_json(lab, name)
        if pod.get("status", {}).get("phase") == "Running" and any(
            condition.get("type") == "Ready" and condition.get("status") == "True"
            for condition in pod.get("status", {}).get("conditions", [])
        ):
            return pod
        time.sleep(1)
    lab.block(f"Fixture Pod did not become Ready: {name}")


def probe(lab, source, destination):
    address = pod_json(lab, destination)["status"]["podIP"]
    script = """
import http.client
import sys
connection = http.client.HTTPConnection(sys.argv[1], port=8080, timeout=1.5)
try:
    connection.request("GET", "/")
    response = connection.getresponse()
    if response.status != 200:
        raise RuntimeError("unexpected response from the owned fixture")
    print("ALLOW:" + response.read().decode())
except TimeoutError:
    print("BLOCKED")
finally:
    connection.close()
"""
    result = lab.kubectl("exec", source, "--", "/opt/conda/bin/python", "-B",
                         "-c", script, address, timeout=8)
    value = result.stdout.strip()
    if value != "BLOCKED" and not value.startswith("ALLOW:"):
        lab.block(f"Unexpected fixture observation from {source}")
    return value


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf.example/image-policy=enabled", "--overwrite")
    lab.apply(ROOT / "case" / "workspaces.yaml")
    pods = {}
    for name in ("dataset-alice", "dataset-bob", "workspace-alice", "workspace-bob"):
        pods[name] = wait_ready(lab, name)

    lab.check(
        "positive", "workspace pods have separate non-token service accounts and bounded hardened containers",
        pods["workspace-alice"]["spec"].get("serviceAccountName") == "workspace-alice"
        and pods["workspace-bob"]["spec"].get("serviceAccountName") == "workspace-bob"
        and pods["workspace-alice"]["spec"].get("automountServiceAccountToken") is False
        and pods["workspace-bob"]["spec"].get("automountServiceAccountToken") is False
        and all(_hardened(pods[name]) for name in ("workspace-alice", "workspace-bob")),
        "distinct service accounts; token automount disabled; non-root, seccomp, no escalation, dropped capabilities, read-only root, bounded CPU/memory",
    )

    red_alice = probe(lab, "workspace-alice", "dataset-bob")
    red_bob = probe(lab, "workspace-bob", "dataset-alice")
    if red_alice != "ALLOW:benign-dataset-bob" or red_bob != "ALLOW:benign-dataset-alice":
        lab.block("Baseline cross-workspace probe did not reach the benign endpoint; NetworkPolicy enforcement is not established")
    lab.check("red", "without workspace egress policies, cross-workspace dataset paths are reachable",
              red_alice == "ALLOW:benign-dataset-bob" and red_bob == "ALLOW:benign-dataset-alice",
              "alice-to-bob=ALLOW; bob-to-alice=ALLOW")

    lab.apply(ROOT / "case" / "workspace-egress.yaml")
    expected = {"alice-to-alice": "ALLOW:benign-dataset-alice", "alice-to-bob": "BLOCKED",
                "bob-to-bob": "ALLOW:benign-dataset-bob", "bob-to-alice": "BLOCKED"}
    deadline = time.monotonic() + 35
    observed = {}
    streak = 0
    while time.monotonic() < deadline:
        observed = {f"{source}-to-{destination}": probe(
            lab, f"workspace-{source}", f"dataset-{destination}")
            for source, destination in (("alice", "alice"), ("alice", "bob"), ("bob", "bob"), ("bob", "alice"))}
        streak = streak + 1 if observed == expected else 0
        if streak == 2:
            break
    lab.check("green", "Each workspace reaches its own dataset while both cross-workspace paths remain blocked",
              streak == 2, {**observed, "consecutive_matches": streak})

    unapproved = _dry_run_pod("admission-unapproved", "quay.io/jupyter/base-notebook:2025-04-01")
    baseline = lab.create(unapproved, dry_run=True, allow_failure=True)
    if baseline.returncode:
        lab.block(f"The unapproved-image baseline did not reach Pod admission: {baseline.stderr}")
    lab.check("red", "Without the image binding the same unpinned fixture image is admitted by server dry-run",
              baseline.returncode == 0, {"server_dry_run_admitted": True})
    lab.apply(ROOT / "case" / "image-admission.yaml")
    end = time.monotonic() + 15
    message = "workspace Pod image must match the approved digest-pinned base image"
    while True:
        denied = lab.create(unapproved, dry_run=True, allow_failure=True)
        if denied.returncode or time.monotonic() >= end:
            break
        time.sleep(0.25)
    if denied.returncode and message not in denied.stderr:
        lab.block(f"Image approval probe was rejected by an unrelated response: {denied.stderr}")
    lab.check("green", "The native image policy rejects the same unpinned reference",
              denied.returncode != 0 and message in denied.stderr,
              {"denied_by_policy": denied.returncode != 0, "policy": "saf-notebook-approved-image"})
    accepted = lab.create(_dry_run_pod("admission-approved", IMAGE), dry_run=True, allow_failure=True)
    if accepted.returncode:
        lab.block(f"The pinned positive-control image was not admitted: {accepted.stderr}")
    lab.check("positive", "The exact approved notebook image remains admissible",
              accepted.returncode == 0, {"approved_reference": IMAGE, "admitted": True})

    kernel_script = (ROOT / "notebook-kernel.py").read_text()
    summaries = {}
    for user, uid in (("alice", 1000), ("bob", 1001)):
        result = lab.kubectl("exec", "-i", f"workspace-{user}", "--", "/opt/conda/bin/python", "-B", "-",
                             payload=kernel_script, timeout=55)
        summaries[user] = json.loads(result.stdout)
        spec = pod_json(lab, f"workspace-{user}")["spec"]
        lab.check("positive", f"The {user} workspace executes a fixed cell through its installed Jupyter kernel",
                  summaries[user] == {"uid": uid, "stdout": "fixture-notebook-ok\n", "kernel": "python3"}
                  and spec["containers"][0]["image"] == IMAGE, summaries[user])
    (lab.evidence / "workspace-isolation.raw.json").write_text(json.dumps(
        {"pods": pods, "dataset_access": observed, "kernels": summaries}, indent=2) + "\n")


def _hardened(pod):
    spec = pod["spec"]
    pod_security = spec.get("securityContext", {})
    if not pod_security.get("runAsNonRoot") or pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault":
        return False
    containers = spec.get("containers", [])
    if len(containers) != 1:
        return False
    container = containers[0]
    security = container.get("securityContext", {})
    resources = container.get("resources", {})
    return (
        security.get("allowPrivilegeEscalation") is False
        and security.get("readOnlyRootFilesystem") is True
        and "ALL" in security.get("capabilities", {}).get("drop", [])
        and bool(resources.get("requests", {}).get("cpu"))
        and bool(resources.get("requests", {}).get("memory"))
        and bool(resources.get("limits", {}).get("cpu"))
        and bool(resources.get("limits", {}).get("memory"))
    )


def _dry_run_pod(name, image):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf.example/workspace": "true"}},
        "spec": {"containers": [{"name": "workspace", "image": image,
                                  "command": ["python", "-c", "pass"]}]},
    }
