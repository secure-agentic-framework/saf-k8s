"""Exercise separation of an unverified shared pool from a second trust namespace."""

import json
import time

SCOPE = "Real ResourceQuota and scheduling for synthetic shared and alternative accelerator keys."
SHARED = "fixture.example/shared-trust-a"
ALTERNATE = "fixture.example/dedicated-trust-b"
PRIMARY = "saf-test"
SECONDARY = "saf-other-trust"
QUOTA = "fixture-allocation-boundary"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def insert(lab, namespace, resource, *, dry_run=False, allow_failure=False):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("--namespace", namespace, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(resource), allow_failure=allow_failure)


def workload(name, resource):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "fixture", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(140)"],
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                   "limits": {resource: "1", "cpu": "100m", "memory": "40Mi"}}}]}}


def limit(lab, ns, allowed, denied):
    hard = {f"requests.{allowed}": "1", f"requests.{denied}": "0"}
    insert(lab, ns, {"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": QUOTA}, "spec": {"hard": hard}})
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        actual = json.loads(lab.kubectl("--namespace", ns, "get", "resourcequota", QUOTA, "-o", "json").stdout)
        if actual.get("status", {}).get("hard") == hard:
            return
        time.sleep(0.5)
    lab.block("The namespace quota controller did not report the configured limits")


def blocked(lab, ns, pod):
    reply = insert(lab, ns, pod, dry_run=True, allow_failure=True)
    return reply.returncode != 0 and "exceeded quota" in reply.stderr and QUOTA in reply.stderr


def run(lab):
    lab.kubectl("create", "namespace", SECONDARY)
    for ns in (PRIMARY, SECONDARY):
        lab.kubectl("label", "namespace", ns, "pod-security.kubernetes.io/enforce=restricted")
    other = workload("unapproved-shared-allocation", SHARED)
    baseline = insert(lab, SECONDARY, other, dry_run=True, allow_failure=True).returncode == 0
    lab.check("red", "Before the boundary, admission accepts the shared resource in the second trust namespace",
              baseline, {"cross_trust_request_initially_admitted": baseline})

    limit(lab, PRIMARY, SHARED, ALTERNATE)
    limit(lab, SECONDARY, ALTERNATE, SHARED)
    secondary_denied = blocked(lab, SECONDARY, other)
    primary_denied = blocked(lab, PRIMARY, workload("unapproved-alternative", ALTERNATE))
    lab.check("green", "The two namespace quotas deny each resource outside its assigned policy boundary",
              secondary_denied and primary_denied, {"cross_trust_shared_request_denied": secondary_denied,
                                                     "other_namespace_alternate_request_denied": primary_denied})

    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    node_name = node["metadata"]["name"]
    update = [{"op": "add", "path": f"/status/capacity/{key.replace('/', '~1')}", "value": "1"} for key in (SHARED, ALTERNATE)]
    lab.kubectl("patch", "node", node_name, "--subresource=status", "--type=json", "-p", json.dumps(update))
    approved = {}
    for ns, key in ((PRIMARY, SHARED), (SECONDARY, ALTERNATE)):
        name = "approved-resource-fixture"
        insert(lab, ns, workload(name, key))
        lab.kubectl("--namespace", ns, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=65s", timeout=75)
        actual = json.loads(lab.kubectl("--namespace", ns, "get", "pod", name, "-o", "json").stdout)
        approved[ns] = actual["spec"]["containers"][0]["resources"]["requests"].get(key) == "1"
    lab.check("positive", "Each namespace still runs a fixture using only its own approved synthetic resource",
              all(approved.values()), {"approved_resources_running_by_namespace": approved})
    (lab.evidence / "sharing-boundary-observations.json").write_text(json.dumps(
        {"initially_admitted": baseline, "cross_trust_shared_request_denied": secondary_denied,
         "other_namespace_alternate_request_denied": primary_denied, "approved_resources_running_by_namespace": approved,
         "physical_isolation_or_reset_tested": False}, indent=2) + "\n")
