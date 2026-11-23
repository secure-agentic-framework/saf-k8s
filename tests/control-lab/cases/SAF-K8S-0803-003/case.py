"""Evaluate inert allocation policy observations in a real Kubernetes Job."""

import json
from pathlib import Path

SCOPE = "A real Kubernetes Job reading synthetic accelerator memory-region and queue-scope policy observations."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
JOB = "fixture-rdma-scope"
CONFIG = "fixture-rdma-scope"


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    approved = {"trust": "fixture-a", "region_scope": "fixture-a", "queue_scope": "fixture-a",
                "observed_at": 10, "expires_at": 20, "allocated_count": 1,
                "approved_operations": ["read-fixture"], "observed_operations": ["read-fixture"]}
    cases = {
        "approved": approved,
        "different-trust": dict(approved, queue_scope="fixture-b"),
        "missing-scope": dict(approved, region_scope=""),
        "extra-operation": dict(approved, observed_operations=["read-fixture", "write-fixture"]),
        "expired": dict(approved, observed_at=20),
    }
    coarse = all(item["allocated_count"] <= 1 for item in cases.values())
    lab.check("red", "A resource count check alone accepts each conflicting modeled authorization record",
              coarse, {"count_only_check_accepts_every_record": coarse})
    data = {"policy-cases.json": json.dumps(cases), "verify-boundary.py": Path(__file__).with_name("verify-boundary.py").read_text()}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "immutable": True, "data": data})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                "spec": {"backoffLimit": 0, "template": {"spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}}],
                    "containers": [{"name": "compare", "image": IMAGE, "command": ["python", "/fixture/verify-boundary.py"],
                                    "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                                    "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                  "limits": {"cpu": "100m", "memory": "40Mi"}},
                                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}}}]}}}})
    lab.kubectl("wait", "--for=condition=complete", f"job/{JOB}", "--timeout=60s", timeout=70)
    observed = json.loads(lab.kubectl("logs", f"job/{JOB}").stdout)
    rejected = {name: status for name, status in observed.items() if name != "approved"}
    expected = {"different-trust": "wrong-trust-boundary", "missing-scope": "incomplete",
                "extra-operation": "unapproved-permission", "expired": "stale"}
    lab.check("green", "The actual policy Job distinguishes scope, permission, freshness and completeness",
              rejected == expected, rejected)
    lab.check("positive", "The matching reviewed record remains eligible at the fixture policy layer",
              observed["approved"] == "consistent-fixture", {"approved": observed["approved"]})
    (lab.evidence / "rdma-policy-observations.json").write_text(json.dumps({
        "count_only_check_accepts_every_record": coarse, "job_results": observed,
        "hardware_and_remote_memory_access_tested": False}, indent=2) + "\n")
