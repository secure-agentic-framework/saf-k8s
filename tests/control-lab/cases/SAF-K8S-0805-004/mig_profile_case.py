"""Prove the admission response used by the physical MIG runner on Kind."""

from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import time

spec = spec_from_file_location("saf_mig_admission", Path(__file__).with_name("mig_admission.py"))
admission = module_from_spec(spec)
spec.loader.exec_module(admission)
NS = "saf-mig-profile-fixture"
POLICY = "saf-mig-profile-proof"
RUN = "kind-profile-check"
POD = "saf-profile-witness"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def submit(lab, resource, *, scope=RUN):
    limits = {resource: "1"}
    value = {"apiVersion": "v1", "kind": "Pod",
             "metadata": {"name": POD, "labels": {admission.RUN_LABEL: scope}},
             "spec": {"restartPolicy": "Never", "runtimeClassName": "nvidia",
                      "automountServiceAccountToken": False,
                      "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                           "seccompProfile": {"type": "RuntimeDefault"}},
                      "containers": [{"name": "fixture", "image": IMAGE, "resources": {"limits": limits},
                                      "securityContext": {"allowPrivilegeEscalation": False,
                                                          "capabilities": {"drop": ["ALL"]}}}]}}
    return lab.kubectl("-n", NS, "create", "-f", "-", "-o", "json", "--dry-run=server",
                       payload=json.dumps(value), allow_failure=True)


def run(lab):
    lab.create({"apiVersion": "v1", "kind": "Namespace",
                "metadata": {"name": NS, "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}})
    lab.create({"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
                "metadata": {"name": "nvidia"}, "handler": "runc"})
    whole_gpu = "nvidia.com/gpu"
    before = submit(lab, whole_gpu).returncode == 0
    for obj in admission.objects(NS, POLICY, RUN):
        lab.create(obj)
    deadline = time.monotonic() + 20
    denied = False
    while time.monotonic() < deadline:
        result = submit(lab, whole_gpu)
        denied = admission.exact_denial(result, POD, POLICY)
        if result.returncode:
            if not denied:
                lab.block("The API probe failed without the named Forbidden decision: " + result.stderr)
            break
        time.sleep(0.5)
    approved = submit(lab, admission.RESOURCE).returncode == 0
    unmarked = submit(lab, whole_gpu, scope="outside-proof").returncode == 0
    absent = not lab.kubectl("-n", NS, "get", "pod", POD, "--ignore-not-found", "-o", "name").stdout.strip()
    observed = {"whole_gpu_dry_run_passed_before_policy": before, "exact_foreign_resource_denial": denied,
                "approved_mig_profile_accepted_as_dry_run": approved, "unmarked_fixture_accepted_as_dry_run": unmarked,
                "all_probe_workloads_absent": absent}
    (lab.evidence / "mig-profile-admission.json").write_text(json.dumps({
        "schema": "saf-mig-profile-admission-kind-v1", "scope": "Kubernetes admission dry-runs using fixture resource names",
        "observed": observed}, sort_keys=True, indent=2) + "\n")
    lab.check("mig-profile-admission", "The exact whole-GPU request is denied by the bound MIG fixture policy while the approved and unmarked dry-runs pass",
              all(observed.values()), observed)
