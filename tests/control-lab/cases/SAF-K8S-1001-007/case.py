"""Compare a live synthetic workload with the kind API server's audit stream."""

import json
from pathlib import Path
import re
import subprocess
import time


CASE_DIR = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
WORKLOAD_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAMESPACE = "saf-test"
FIXTURE_NAME = "telemetry-fixture"
AUDIT_ORACLE = "telemetry-api-oracle"
AUDIT_DIR = "/var/log/kubernetes/audit"
AUDIT_PATH = f"{AUDIT_DIR}/audit.log"
SCOPE = (
    "Kubernetes Metadata audit versus scoped telemetry for synthetic HTTP workloads in two pods "
    "on one local kind node. The case uses fictional model information, an inert prompt marker, "
    "and a pod-local collector. Mesh, GPU processes, central forwarding and production retention "
    "require separate evidence."
)


def prepare_kind(_lab, temporary: Path) -> Path:
    policy = (CASE_DIR / "audit-policy.yaml").resolve()
    config = temporary / "kind-config.yaml"
    config.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n  - role: control-plane\n    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n"
        "        readOnly: true\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    apiServer:\n      extraArgs:\n"
        "        - name: audit-policy-file\n"
        "          value: /etc/kubernetes/audit-policy.yaml\n"
        f"        - name: audit-log-path\n          value: {AUDIT_PATH}\n"
        "        - name: audit-log-maxage\n          value: \"1\"\n"
        "        - name: audit-log-maxbackup\n          value: \"1\"\n"
        "        - name: audit-log-maxsize\n          value: \"10\"\n"
        "      extraVolumes:\n"
        "        - name: audit-policy\n"
        "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n          pathType: File\n"
        "        - name: audit-log\n"
        f"          hostPath: {AUDIT_DIR}\n"
        f"          mountPath: {AUDIT_DIR}\n"
        "          readOnly: false\n          pathType: DirectoryOrCreate\n",
        encoding="utf-8",
    )
    return config


def run_workload(lab, phase):
    name = f"telemetry-{phase}"
    lab.create({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 10001,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "workload",
                "image": WORKLOAD_IMAGE,
                "command": ["python", "-B", "/fixture/workload.py", phase],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
            }],
            "volumes": [{"name": "fixture", "configMap": {"name": FIXTURE_NAME}}],
        },
    })
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=110s", timeout=119)
    observed = json.loads(lab.kubectl("logs", f"pod/{name}").stdout)
    event_id = observed.pop("event_id")
    if not re.fullmatch(r"saf-k8s-1001-007-[0-9a-f]{32}", event_id):
        lab.block("The workload did not return a generated event identifier")
    return event_id, observed


def read_audit(lab):
    node = f"{lab.cluster}-control-plane"
    result = subprocess.run(
        ["docker", "exec", node, "cat", AUDIT_PATH],
        env=lab.env, capture_output=True, text=True, timeout=8,
    )
    if result.returncode:
        lab.block("The owned control plane did not expose its fixture audit file")
    # Keep audit events in memory. The runner receipt includes only scoped observations.
    return result.stdout


def read_positive(lab):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        audit = read_audit(lab)
        for line in audit.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            ref = event.get("objectRef") or {}
            if (event.get("stage") == "ResponseComplete" and event.get("verb") == "get"
                    and ref.get("resource") == "configmaps" and ref.get("name") == AUDIT_ORACLE
                    and ref.get("namespace") == NAMESPACE):
                return audit, event
        time.sleep(0.2)
    lab.block("The known Kubernetes API request was absent from the audit stream")


def run(lab):
    lab.kubectl(
        "create", "configmap", FIXTURE_NAME,
        f"--from-file={CASE_DIR / 'synthetic_services.py'}",
        f"--from-file={CASE_DIR / 'workload.py'}",
    )
    red_id, red = run_workload(lab, "red")
    green_id, green = run_workload(lab, "green")

    lab.kubectl("create", "configmap", AUDIT_ORACLE, "--from-literal=fixture=telemetry")
    lab.kubectl("get", "configmap", AUDIT_ORACLE, "-o", "name")
    audit, api = read_positive(lab)
    positive = {
        "metadata_level": api.get("level") == "Metadata",
        "completed_successfully": (api.get("responseStatus") or {}).get("code") == 200,
        "request_body_absent": "requestObject" not in api,
        "response_body_absent": "responseObject" not in api,
    }
    lab.check("positive", "The successful fixture ConfigMap read appears in the real Metadata audit file",
              all(positive.values()), positive)

    red["runtime_event_absent_from_api_audit"] = red_id not in audit
    lab.check("red", "Without supplemental collection, the workload accepts a request with no collected event",
              red == {
                  "status": 200,
                  "response_matches_event": True,
                  "records": 0,
                  "runtime_event_absent_from_api_audit": True,
              }, red)

    green["runtime_event_absent_from_api_audit"] = green_id not in audit
    lab.check("green", "Supplemental collection persists one allowlisted event while API audit omits it",
              green == {
                  "status": 200,
                  "response_matches_event": True,
                  "records": 1,
                  "persisted_event_matches_allowlist": True,
                  "prompt_absent_from_record": True,
                  "runtime_event_absent_from_api_audit": True,
              }, green)
