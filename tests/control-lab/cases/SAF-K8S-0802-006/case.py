"""Verify policy and audit evidence for a device directory mount declaration."""

import json
import time

SCOPE = "Dry-run hostPath decisions and metadata-only Kubernetes auditing, with no device directory access."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
DIRECTORY = "/var/lib/kubelet/device-plugins"
LOG = "/var/log/kubernetes/saf-device-mount-audit.log"


def prepare_kind(_lab, temporary):
    policy = temporary / "device-mount-policy.json"
    policy.write_text(json.dumps({"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "Metadata", "verbs": ["create"], "namespaces": ["saf-test"],
                   "resources": [{"group": "", "resources": ["pods"]}]}, {"level": "None"}]}))
    config = temporary / "kind-device-mount.yaml"
    config.write_text(f'''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-device-mount-policy.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-device-mount-policy.json
        - name: audit-log-path
          value: {LOG}
      extraVolumes:
        - name: saf-fixture-policy
          hostPath: /etc/kubernetes/saf-device-mount-policy.json
          mountPath: /etc/kubernetes/saf-device-mount-policy.json
          readOnly: true
          pathType: File
        - name: saf-fixture-audit
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
''')
    return config
def pod(name, path=None):
    container = {"name": "fixture", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(120)"],
                 "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "40Mi"}},
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}
    spec = {"restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container]}
    if path:
        spec["volumes"] = [{"name": "fixture-declaration", "hostPath": {"path": path}}]
        container["volumeMounts"] = [{"name": "fixture-declaration", "mountPath": "/owned-fixture", "readOnly": True}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}


def blocked(response):
    return response.returncode != 0 and "violates PodSecurity" in response.stderr and "hostPath" in response.stderr


def audit_denials(lab):
    result = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat", LOG, allow_failure=True)
    if result.returncode:
        return []
    found = []
    for line in result.stdout.splitlines():
        event = json.loads(line)
        ref, status = event.get("objectRef", {}), event.get("responseStatus", {})
        if (event.get("level") == "Metadata" and event.get("stage") == "ResponseComplete"
                and event.get("verb") == "create" and ref.get("namespace") == "saf-test"
                and ref.get("resource") == "pods" and "dryRun=All" in event.get("requestURI", "")
                and status.get("code") == 403 and "hostPath" in status.get("message", "")
                and "requestObject" not in event and "responseObject" not in event):
            found.append(event["auditID"])
    return sorted(set(found))


def run(lab):
    declaration = pod("fixture-device-dir", DIRECTORY)
    before = lab.create(declaration, dry_run=True, allow_failure=True).returncode == 0
    lab.check("red", "The dry-run declaration is accepted before hostPath admission enforcement",
              before, {"declaration_initially_admitted": before})
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    directory_denied = blocked(lab.create(declaration, dry_run=True, allow_failure=True))
    child_denied = blocked(lab.create(pod("fixture-device-child", f"{DIRECTORY}/saf-inert-marker"), dry_run=True, allow_failure=True))
    lab.check("green", "Pod Security Admission denies both dry-run hostPath declarations",
              directory_denied and child_denied, {"directory_declaration_denied": directory_denied,
                                                 "child_declaration_denied": child_denied})
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        events = audit_denials(lab)
        if len(events) == 2:
            break
        time.sleep(0.4)
    else:
        lab.block("Two distinct scoped metadata-only denial records were not observed")
    name = "fixture-without-host-path"
    lab.create(pod(name))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=55s", timeout=65)
    lab.check("positive", "The API audit backend records both decisions and the ordinary workload stays available",
              len(events) == 2, {"metadata_denial_events": len(events), "ordinary_workload_ready": True})
    (lab.evidence / "device-directory-observations.json").write_text(json.dumps({
        "directory_declaration_denied": directory_denied, "child_declaration_denied": child_denied,
        "metadata_dry_run_denial_event_ids": events, "ordinary_workload_ready": True,
        "device_path_operations_performed": False}, indent=2) + "\n")
