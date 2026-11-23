"""Observe API and repository audit as two distinct recording boundaries."""

from datetime import datetime
import json
from pathlib import Path
import time

SCOPE = "Metadata audit on the Kubernetes API plus separate fixture repository logs with Linux peer identity."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NS = "saf-test"
POD = "fixture-backup-audit"
TARGET = "fixture-backup-marker"
ALLOWED = "fixture-backup-approved"
DENIED = "fixture-backup-ordinary"
LOG = "/var/log/kubernetes/saf-backup-audit.log"
RBAC = "rbac.authorization.k8s.io"
CLIENT = """
import socket
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.connect('/repo/read.sock')
    connection.sendall(b'read')
    print(connection.recv(128).decode())
"""


def prepare_kind(_lab, temporary):
    path = temporary / "backup-audit-policy.json"
    path.write_text(json.dumps({
        "apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "Metadata", "verbs": ["get"], "namespaces": [NS],
                   "resources": [{"group": "", "resources": ["configmaps"], "resourceNames": [TARGET]}]},
                  {"level": "None"}],
    }))
    config = temporary / "kind-backup-audit.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(path))}
        containerPath: /etc/kubernetes/saf-backup-audit-policy.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-backup-audit-policy.json
        - name: audit-log-path
          value: {LOG}
      extraVolumes:
        - name: saf-backup-audit-policy
          hostPath: /etc/kubernetes/saf-backup-audit-policy.json
          mountPath: /etc/kubernetes/saf-backup-audit-policy.json
          readOnly: true
          pathType: File
        - name: saf-backup-audit-log
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
""")
    return config


def unit(name, uid, command):
    return {"name": name, "image": IMAGE, "command": command,
            "volumeMounts": [{"name": "repository", "mountPath": "/repo"},
                             {"name": "configuration", "mountPath": "/configuration", "readOnly": True}],
            "securityContext": {"runAsUser": uid, "runAsGroup": uid, "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "48Mi"}}}


def prepare_repo(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": POD},
                "data": {"repository.py": Path(__file__).with_name("repository.py").read_text()}})
    repo = unit("repository", 1001, ["python", "-B", "/configuration/repository.py"])
    repo["readinessProbe"] = {"exec": {"command": ["test", "-S", "/repo/read.sock"]}, "periodSeconds": 1}
    clients = [unit(name, uid, ["python", "-c", "import time; time.sleep(180)"])
               for name, uid in (("restore", 1002), ("ordinary", 1003))]
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [repo, *clients], "volumes": [{"name": "repository", "emptyDir": {}},
                                                  {"name": "configuration", "configMap": {"name": POD}}],
    }})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + POD, "--timeout=75s", timeout=85)


def api_audit(lab):
    result = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat", LOG, allow_failure=True)
    if result.returncode:
        return []
    found = []
    for line in result.stdout.splitlines():
        event = json.loads(line)
        resource = event.get("objectRef", {})
        if (resource.get("namespace") != NS or resource.get("name") != TARGET
                or event.get("verb") != "get" or event.get("stage") != "ResponseComplete"):
            continue
        found.append({"user": (event.get("impersonatedUser") or event["user"])["username"],
                      "status": event["responseStatus"]["code"], "at": event["stageTimestamp"],
                      "id": event["auditID"], "metadata_only": event["level"] == "Metadata"
                          and "requestObject" not in event and "responseObject" not in event})
    return found


def run(lab):
    lab.kubectl("label", "namespace", NS, "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": TARGET},
                "data": {"marker": "local API fixture"}})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": POD},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [TARGET], "verbs": ["get"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": POD},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": POD},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": ALLOWED}]})
    prepare_repo(lab)
    replies = {role: lab.kubectl("exec", "pod/" + POD, "-c", role, "--", "python", "-c", CLIENT).stdout.strip()
               for role in ("restore", "ordinary")}
    audit_empty = not api_audit(lab)
    lab.check("red", "Socket repository reads produce real outcomes without a matching API read audit event",
              replies == {"restore": "public backup fixture", "ordinary": "denied"} and audit_empty,
              {"repository_read_permitted": replies["restore"] == "public backup fixture",
               "repository_read_denied": replies["ordinary"] == "denied", "api_read_events_before_api_calls": 0})

    granted = lab.kubectl("--as", ALLOWED, "get", "configmap", TARGET, "-o", "json")
    denied = lab.kubectl("--as", DENIED, "get", "configmap", TARGET, allow_failure=True)
    deadline = time.monotonic() + 20
    expected = {(ALLOWED, 200), (DENIED, 403)}
    api_rows = []
    while time.monotonic() < deadline:
        api_rows = api_audit(lab)
        if {(row["user"], row["status"]) for row in api_rows} == expected:
            break
        time.sleep(0.4)
    metadata_only = (len({row["id"] for row in api_rows}) == 2 and all(
        row["metadata_only"] and datetime.fromisoformat(row["at"].replace("Z", "+00:00")).tzinfo for row in api_rows))
    lab.check("green", "The API audit records the permitted and denied marker reads by subject without bodies",
              json.loads(granted.stdout)["data"]["marker"] == "local API fixture" and denied.returncode != 0
              and {(row["user"], row["status"]) for row in api_rows} == expected and metadata_only,
              {"expected_api_outcomes": sorted(expected), "metadata_only_events": metadata_only})

    raw = lab.kubectl("logs", "pod/" + POD, "-c", "repository").stdout
    repository_rows = [json.loads(line) for line in raw.splitlines()]
    repository_matches = {(row["peer_uid"], row["outcome"]) for row in repository_rows}
    complete = len(repository_rows) == 2 and all(
        row["source"] == "repository" and row["operation"] == "read" and row["target"] == TARGET
        and datetime.fromisoformat(row["time"]).tzinfo for row in repository_rows)
    lab.check("positive", "Independent repository logs retain peer identity, operation, target, time, and outcome",
              complete and repository_matches == {(1002, "allowed"), (1003, "denied")},
              {"repository_outcomes": sorted(repository_matches), "repository_fields_complete": complete})
    (lab.evidence / "backup-access-audit-observations.json").write_text(json.dumps({
        "api": api_rows, "repository": repository_rows, "real_backup_data_used": False,
    }, indent=2) + "\n")
