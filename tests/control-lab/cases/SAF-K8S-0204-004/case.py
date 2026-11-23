"""Collect and verify an owned incident fixture through an authorized read path."""

from datetime import datetime, timezone
import hashlib
import json
import time

from fixtures import container, pod, ready

SCOPE = "A named fixture collector uses the Kubernetes API to copy an owned volatile file, verifies custody and observes workload continuity."
NAME = "fixture-incident-workload"
OTHER = "fixture-unrelated-workload"
COLLECTOR = "fixture-incident-collector"
STATE = "/state/owned-public.txt"
MARKER = "Fixture incident evidence only"
NAMESPACE = "saf-test"


def create_workload(lab, name):
    lab.create(pod(
        name, [container("target",
            command=["sh", "-ec", 'printf "%s\\n" "$1" > /state/owned-public.txt; exec sleep 180', "sh", MARKER],
            volumeMounts=[{"name": "state", "mountPath": "/state"}],
            securityContext={"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
            resources={"requests": {"cpu": "5m", "memory": "8Mi"}, "limits": {"cpu": "50m", "memory": "24Mi"}},
        )],
        automountServiceAccountToken=False,
        securityContext={"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                         "seccompProfile": {"type": "RuntimeDefault"}},
        volumes=[{"name": "state", "emptyDir": {}}],
    ))


def workload_state(lab, name):
    row = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    unit, = row["status"]["containerStatuses"]
    return {"uid": row["metadata"]["uid"], "node": row["spec"]["nodeName"],
            "container_id": unit["containerID"], "restart_count": unit["restartCount"]}


def collect(lab, name):
    return lab.kubectl(f"--as={COLLECTOR}", "exec", f"pod/{name}", "--", "cat", STATE, allow_failure=True)


def grant(lab):
    base = {"apiVersion": "rbac.authorization.k8s.io/v1", "metadata": {"name": COLLECTOR}}
    lab.create({**base, "kind": "Role",
                "rules": [{"apiGroups": [""], "resources": ["pods"],
                           "resourceNames": [NAME], "verbs": ["get"]},
                          {"apiGroups": [""], "resources": ["pods/exec"],
                           "resourceNames": [NAME], "verbs": ["get", "create"]}]})
    lab.create({**base, "kind": "RoleBinding",
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": COLLECTOR},
                "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": COLLECTOR}]})


def denied(result):
    return result.returncode != 0 and "forbidden" in result.stderr.lower()


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce=restricted")
    for name in (NAME, OTHER):
        create_workload(lab, name)
        ready(lab, name)
    before = workload_state(lab, NAME)
    restricted = denied(collect(lab, NAME))
    lab.check("red", "The unassigned fixture collector is forbidden from collecting owned state",
              restricted, {"unassigned_collector_denied": restricted})
    grant(lab)
    deadline = time.monotonic() + 12
    allowed = collect(lab, NAME)
    while allowed.returncode and time.monotonic() < deadline:
        time.sleep(0.4)
        allowed = collect(lab, NAME)
    outside = denied(collect(lab, OTHER))
    expected = (MARKER + "\n").encode()
    capture = allowed.stdout.encode()
    digest = hashlib.sha256(capture).hexdigest()
    verified = allowed.returncode == 0 and digest == hashlib.sha256(expected).hexdigest()
    lab.check("green", "The assigned collector verifies the exact evidence bytes and is denied on an unrelated fixture",
              verified and outside, {"exact_capture_verified": verified, "unrelated_workload_denied": outside})
    artifact = lab.evidence / "captured-public-marker.txt"
    artifact.write_bytes(capture)
    after = workload_state(lab, NAME)
    again = collect(lab, NAME)
    continuous = before == after and before["restart_count"] == 0 and again.returncode == 0 and again.stdout.encode() == capture
    lab.check("positive", "The evidence digest still matches and the workload instance remains running without a restart",
              continuous and hashlib.sha256(artifact.read_bytes()).hexdigest() == digest,
              {"same_running_container_and_marker": continuous})
    (lab.evidence / "forensic-custody-observations.json").write_text(json.dumps({
        "cluster": lab.cluster, "namespace": NAMESPACE, "collector": COLLECTOR, "object": NAME, "path": STATE,
        "method": "scoped Kubernetes exec of cat on owned public fixture", "captured_at": datetime.now(timezone.utc).isoformat(),
        "sha256": digest, "workload_identity_before": before, "workload_identity_after": after,
        "collection_scope": "owned text file and Kubernetes workload metadata",
    }, indent=2) + "\n")
