"""Exercise automated synthetic audit forwarding and receiver restart retention."""
import json
from pathlib import Path
import time


HERE = Path(__file__).parent
NAMESPACE = "saf-test"
IMAGE = (
    "docker.io/library/python:3.13-slim@"
    "sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
EVENT = {
    "kind": "SyntheticNodeAuditEvent",
    "schema": "saf-k8s-lab/v1",
    "auditID": "saf-synthetic-016-001",
    "node": "kind-control-plane",
    "event": "synthetic-kubelet-config-read",
    "path": "/synthetic/fixture/kubelet.conf",
    "result": "success",
}
SCOPE = (
    "One disposable kind cluster runs a nonroot Python forwarder with one inert synthetic event "
    "and a private ClusterIP fixture receiver backed by a disposable PVC. Observes an HTTP 503, "
    "automatic retry and delivery after receiver recovery, then restarts the receiver and queries "
    "the sink for the retained event. Does not generate Linux Audit events, configure host auditd "
    "or node agents, prove production retention/review/alerting, or cover a fleet."
)


def _meta(name, labels=None):
    metadata = {"name": name, "namespace": NAMESPACE}
    if labels:
        metadata["labels"] = labels
    return metadata


def _pod_security():
    return {
        "serviceAccountName": "default",
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "runAsGroup": 10001,
            "fsGroup": 10001,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def _container_security():
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }


def _container(name, command, mounts, ports=None):
    result = {
        "name": name,
        "image": IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": command,
        "volumeMounts": mounts,
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": _container_security(),
    }
    if ports:
        result["ports"] = ports
    return result


def _receiver_deployment():
    pod = _pod_security()
    pod.update({
        "containers": [_container(
            "receiver", ["python", "-u", "/app/receiver.py"],
            [{"name": "app", "mountPath": "/app", "readOnly": True},
             {"name": "sink", "mountPath": "/data"}],
            [{"containerPort": 8080, "name": "http"}],
        )],
        "volumes": [
            {"name": "app", "configMap": {"name": "audit-forwarding-app",
                                               "items": [{"key": "receiver.py", "path": "receiver.py"}]}},
            {"name": "sink", "persistentVolumeClaim": {"claimName": "audit-sink"}},
        ],
    })
    pod["containers"][0]["readinessProbe"] = {
        "httpGet": {"path": "/health", "port": "http"}, "periodSeconds": 1
    }
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": _meta("audit-receiver"),
        "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {"app": "audit-receiver"}},
                 "template": {"metadata": {"labels": {"app": "audit-receiver"}}, "spec": pod}},
    }


def _forwarder_pod():
    pod = _pod_security()
    pod.update({
        "restartPolicy": "Never",
        "containers": [_container(
            "forwarder", ["python", "-u", "/app/forwarder.py"],
            [{"name": "app", "mountPath": "/app", "readOnly": True},
             {"name": "event", "mountPath": "/input", "readOnly": True},
             {"name": "spool", "mountPath": "/spool"}],
        )],
        "volumes": [
            {"name": "app", "configMap": {"name": "audit-forwarding-app",
                                               "items": [{"key": "forwarder.py", "path": "forwarder.py"}]}},
            {"name": "event", "configMap": {"name": "audit-forwarding-app",
                                                 "items": [{"key": "event.json", "path": "event.json"}]}},
            {"name": "spool", "emptyDir": {}},
        ],
    })
    return {"apiVersion": "v1", "kind": "Pod", "metadata": _meta("audit-forwarder"), "spec": pod}


def _wait_for_log(lab, needle, timeout=45):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = lab.kubectl("logs", "pod/audit-forwarder", allow_failure=True)
        if needle in result.stdout:
            return result.stdout
        time.sleep(0.5)
    return lab.kubectl("logs", "pod/audit-forwarder", allow_failure=True).stdout


def _sink_query(lab):
    query = (
        "import urllib.request; "
        "print(urllib.request.urlopen("
        "'http://audit-receiver.saf-test.svc:8080/events?auditID=saf-synthetic-016-001', "
        "timeout=5).read().decode())"
    )
    return lab.kubectl("exec", "pod/audit-forwarder", "--", "python", "-c", query, timeout=15)


def run(lab):
    event_line = json.dumps(EVENT, sort_keys=True, separators=(",", ":"))
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": _meta("audit-forwarding-app"),
        "data": {"event.json": event_line,
                 "receiver.py": (HERE / "receiver.py").read_text(encoding="utf-8"),
                 "forwarder.py": (HERE / "forwarder.py").read_text(encoding="utf-8")},
    })
    lab.create({
        "apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": _meta("audit-sink"),
        "spec": {"accessModes": ["ReadWriteOnce"],
                 "resources": {"requests": {"storage": "16Mi"}}},
    })
    lab.create({
        "apiVersion": "v1", "kind": "Service", "metadata": _meta("audit-receiver"),
        "spec": {"type": "ClusterIP", "selector": {"app": "audit-receiver"},
                 "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]},
    })
    lab.create(_receiver_deployment())
    lab.create(_forwarder_pod())

    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Bound", "pvc/audit-sink", "--timeout=60s", timeout=70)
    lab.kubectl("rollout", "status", "deployment/audit-receiver", "--timeout=90s", timeout=100)
    lab.kubectl("wait", "--for=condition=Ready", "pod/audit-forwarder", "--timeout=60s", timeout=70)
    receiver_pods = json.loads(lab.kubectl("get", "pods", "-l", "app=audit-receiver", "-o", "json").stdout)
    forwarder_pod = json.loads(lab.kubectl("get", "pod/audit-forwarder", "-o", "json").stdout)
    pvc = json.loads(lab.kubectl("get", "pvc/audit-sink", "-o", "json").stdout)
    pod_spec = receiver_pods["items"][0]["spec"]
    forwarder_spec = forwarder_pod["spec"]
    receiver_secure = (pod_spec.get("automountServiceAccountToken") is False
                       and pod_spec.get("securityContext", {}).get("runAsNonRoot") is True
                       and pod_spec.get("securityContext", {}).get("runAsUser") == 10001)
    forwarder_secure = (forwarder_spec.get("automountServiceAccountToken") is False
                        and forwarder_spec.get("securityContext", {}).get("runAsNonRoot") is True
                        and forwarder_spec.get("securityContext", {}).get("runAsUser") == 10001)
    pvc_bound = pvc.get("status", {}).get("phase") == "Bound"
    lab.check("positive", "The sink uses a bound disposable PVC and has a nonroot tokenless pod",
              len(receiver_pods["items"]) == 1 and pvc_bound and receiver_secure and forwarder_secure,
              {"pvc_phase": pvc.get("status", {}).get("phase"), "receiver_pod_count": len(receiver_pods["items"]),
               "receiver_run_as_nonroot": pod_spec.get("securityContext", {}).get("runAsNonRoot"),
               "receiver_token_automount": pod_spec.get("automountServiceAccountToken"),
               "forwarder_run_as_nonroot": forwarder_spec.get("securityContext", {}).get("runAsNonRoot"),
               "forwarder_token_automount": forwarder_spec.get("automountServiceAccountToken")})

    red_log = _wait_for_log(lab, "delivery status=503")
    pending = lab.kubectl("exec", "pod/audit-forwarder", "--", "test", "-s", "/spool/pending.json",
                          allow_failure=True).returncode == 0
    receiver_logs = lab.kubectl("logs", "deployment/audit-receiver", allow_failure=True).stdout
    receiver_503 = "status=503" in receiver_logs
    unavailable_events = json.loads(_sink_query(lab).stdout)
    no_pre_recovery_receipt = unavailable_events == []
    lab.check("red", "The active forwarder records the receiver 503 while retaining the event",
              "delivery status=503" in red_log and pending and no_pre_recovery_receipt,
              {"forwarder_logged_503": "delivery status=503" in red_log,
               "pending_event_retained": pending, "receiver_logged_503": receiver_503,
               "sink_query_empty_before_recovery": no_pre_recovery_receipt})
    lab.check("positive", "The receiver is rejecting delivery before recovery",
              receiver_503, {"receiver_logged_503": receiver_503})

    lab.kubectl("exec", "deployment/audit-receiver", "--", "touch", "/data/accepting")
    delivered_log = _wait_for_log(lab, "delivery accepted")
    lab.check("green", "The running forwarder retries automatically and delivers after recovery",
              "delivery accepted" in delivered_log,
              {"forwarder_logged_delivery": "delivery accepted" in delivered_log})
    queued_after_delivery = lab.kubectl(
        "exec", "pod/audit-forwarder", "--", "test", "-e", "/spool/pending.json", allow_failure=True
    ).returncode == 0
    lab.check("positive", "The sender removes the pending copy after receiver acknowledgement",
              not queued_after_delivery, {"pending_after_ack": queued_after_delivery})

    before_restart = json.loads(_sink_query(lab).stdout)
    event_before_restart = before_restart == [EVENT]
    lab.check("positive", "The fixture sink can query the delivered synthetic event",
              event_before_restart, {"query_event_count": len(before_restart), "matches_fixture": event_before_restart})
    old_uid = receiver_pods["items"][0]["metadata"]["uid"]
    old_volume = pvc["spec"]["volumeName"]
    lab.kubectl("rollout", "restart", "deployment/audit-receiver")
    lab.kubectl("rollout", "status", "deployment/audit-receiver", "--timeout=90s", timeout=100)
    replacement = json.loads(lab.kubectl("get", "pods", "-l", "app=audit-receiver", "-o", "json").stdout)
    active = [item for item in replacement["items"] if "deletionTimestamp" not in item["metadata"]]
    new_pod = len(active) == 1 and active[0]["metadata"]["uid"] != old_uid
    current_pvc = json.loads(lab.kubectl("get", "pvc/audit-sink", "-o", "json").stdout)
    same_volume = current_pvc["spec"]["volumeName"] == old_volume
    lab.check("positive", "The replacement receiver mounts the same bound volume",
              new_pod and same_volume, {"new_receiver_pod": new_pod, "same_volume": same_volume})
    after_restart = json.loads(_sink_query(lab).stdout)
    retained = after_restart == [EVENT]
    lab.check("positive", "The PVC-backed sink retains the event across receiver restart",
              retained, {"query_event_count_after_restart": len(after_restart), "matches_fixture": retained})
