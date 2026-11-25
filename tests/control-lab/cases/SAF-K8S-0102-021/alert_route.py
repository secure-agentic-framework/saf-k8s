"""Exercise the owned Alertmanager route for synthetic certificate alerts.

This separate route check sends only the two synthetic API-v2 events to an
owned Alertmanager and reads only the case-local inert receiver state. It does
not call Prometheus, promtool, or any external notification integration.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time


HERE = Path(__file__).parent
ALERTMANAGER = "saf-etcd-alertmanager"
RECEIVER = "saf-etcd-alert-receiver"
AM_IMAGE = (
    "docker.io/prom/alertmanager:v0.28.1@sha256:"
    "27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
ALERT_NAME = "EtcdCertificateExpirySoon"

ROUTE_CONFIG = {
    "route": {
        "receiver": "discard-unmatched",
        "group_by": ["alertname", "cluster", "member", "certificate"],
        "group_wait": "1s",
        "group_interval": "1m",
        "repeat_interval": "1h",
        "routes": [{
            "receiver": "case-local-inert",
            "matchers": [
                'alertname="EtcdCertificateExpirySoon"',
                'cluster="synthetic-kind"',
                'severity="warning"',
                'certificate=~"etcd-server|etcd-peer|apiserver-etcd-client"',
            ],
            "continue": False,
        }],
    },
    "receivers": [
        {"name": "discard-unmatched"},
        {"name": "case-local-inert", "webhook_configs": [{
            "url": f"http://{RECEIVER}:18082/events",
            "send_resolved": False,
            "max_alerts": 1,
        }]},
    ],
}

HTTP_SCRIPT = r'''import json,sys,urllib.request
url=sys.argv[1]
if len(sys.argv)>2 and sys.argv[2]:
 data=sys.argv[2].encode()
 req=urllib.request.Request(url,data=data,headers={"Content-Type":"application/json"},method="POST")
else:
 req=urllib.request.Request(url)
with urllib.request.urlopen(req,timeout=4) as r:
 body=r.read().decode()
 print(json.dumps({"status":r.status,"body":body}))
'''


def create_workload(lab, name, image, args, port, config_name, config_files, command=None):
    selector = {"app": name}
    volume_mounts = [{"name": "config", "mountPath": "/saf", "readOnly": True}]
    container = {
        "name": "app", "image": image, "args": args,
        "ports": [{"containerPort": port}],
        "volumeMounts": volume_mounts,
        "securityContext": {"allowPrivilegeEscalation": False,
                             "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "20m", "memory": "32Mi"},
                      "limits": {"cpu": "250m", "memory": "128Mi"}},
    }
    if command:
        container["command"] = command
    readiness_path = "/state" if name == RECEIVER else "/-/ready"
    container["readinessProbe"] = {
        "httpGet": {"path": readiness_path, "port": port}, "periodSeconds": 1,
    }
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": config_name}, "data": config_files})
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": name},
                "spec": {"replicas": 1, "selector": {"matchLabels": selector},
                         "template": {"metadata": {"labels": selector},
                                      "spec": {"automountServiceAccountToken": False,
                                               "containers": [container],
                                               "securityContext": {"runAsNonRoot": True,
                                                                   "runAsUser": 65534,
                                                                   "seccompProfile": {"type": "RuntimeDefault"}},
                                               "volumes": [{"name": "config",
                                                            "configMap": {"name": config_name}}]}}}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                "spec": {"selector": selector,
                         "ports": [{"name": "http", "port": port, "targetPort": port}]}})
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)


def fixture_event(cluster):
    start = datetime.now(timezone.utc) - timedelta(seconds=2)
    end = start + timedelta(days=1)
    return [{
        "labels": {"alertname": ALERT_NAME, "cluster": cluster,
                   "member": "control-plane-0", "certificate": "etcd-server",
                   "severity": "warning"},
        "startsAt": start.isoformat().replace("+00:00", "Z"),
        "endsAt": end.isoformat().replace("+00:00", "Z"),
        "generatorURL": "http://prometheus.fixture.invalid/graph",
    }]


def in_receiver(lab, url, payload=None):
    args = ["exec", f"deployment/{RECEIVER}", "--", "python", "-c", HTTP_SCRIPT, url]
    if payload is not None:
        args.append(json.dumps(payload, separators=(",", ":")))
    return json.loads(lab.kubectl(*args, timeout=12).stdout)


def receiver_state(lab):
    response = in_receiver(lab, f"http://{RECEIVER}:18082/state")
    if response["status"] != 200:
        lab.block("The owned alert receiver did not report state")
    return json.loads(response["body"])


def submit(lab, payload):
    response = in_receiver(lab, f"http://{ALERTMANAGER}:9093/api/v2/alerts", payload)
    if response.get("status") != 200:
        lab.block("The owned Alertmanager did not accept a synthetic API v2 alert")


def wait_count(lab, expected, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = receiver_state(lab)
        if state.get("message_count") == expected:
            return state
        time.sleep(0.5)
    return None


def verify_quiet(lab, expected, duration=3):
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        state = receiver_state(lab)
        if state.get("message_count") != expected:
            return None
        time.sleep(0.25)
    return state


def run(lab):
    # Every object is created in the existing case-owned saf-test namespace.
    create_workload(lab, RECEIVER, PYTHON_IMAGE, ["/saf/inert_receiver.py"], 18082,
                    "saf-etcd-route-receiver",
                    {"inert_receiver.py": (HERE / "inert_receiver.py").read_text()},
                    command=["python"])
    create_workload(lab, ALERTMANAGER, AM_IMAGE,
                    ["--config.file=/saf/alertmanager.json", "--cluster.listen-address=", "--storage.path=/tmp"],
                    9093, "saf-etcd-route-alertmanager",
                    {"alertmanager.json": json.dumps(ROUTE_CONFIG)})

    initial = receiver_state(lab)
    if initial != {"message_count": 0, "messages": []}:
        lab.block("The case-local inert receiver did not start empty")

    # Control: accepted by API v2 but routed to the no-integration fallback.
    submit(lab, fixture_event("unexpected-fixture"))
    no_delivery = verify_quiet(lab, 0)
    lab.check("red", "A wrong-cluster certificate alert does not reach the case-local receiver",
              no_delivery is not None,
              {"wrong_cluster_event_submitted": True, "inert_receiver_count_unchanged": bool(no_delivery)})

    # Positive: only this exact synthetic alert matches the configured route.
    submit(lab, fixture_event("synthetic-kind"))
    delivered = wait_count(lab, 1)
    exact = False
    if delivered and len(delivered["messages"]) == 1:
        message = delivered["messages"][0]
        alerts = message.get("alerts", [])
        exact = (message.get("receiver") == "case-local-inert"
                 and len(alerts) == 1 and alerts[0].get("status") == "firing"
                 and alerts[0].get("labels") == {
                     "alertname": ALERT_NAME, "cluster": "synthetic-kind",
                     "member": "control-plane-0", "certificate": "etcd-server",
                     "severity": "warning",
                 })
    lab.check("green", "The approved synthetic etcd certificate alert reaches the exact inert route",
              exact, {"receiver_identity_exact": bool(exact), "notification_count": 1 if delivered else 0,
                      "matched_labels_only": bool(exact), "external_integrations": 0})
