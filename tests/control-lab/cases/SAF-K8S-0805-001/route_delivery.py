"""Route fixed synthetic accelerator alerts to an owned in-cluster receiver."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
PREFIX = "saf-0805-001-route"
PROM = "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
ALERTMANAGER = ("docker.io/prom/alertmanager:v0.28.1@sha256:"
                "27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba")
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
METRIC = "fixture_gpu_utilization_ratio"
EXPECTED = {
    ("FixtureAcceleratorHigh", "high", "high", "warning", "fixture-accelerator-exporter:8080"),
    ("FixtureAcceleratorSignalMissing", "missing", "missing", "warning", "fixture-accelerator-exporter:8080"),
}
EXPECTED_DELIVERIES = {
    ("case-local-fixture", "firing", name, job, target, severity, instance)
    for name, job, target, severity, instance in EXPECTED
}

PROM_CONFIG = {
    "global": {"scrape_interval": "1s", "scrape_timeout": "1s", "evaluation_interval": "1s"},
    "scrape_configs": [{"job_name": target, "metrics_path": "/" + target,
                        "static_configs": [{"targets": ["fixture-accelerator-exporter:8080"],
                                            "labels": {"fixture_target": target}}]}
                       for target in ("normal", "high", "missing")],
    "rule_files": ["/fixture/rules.json"],
    "alerting": {"alertmanagers": [{"static_configs": [{"targets": [PREFIX + "-alertmanager:9093"]}]}]},
}
RULES = {"groups": [{"name": "fixture-accelerator-route", "rules": [
    {"alert": "FixtureAcceleratorHigh", "expr": METRIC + '{job="high"} > 0.8', "for": "2s",
     "labels": {"severity": "warning"}},
    {"alert": "FixtureAcceleratorSignalMissing",
     "expr": 'up{job="missing"} == 1 unless on(job, instance) ' + METRIC,
     "for": "2s", "labels": {"severity": "warning"}},
]}]}
AM_CONFIG = {
    "route": {"receiver": "discard", "group_by": ["alertname", "fixture_target"],
              "group_wait": "1s", "group_interval": "10s", "repeat_interval": "1h",
              "routes": [{"receiver": "case-local-fixture",
                          "matchers": ['alertname=~"FixtureAcceleratorHigh|FixtureAcceleratorSignalMissing"']} ]},
    "receivers": [{"name": "discard"},
                  {"name": "case-local-fixture", "webhook_configs": [{
                      "url": "http://" + PREFIX + "-receiver:18082/events",
                      "send_resolved": False, "max_alerts": 4}]}],
}

HTTP_JSON = r'''import json,sys,urllib.request
with urllib.request.urlopen(sys.argv[1],timeout=4) as r:
 print(r.read().decode())
'''


def _resource(lab, name, image, command, config_name, port, *, readiness_path):
    label = {"app": name}
    container = {"name": "app", "image": image, "imagePullPolicy": "IfNotPresent",
                 "command": command, "ports": [{"containerPort": port}],
                 "volumeMounts": [{"name": "config", "mountPath": "/fixture", "readOnly": True},
                                  {"name": "scratch", "mountPath": "/scratch"}],
                 "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                               "limits": {"cpu": "300m", "memory": "160Mi"}},
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}
    if readiness_path:
        container["readinessProbe"] = {"httpGet": {"path": readiness_path, "port": port},
                                       "periodSeconds": 1, "timeoutSeconds": 2, "failureThreshold": 60}
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": label},
           "spec": {"restartPolicy": "Always", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [container],
                    "volumes": [{"name": "config", "configMap": {"name": config_name}},
                                {"name": "scratch", "emptyDir": {"sizeLimit": "32Mi"}}]}}
    lab.create(pod)
    if port:
        lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                    "spec": {"selector": label, "ports": [{"port": port, "targetPort": port}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "--timeout=90s", timeout=98)


def _http(lab, endpoint):
    result = lab.kubectl("exec", "pod/" + PREFIX + "-receiver", "--", "python", "-c",
                         HTTP_JSON, endpoint, allow_failure=True, timeout=12)
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        return None


def _api_alerts(lab):
    data = _http(lab, "http://" + PREFIX + "-prometheus:9090/api/v1/alerts")
    if not data or data.get("status") != "success":
        return None
    return {(row.get("labels", {}).get("alertname"), row.get("labels", {}).get("job"),
             row.get("labels", {}).get("fixture_target"), row.get("state"))
            for row in data.get("data", {}).get("alerts", []) if row.get("state") == "firing"}


def _deliveries(lab):
    data = _http(lab, "http://" + PREFIX + "-receiver:18082/events")
    if not isinstance(data, list):
        return None
    rows = []
    for message in data:
        for alert in message.get("alerts", []):
            labels = alert.get("labels", {})
            rows.append((message.get("receiver"), alert.get("status"), labels.get("alertname"),
                         labels.get("job"), labels.get("fixture_target"), labels.get("severity"),
                         labels.get("instance")))
    return rows


def assess_delivery_reads(delivery_snapshot, quiet_samples, quiet_readable):
    """Evaluate the bounded read sequence without treating errors as emptiness."""
    samples = [delivery_snapshot, *quiet_samples]
    if not quiet_readable or not quiet_samples or any(sample is None for sample in samples):
        return {"read_sequence_complete": False, "expected_deliveries_present": False,
                "unexpected_records": [], "normal_target_notification_seen": False,
                "selected_records": []}
    records = [tuple(row) for sample in samples for row in sample]
    unexpected = sorted({row for row in records if row not in EXPECTED_DELIVERIES}, key=json.dumps)
    normal_seen = any(row[4] == "normal" for row in records)
    return {"read_sequence_complete": True,
            "expected_deliveries_present": EXPECTED_DELIVERIES <= set(records),
            "unexpected_records": [list(row) for row in unexpected],
            "normal_target_notification_seen": normal_seen,
            "selected_records": [list(row) for row in records]}


def _wait(probe, seconds=70):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(1)
    return None


def run(lab):
    receiver_config = PREFIX + "-receiver-config"
    # Receiver: locally owned webhook sink, retaining only fixed alert identity fields.
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": receiver_config},
                "immutable": True, "data": {"route_receiver.py": (HERE / "route_receiver.py").read_text()}})
    receiver_label = {"app": PREFIX + "-receiver"}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": PREFIX + "-receiver", "labels": receiver_label},
                "spec": {"restartPolicy": "Always", "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "receiver", "image": PYTHON, "imagePullPolicy": "IfNotPresent",
                                         "command": ["python", "-B", "/fixture/route_receiver.py"],
                                         "ports": [{"containerPort": 18082}],
                                         "readinessProbe": {"httpGet": {"path": "/health", "port": 18082},
                                                            "periodSeconds": 1},
                                         "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                                       "limits": {"cpu": "100m", "memory": "64Mi"}},
                                         "securityContext": {"allowPrivilegeEscalation": False,
                                                              "readOnlyRootFilesystem": True,
                                                              "capabilities": {"drop": ["ALL"]}},
                                         "volumeMounts": [{"name": "config", "mountPath": "/fixture", "readOnly": True}]}],
                         "volumes": [{"name": "config", "configMap": {"name": receiver_config}}]}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": PREFIX + "-receiver"},
                "spec": {"selector": receiver_label,
                         "ports": [{"port": 18082, "targetPort": 18082}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + PREFIX + "-receiver", "--timeout=90s", timeout=98)
    if _http(lab, "http://" + PREFIX + "-receiver:18082/events") != []:
        lab.block("The case-local route receiver did not start empty")

    assets = {"prometheus.json": json.dumps(PROM_CONFIG), "rules.json": json.dumps(RULES),
              "alertmanager.json": json.dumps(AM_CONFIG)}
    cfg = PREFIX + "-assets"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": cfg},
                "immutable": True, "data": assets})
    _resource(lab, PREFIX + "-alertmanager", ALERTMANAGER,
              ["/bin/alertmanager", "--config.file=/fixture/alertmanager.json",
               "--storage.path=/scratch", "--cluster.listen-address="], cfg, 9093,
              readiness_path="/-/ready")
    _resource(lab, PREFIX + "-prometheus", PROM,
              ["/bin/prometheus", "--config.file=/fixture/prometheus.json",
               "--storage.tsdb.path=/scratch", "--storage.tsdb.retention.time=10m"], cfg, 9090,
              readiness_path="/-/ready")

    expected_alerts = {
        ("FixtureAcceleratorHigh", "high", "high", "firing"),
        ("FixtureAcceleratorSignalMissing", "missing", "missing", "firing"),
    }
    def exact_alert_state():
        current = _api_alerts(lab)
        return current if current == expected_alerts else None

    observed_alerts = _wait(exact_alert_state)
    delivery_snapshot = _wait(lambda: rows if (rows := _deliveries(lab)) is not None
                              and EXPECTED_DELIVERIES <= set(map(tuple, rows)) else None)
    # Collect a bounded quiet observation. Do not claim exactly-once delivery;
    # the route's repeat interval is intentionally long, and only absence of a
    # normal-target alert is asserted.
    quiet_start = time.monotonic()
    quiet_samples = []
    quiet_readable = True
    while time.monotonic() - quiet_start < 3:
        rows = _deliveries(lab)
        if rows is None:
            quiet_readable = False
            break
        quiet_samples.append(rows)
        time.sleep(0.5)
    delivery_assessment = assess_delivery_reads(delivery_snapshot, quiet_samples, quiet_readable)
    exact_expected_deliveries = delivery_assessment["expected_deliveries_present"]
    no_unexpected = delivery_assessment["read_sequence_complete"] and not delivery_assessment["unexpected_records"]
    normal_notification_seen = delivery_assessment["normal_target_notification_seen"]
    passed = (observed_alerts == expected_alerts and exact_expected_deliveries
              and no_unexpected and not normal_notification_seen)
    evidence = {"scope": "Case-owned Alertmanager delivery for fixed synthetic Prometheus samples to one in-cluster inert receiver.",
                "receiver_identity": "case-local-fixture", "expected_alert_identities": sorted(map(list, EXPECTED_DELIVERIES)),
                "observed_firing_alerts": sorted(map(list, observed_alerts or set())),
                "receiver_read_sequence_complete": delivery_assessment["read_sequence_complete"],
                "receiver_read_sample_count": len(quiet_samples),
                "observed_delivery_records": delivery_assessment["selected_records"],
                "unexpected_delivery_records": delivery_assessment["unexpected_records"],
                "delivered_alert_records_observed": len(delivery_assessment["selected_records"]),
                "normal_target_notification_seen": normal_notification_seen,
                "no_unexpected_alert_identity": no_unexpected,
                "exactly_once_claimed": False,
                "hardware_telemetry_tested": False, "external_destinations_configured": False}
    (lab.evidence / "alert-route-delivery.raw.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    lab.check("delivery", "Alertmanager delivers the fixed high and missing fixture alerts only to the owned receiver",
              passed, {"expected_firing_alerts_observed": observed_alerts == expected_alerts,
                       "high_and_missing_fixture_alerts_delivered": exact_expected_deliveries,
                       "receiver_read_sequence_complete": delivery_assessment["read_sequence_complete"],
                       "no_normal_target_notification": not normal_notification_seen,
                       "no_unexpected_alert_identity": no_unexpected,
                       "exactly_once_claimed": False,
                       "raw_evidence": "alert-route-delivery.raw.json"})
