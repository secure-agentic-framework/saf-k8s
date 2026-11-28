"""Prove routed handling distinguishes a failed scrape from absent target telemetry."""
import json
from pathlib import Path
import time
from urllib.parse import urlencode

HERE = Path(__file__).resolve().parent
PREFIX = "saf-0805-001-visibility"
PROM = "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
ALERTMANAGER = ("docker.io/prom/alertmanager:v0.28.1@sha256:"
                "27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba")
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
METRIC = "fixture_gpu_utilization_ratio"
EXPECTED = {
    ("FixtureSourceScrapeFailed", "failed", "firing"),
    ("FixtureSourceTargetAbsent", "vanished", "firing"),
}
DELIVERIES = {("case-local-visibility", "firing", alert, job, "visibility-proof", "warning")
              for alert, job in (("FixtureSourceScrapeFailed", "failed"),
                                 ("FixtureSourceTargetAbsent", "vanished"))}


def create_pod(lab, name, image, command, port, *, config_name=None, readiness=None):
    volumes, mounts = [], []
    if config_name:
        volumes = [{"name": "config", "configMap": {"name": config_name}}]
        mounts = [{"name": "config", "mountPath": "/fixture", "readOnly": True}]
    mounts.append({"name": "scratch", "mountPath": "/scratch"})
    container = {"name": "app", "image": image, "imagePullPolicy": "IfNotPresent",
                 "command": command, "ports": [{"containerPort": port}], "volumeMounts": mounts,
                 "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                               "limits": {"cpu": "300m", "memory": "160Mi"}},
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}
    if readiness:
        container["readinessProbe"] = {"httpGet": {"path": readiness, "port": port},
                                       "periodSeconds": 1, "timeoutSeconds": 2, "failureThreshold": 60}
    label = {"app": name}
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": label},
           "spec": {"restartPolicy": "Always", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [container], "volumes": volumes + [{"name": "scratch", "emptyDir": {"sizeLimit": "32Mi"}}]}}
    lab.create(pod)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                "spec": {"selector": label, "ports": [{"port": port, "targetPort": port}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "--timeout=90s", timeout=98)


def read(lab, endpoint):
    script = "import sys,urllib.request;print(urllib.request.urlopen(sys.argv[1],timeout=4).read().decode())"
    result = lab.kubectl("exec", "pod/" + PREFIX + "-receiver", "--", "python", "-c", script,
                         endpoint, timeout=12, allow_failure=True)
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        return None


def query(lab, expression, *, lookback="6s"):
    params = {"query": expression, "lookback_delta": lookback}
    url = f"http://{PREFIX}-prometheus:9090/api/v1/query?" + urlencode(params)
    data = read(lab, url)
    if not isinstance(data, dict) or data.get("status") != "success":
        return None
    return data.get("data", {}).get("result")


def alerts(lab):
    rows = read(lab, f"http://{PREFIX}-prometheus:9090/api/v1/alerts")
    if not isinstance(rows, dict) or rows.get("status") != "success":
        return None
    return {(x.get("labels", {}).get("alertname"), x.get("labels", {}).get("job"), x.get("state"))
            for x in rows.get("data", {}).get("alerts", []) if x.get("state") == "firing"}


def deliveries(lab):
    messages = read(lab, f"http://{PREFIX}-receiver:18082/events")
    if not isinstance(messages, list):
        return None
    found = []
    for message in messages:
        for alert in message.get("alerts", []):
            labels = alert.get("labels", {})
            found.append((message.get("receiver"), alert.get("status"), labels.get("alertname"),
                          labels.get("job"), labels.get("fixture_target"), labels.get("severity")))
    return found


def wait(probe, seconds=70):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(1)
    return None


def run(lab):
    receiver_config = PREFIX + "-receiver-config"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": receiver_config},
                "immutable": True, "data": {"route_receiver.py": (HERE / "route_receiver.py").read_text()}})
    create_pod(lab, PREFIX + "-receiver", PYTHON, ["python", "-B", "/fixture/route_receiver.py"],
               18082, config_name=receiver_config, readiness="/health")
    if read(lab, f"http://{PREFIX}-receiver:18082/events") != []:
        lab.block("The visibility proof receiver did not start empty")

    exporter_cfg = PREFIX + "-exporter-config"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": exporter_cfg},
                "immutable": True, "data": {"exporter.py": (HERE / "visibility_exporter.py").read_text()}})
    create_pod(lab, PREFIX + "-exporter", PYTHON, ["python", "-B", "/fixture/exporter.py"],
               8080, config_name=exporter_cfg)

    scrape = [{"job_name": "healthy", "metrics_path": "/zero",
               "static_configs": [{"targets": [PREFIX + "-exporter:8080"],
                                   "labels": {"fixture_target": "visibility-proof"}}]},
              {"job_name": "failed", "metrics_path": "/failed",
               "static_configs": [{"targets": [PREFIX + "-exporter:8080"],
                                   "labels": {"fixture_target": "visibility-proof"}}]},
              {"job_name": "vanished", "metrics_path": "/healthy",
               "static_configs": [{"targets": [PREFIX + "-exporter:8080"],
                                   "labels": {"fixture_target": "visibility-proof"}}]}]
    rules = {"groups": [{"name": "fixture-source-visibility", "rules": [
        {"alert": "FixtureSourceScrapeFailed", "expr": 'up{job="failed"} == 0', "for": "2s",
         "labels": {"severity": "warning"}, "annotations": {"summary": "Fixture scrape failed"}},
        {"alert": "FixtureSourceTargetAbsent", "expr": 'absent_over_time(up{job="vanished"}[6s])', "for": "4s",
         "labels": {"job": "vanished", "fixture_target": "visibility-proof", "severity": "warning"},
         "annotations": {"summary": "Fixture target is absent from scrape inventory"}},
    ]}]}
    prom_config = {"global": {"scrape_interval": "1s", "scrape_timeout": "1s", "evaluation_interval": "1s"},
                  "scrape_configs": scrape, "rule_files": ["/fixture/rules.json"],
                  "alerting": {"alertmanagers": [{"static_configs": [{"targets": [PREFIX + "-alertmanager:9093"]}]}]}}
    am_config = {"route": {"receiver": "discard", "group_by": ["alertname", "fixture_target"],
                            "group_wait": "1s", "group_interval": "2s", "repeat_interval": "1h",
                            "routes": [{"receiver": "case-local-visibility",
                                        "matchers": ['alertname=~"FixtureSourceScrapeFailed|FixtureSourceTargetAbsent"']}]},
                 "receivers": [{"name": "discard"}, {"name": "case-local-visibility",
                               "webhook_configs": [{"url": f"http://{PREFIX}-receiver:18082/events",
                                                    "send_resolved": False, "max_alerts": 4}]}]}
    cfg = PREFIX + "-assets"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": cfg},
                "data": {"prometheus.json": json.dumps(prom_config), "rules.json": json.dumps(rules),
                         "alertmanager.json": json.dumps(am_config)}})
    create_pod(lab, PREFIX + "-alertmanager", ALERTMANAGER,
               ["/bin/alertmanager", "--config.file=/fixture/alertmanager.json",
                "--storage.path=/scratch", "--cluster.listen-address="], 9093,
               config_name=cfg, readiness="/-/ready")
    create_pod(lab, PREFIX + "-prometheus", PROM,
               ["/bin/prometheus", "--config.file=/fixture/prometheus.json", "--storage.tsdb.path=/scratch",
                "--storage.tsdb.retention.time=10m", "--web.enable-lifecycle"], 9090,
               config_name=cfg, readiness="/-/ready")

    # Establish that the soon-to-be-removed source was visible before removing
    # only its scrape job. The healthy peer and failed-scrape job stay configured.
    initial_vanished_up = wait(lambda: rows if (rows := query(lab, 'up{job="vanished"}'))
                               and len(rows) == 1 and rows[0]["value"][1] == "1" else None)
    initial_vanished_metric = query(lab, METRIC + '{job="vanished"}')
    if initial_vanished_up is None or not initial_vanished_metric or initial_vanished_metric[0]["value"][1] != "0.2":
        lab.block("The vanishing fixture source was not observable before its scrape target was removed")
    before = deliveries(lab)
    if before is None or any(row[2] == "FixtureSourceTargetAbsent" for row in before):
        lab.block("The tracked source must have no absence delivery while visible")
    remaining_scrapes = [entry for entry in scrape if entry["job_name"] != "vanished"]
    replacement_config = dict(prom_config, scrape_configs=remaining_scrapes)
    lab.kubectl("patch", "configmap", cfg, "--type=merge", "-p",
                json.dumps({"data": {"prometheus.json": json.dumps(replacement_config)}}))

    lab.kubectl("annotate", "pod", PREFIX + "-prometheus", "fixture.example/config-change=vanished-removed")

    def projected_config_updated():
        result = lab.kubectl("exec", "pod/" + PREFIX + "-prometheus", "--", "cat",
                             "/fixture/prometheus.json", timeout=12, allow_failure=True)
        return result.returncode == 0 and json.loads(result.stdout) == replacement_config

    if not wait(projected_config_updated, seconds=125):
        lab.block("Prometheus did not receive the new projected configuration")
    reload_script = ("import urllib.request; r=urllib.request.Request('http://" + PREFIX
                     + "-prometheus:9090/-/reload',method='POST'); print(urllib.request.urlopen(r,timeout=5).status)")
    lab.kubectl("exec", "pod/" + PREFIX + "-receiver", "--", "python", "-c", reload_script, timeout=12)

    expected_alerts = EXPECTED
    observed_alerts = wait(lambda: current if (current := alerts(lab)) == expected_alerts else None)
    # Queries must show three distinct states: failed target has up=0, absent job has no up series,
    # and the independent healthy source remains up with its metric visible.
    failed_rows = query(lab, 'up{job="failed"}')
    failed_metric = query(lab, METRIC + '{job="failed"}')
    target_status = read(lab, f"http://{PREFIX}-prometheus:9090/api/v1/targets?state=active")
    current_targets = (target_status or {}).get("data", {}).get("activeTargets", [])
    failed = [row for row in current_targets if row.get("scrapePool") == "failed"]
    target_contract = (len(failed) == 1 and failed[0].get("health") == "down"
                       and "503" in failed[0].get("lastError", "")
                       and not any(row.get("scrapePool") == "vanished" for row in current_targets))
    absent_seen = wait(lambda: True if query(lab, 'up{job="vanished"}') == [] else None)
    absent_rows = query(lab, 'up{job="vanished"}') if absent_seen else None
    default_lookback = query(lab, 'up{job="vanished"}', lookback="5m")
    absent_probe = query(lab, 'absent_over_time(up{job="vanished"}[6s])')
    healthy_up = query(lab, 'up{job="healthy"}')
    healthy_metric = query(lab, METRIC + '{job="healthy"}')
    state_contract = (failed_rows is not None and len(failed_rows) == 1 and failed_rows[0]["value"][1] == "0"
                      and failed_metric == [] and target_contract and absent_rows == [] and absent_probe is not None and len(absent_probe) == 1
                      and absent_probe[0]["value"][1] == "1"
                      and healthy_up is not None and len(healthy_up) == 1 and healthy_up[0]["value"][1] == "1"
                      and healthy_metric is not None and len(healthy_metric) == 1
                      and healthy_metric[0]["value"][1] == "0")
    routed = wait(lambda: rows if (rows := deliveries(lab)) is not None and DELIVERIES == set(rows) else None)
    receipt_bound = routed is not None and DELIVERIES == set(routed)
    raw = {"schema": "saf-0805-001-visibility-route-v1", "status": "passed" if
           (observed_alerts == expected_alerts and state_contract and receipt_bound) else "failed",
           "source_mode": "synthetic isolated HTTP fixture; no GPU telemetry",
           "failed_target_http_503": target_contract,
           "failed_target_device_metric_absent": failed_metric == [],
           "projected_config_checked_before_reload": True,
           "no_absence_delivery_before_reload": True,
           "failed_target_up_value": (failed_rows[0]["value"][1] if failed_rows else None),
           "vanished_target_up_before_removal": (initial_vanished_up[0]["value"][1] if initial_vanished_up else None),
           "vanished_target_metric_before_removal": (initial_vanished_metric[0]["value"][1]
                                                       if initial_vanished_metric else None),
           "vanished_target_up_series_count": (len(absent_rows) if absent_rows is not None else None),
           "query_lookback_seconds": 6,
           "target_absence_rule_window_seconds": 6,
           "default_five_minute_lookback_series_count": len(default_lookback) if default_lookback is not None else None,
           "absent_up_probe_value": (absent_probe[0]["value"][1] if absent_probe else None),
           "healthy_source_up_value": (healthy_up[0]["value"][1] if healthy_up else None),
           "healthy_source_metric_value": (healthy_metric[0]["value"][1] if healthy_metric else None),
           "expected_firing_alerts": sorted([list(x) for x in EXPECTED]),
           "observed_firing_alerts": sorted([list(x) for x in (observed_alerts or set())]),
           "expected_route_receipts": sorted([list(x) for x in DELIVERIES]),
           "observed_route_receipts": [list(x) for x in (routed or [])],
           "route_receipt_confirmed": receipt_bound,
           "other_source_remained_observable": bool(healthy_up and healthy_metric)}
    (lab.evidence / "source-visibility-route.raw.json").write_text(json.dumps(raw, sort_keys=True, indent=2) + "\n")
    lab.check("visibility-route", "A failed scrape (up=0) and absent target (no up series) produce distinct routed alerts while a peer source remains observable",
              raw["status"] == "passed",
              {"failed_scrape_up_zero": state_contract and raw["failed_target_up_value"] == "0",
               "absent_target_series_distinct": state_contract and raw["vanished_target_up_series_count"] == 0
                   and raw["absent_up_probe_value"] == "1",
               "healthy_peer_reports_real_zero": state_contract and raw["healthy_source_up_value"] == "1"
                   and raw["healthy_source_metric_value"] == "0",
               "expected_alerts_fired": observed_alerts == expected_alerts,
               "expected_route_receipt_observed": receipt_bound,
               "raw_evidence": "source-visibility-route.raw.json"})
