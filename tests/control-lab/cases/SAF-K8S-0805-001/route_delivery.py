"""Route fixed synthetic accelerator alerts to an owned in-cluster receiver."""
import hashlib
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


T4_SOURCE_COMMIT = "23a8b7a4be1fec186b4138fc30e12ab0964e33b9"
T4_SOURCE_SHA256 = "907e0801f74229eb074bb04c8fc70681ab181cd908281076b5f123af436f0b68"
T4_RECEIPT_HASHES = {
    ("run-1", "idle"): "2e739e08bcedea3e99d1af2d84b4cd6902f2dee1210d57de0c8e461735e37217",
    ("run-1", "allocated"): "5add18a7db9124948b71a51d4dc7e9a051e11e487371ae42edf9c5c66c6ddbdd",
    ("run-2", "idle"): "ff84433f9a6497f43d75a136885f0c440e5cc209bd57658b097becc8259ce3d3",
    ("run-2", "allocated"): "b14b2f972e4bba8c37c1d05c0ff4ee48dd3b5ba12ebe4bc84ee584a4cd98b628",
}
T4_ALERT = "FixtureT4HistoricalFramebuffer"
T4_THRESHOLD_MIB = 100
T4_PREFIX = PREFIX + "-t4-history"


def _t4_projection():
    """Project only reviewed T4 FB_USED values and pseudonymous workload refs."""
    source_path = HERE / "t4-reference-result.json"
    source_bytes = source_path.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    if source_hash != T4_SOURCE_SHA256:
        raise RuntimeError("The pinned public T4 reference summary changed")
    source = json.loads(source_bytes)
    if (source.get("schema") != "saf-k8s-dcgm-t4-reference-v1"
            or source.get("control") != "SAF-K8S-1002-003"
            or source.get("status") != "passed"
            or source.get("scope") != "Two freshly provisioned K3s clusters on one whole passthrough T4 VM"):
        raise RuntimeError("The pinned T4 summary has an unexpected scope or status")
    if len(source.get("runs", [])) != 2:
        raise RuntimeError("The reference must contain the two reviewed T4 runs")

    projected = []
    checks = {}
    for run in source["runs"]:
        run_name = run.get("run")
        workload_ref = run.get("workload_uid_sha256")
        if run_name not in ("run-1", "run-2") or not isinstance(workload_ref, str) or len(workload_ref) != 64:
            raise RuntimeError("The summary lacks a pseudonymous workload reference")
        observation = run.get("observation", {})
        for phase in ("idle", "allocated"):
            record = observation.get(phase, {})
            if record.get("receipt_sha256") != T4_RECEIPT_HASHES[(run_name, phase)]:
                raise RuntimeError("The T4 receipt hash differs from the independently reviewed pin")
            fb_rows = [sample for sample in record.get("samples", [])
                       if sample.get("metric") == "DCGM_FI_DEV_FB_USED"]
            if len(fb_rows) != 1:
                raise RuntimeError("The T4 summary lacks one framebuffer sample")
            sample = fb_rows[0]
            expected_value = 0 if phase == "idle" else 232
            if not (sample.get("direct_value") == expected_value
                    and sample.get("prometheus_value") == expected_value
                    and sample.get("absolute_delta") == 0
                    and sample.get("unit") == "MiB"
                    and sample.get("uid_binding") == "direct_pod_uid_label"
                    and isinstance(sample.get("sample_skew_seconds"), (int, float))
                    and 0 <= sample["sample_skew_seconds"] <= 10):
                raise RuntimeError("The T4 framebuffer observation does not match the reviewed result")
            interval = record.get("interval", {})
            if not (isinstance(interval.get("start_utc"), str) and isinstance(interval.get("end_utc"), str)):
                raise RuntimeError("The historical capture interval is missing")
            projected.append({
                "capture_ref": f"{run_name}-{phase}",
                "phase": phase,
                "value_mib": expected_value,
                "workload_ref": workload_ref,
                "receipt_sha256": record["receipt_sha256"],
                "capture_interval": interval,
                "sample_skew_seconds": sample["sample_skew_seconds"],
                "source_age_class": "historical",
            })
            checks[f"{run_name}-{phase}"] = True
    if len({row["capture_ref"] for row in projected}) != 4:
        raise RuntimeError("The historical capture references are not unique")
    return {
        "source_commit": T4_SOURCE_COMMIT,
        "source_summary_sha256": source_hash,
        "source_control": source["control"],
        "hardware_class": "NVIDIA Tesla T4",
        "metric": "DCGM_FI_DEV_FB_USED",
        "unit": "MiB",
        "historical": True,
        "freshness_evaluated": False,
        "known_good_fixture_allocation": True,
        "samples": projected,
        "receipt_hash_pins_matched": checks,
    }


def _history_exporter_script():
    return r'''import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

with open("/fixture/history.json", encoding="utf-8") as stream:
    history = json.load(stream)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok\n"); return
        if self.path != "/metrics":
            self.send_error(404); return
        rows = ["# TYPE fixture_gpu_fb_used_mib gauge"]
        for sample in history["samples"]:
            labels = {"evidence_source": "historical_receipt",
                      "capture_age": "historical",
                      "hardware_class": "nvidia_t4",
                      "capture_ref": sample["capture_ref"],
                      "capture_phase": sample["phase"],
                      "workload_ref": sample["workload_ref"]}
            encoded = ",".join(f'{key}="{value}"' for key, value in labels.items())
            rows.append(f"fixture_gpu_fb_used_mib{{{encoded}}} {sample['value_mib']}")
        payload = ("\n".join(rows) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers(); self.wfile.write(payload)
    def log_message(self, *_args): pass

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def _t4_history_query(lab):
    data = _http(lab, f"http://{T4_PREFIX}-prometheus:9090/api/v1/query?query="
                 "fixture_gpu_fb_used_mib%7Bevidence_source%3D%22historical_receipt%22%7D")
    if not data or data.get("status") != "success":
        return None
    rows = data.get("data", {}).get("result", [])
    return {row.get("metric", {}).get("capture_ref"): {
        "value": float(row.get("value", [None, "nan"])[1]),
        "phase": row.get("metric", {}).get("capture_phase"),
        "age": row.get("metric", {}).get("capture_age"),
        "source": row.get("metric", {}).get("evidence_source"),
        "workload_ref": row.get("metric", {}).get("workload_ref"),
    } for row in rows}


def _t4_history_alerts(lab):
    data = _http(lab, f"http://{T4_PREFIX}-prometheus:9090/api/v1/alerts")
    if not data or data.get("status") != "success":
        return None
    return {(row.get("labels", {}).get("alertname"), row.get("labels", {}).get("capture_ref"),
             row.get("labels", {}).get("capture_phase"), row.get("labels", {}).get("capture_age"),
             row.get("labels", {}).get("evidence_source"), row.get("labels", {}).get("workload_ref"),
             row.get("state")) for row in data.get("data", {}).get("alerts", [])
            if row.get("labels", {}).get("alertname") == T4_ALERT and row.get("state") == "firing"}


def _t4_history_deliveries(lab):
    messages = _http(lab, "http://" + PREFIX + "-receiver:18082/events")
    if not isinstance(messages, list):
        return None
    rows = []
    for message in messages:
        if message.get("receiver") != "case-local-t4-historical":
            continue
        for alert in message.get("alerts", []):
            labels = alert.get("labels", {})
            rows.append((alert.get("status"), labels.get("alertname"), labels.get("capture_ref"),
                         labels.get("capture_phase"), labels.get("capture_age"),
                         labels.get("evidence_source"), labels.get("workload_ref")))
    return rows


def run_t4_historical(lab):
    history = _t4_projection()
    history_json = json.dumps(history, sort_keys=True, separators=(",", ":"))
    prom_config = {
        "global": {"scrape_interval": "1s", "scrape_timeout": "1s", "evaluation_interval": "1s"},
        "scrape_configs": [{"job_name": "t4-historical-replay", "metrics_path": "/metrics",
                            "static_configs": [{"targets": [T4_PREFIX + "-exporter:8080"],
                                                "labels": {"fixture_target": "historical-t4-receipt"}}]}],
        "rule_files": ["/fixture/history-rules.json"],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": [T4_PREFIX + "-alertmanager:9093"]}]}]},
    }
    rules = {"groups": [{"name": "t4-historical-reference", "rules": [{
        "alert": T4_ALERT,
        "expr": (f'fixture_gpu_fb_used_mib{{evidence_source="historical_receipt",'
                 f'capture_age="historical"}} > {T4_THRESHOLD_MIB}'),
        "for": "1s",
        "labels": {"severity": "warning"},
        "annotations": {"summary": "Historical T4 framebuffer fixture exceeded the review threshold"},
    }]}]}
    alertmanager_config = {
        "route": {"receiver": "discard", "group_by": ["alertname", "capture_ref"],
                  "group_wait": "1s", "group_interval": "10s", "repeat_interval": "1h",
                  "routes": [{"receiver": "case-local-t4-historical",
                              "matchers": [f'alertname="{T4_ALERT}"']} ]},
        "receivers": [{"name": "discard"}, {"name": "case-local-t4-historical", "webhook_configs": [{
            "url": "http://" + PREFIX + "-receiver:18082/events", "send_resolved": False, "max_alerts": 2}]}],
    }
    cfg = T4_PREFIX + "-assets"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": cfg}, "immutable": True,
                "data": {"history.json": history_json, "history_exporter.py": _history_exporter_script(),
                         "prometheus.json": json.dumps(prom_config), "history-rules.json": json.dumps(rules),
                         "alertmanager.json": json.dumps(alertmanager_config)}})
    _resource(lab, T4_PREFIX + "-exporter", PYTHON,
              ["python", "-B", "/fixture/history_exporter.py"], cfg, 8080, readiness_path="/health")
    _resource(lab, T4_PREFIX + "-alertmanager", ALERTMANAGER,
              ["/bin/alertmanager", "--config.file=/fixture/alertmanager.json",
               "--storage.path=/scratch", "--cluster.listen-address="], cfg, 9093, readiness_path="/-/ready")
    _resource(lab, T4_PREFIX + "-prometheus", PROM,
              ["/bin/prometheus", "--config.file=/fixture/prometheus.json",
               "--storage.tsdb.path=/scratch", "--storage.tsdb.retention.time=10m"],
              cfg, 9090, readiness_path="/-/ready")

    expected_values = {sample["capture_ref"]: {
        "value": float(sample["value_mib"]), "phase": sample["phase"], "age": "historical",
        "source": "historical_receipt", "workload_ref": sample["workload_ref"]}
        for sample in history["samples"]}
    expected_alerts = {(T4_ALERT, sample["capture_ref"], "allocated", "historical", "historical_receipt",
                        sample["workload_ref"], "firing") for sample in history["samples"]
                       if sample["phase"] == "allocated"}
    values = _wait(lambda: current if (current := _t4_history_query(lab)) == expected_values else None, seconds=50)
    if values is None:
        lab.block("The pinned historical T4 series were not all visible with their reviewed labels and values")
    alerts = _wait(lambda: current if (current := _t4_history_alerts(lab)) == expected_alerts else None, seconds=70)
    if alerts is None:
        alerts = _t4_history_alerts(lab)
    expected_deliveries = {("firing", T4_ALERT, sample["capture_ref"], "allocated", "historical",
                            "historical_receipt", sample["workload_ref"])
                           for sample in history["samples"] if sample["phase"] == "allocated"}
    deliveries = _wait(lambda: current if (current := _t4_history_deliveries(lab)) is not None
                       and expected_deliveries <= set(current) else None, seconds=70)
    if deliveries is None:
        deliveries = _t4_history_deliveries(lab)
    idle_refs = [sample["capture_ref"] for sample in history["samples"] if sample["phase"] == "idle"]
    idle_quiet = (len(idle_refs) == 2 and all(values[ref]["value"] <= T4_THRESHOLD_MIB for ref in idle_refs)
                  and alerts is not None and all(row[1] not in idle_refs for row in alerts))
    allocated_known_good = (history["known_good_fixture_allocation"] is True
                            and all(sample["phase"] != "allocated" or sample["value_mib"] == 232
                                    for sample in history["samples"]))
    only_allocated = (alerts == expected_alerts and len(expected_alerts) == 2
                      and all(row[2] == "allocated" for row in expected_alerts))
    only_expected_delivered = (deliveries is not None and expected_deliveries <= set(deliveries)
                               and all(row in expected_deliveries for row in deliveries))
    history_source_marked = all(sample["source_age_class"] == "historical" for sample in history["samples"])
    passed = (history_source_marked and idle_quiet and allocated_known_good and only_allocated
              and only_expected_delivered and history["freshness_evaluated"] is False)
    raw = {"scope": "Case-owned replay of two hash-pinned, previously observed T4 framebuffer captures through Prometheus and Alertmanager.",
           "source_commit": history["source_commit"], "source_summary_sha256": history["source_summary_sha256"],
           "hardware_class": history["hardware_class"], "metric": history["metric"], "unit": history["unit"],
           "threshold_mib": T4_THRESHOLD_MIB, "freshness_evaluated": False,
           "receipt_hash_pins_matched": history["receipt_hash_pins_matched"],
           "known_good_fixture_allocation": True, "projected_samples": history["samples"],
           "prometheus_values": values, "firing_alerts": sorted([list(row) for row in alerts or set()]),
           "delivered_alerts": [list(row) for row in deliveries or []],
           "idle_series_quiet": idle_quiet, "allocated_series_alerted": only_allocated,
           "only_expected_allocated_alerts_delivered": only_expected_delivered,
           "exactly_once_claimed": False, "misuse_or_incident_claimed": False}
    (lab.evidence / "t4-historical-alert-route.raw.json").write_text(json.dumps(raw, sort_keys=True, indent=2) + "\n")
    lab.check("historical", "The historical T4 allocation values alert and route with pseudonymous provenance while idle stays below threshold",
              passed, {"pinned_historical_source_used": history_source_marked,
                       "four_attributed_capture_values_observed": values == expected_values,
                       "idle_samples_remain_quiet": idle_quiet,
                       "only_allocated_samples_fire": only_allocated,
                       "only_expected_allocated_alerts_delivered": only_expected_delivered,
                       "freshness_evaluated": False,
                       "misuse_or_incident_claimed": False,
                       "exactly_once_claimed": False,
                       "raw_evidence": "t4-historical-alert-route.raw.json"})
