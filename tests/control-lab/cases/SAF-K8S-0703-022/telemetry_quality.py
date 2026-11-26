"""Add one case-owned synthetic Prometheus freshness/coverage comparison."""

import json
import time
from urllib.parse import urlencode


PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
PROM = "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
NAMESPACE = "saf-test"
STALE_AFTER = 60
EXPECTED = {"approved-intensive", "stale-telemetry", "missing-sample"}
TELEMETRY_EXPORTER = '''import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        now = time.time()
        rows = [
            "# TYPE fixture_gpu_expected_sample gauge",
            'fixture_gpu_expected_sample{workload="approved-intensive",device="fixture-device-0"} 1',
            'fixture_gpu_expected_sample{workload="stale-telemetry",device="fixture-device-1"} 1',
            'fixture_gpu_expected_sample{workload="missing-sample",device="fixture-device-2"} 1',
            "# TYPE fixture_gpu_sample_timestamp_seconds gauge",
            f'fixture_gpu_sample_timestamp_seconds{{workload="approved-intensive",device="fixture-device-0"}} {now:.3f}',
            f'fixture_gpu_sample_timestamp_seconds{{workload="stale-telemetry",device="fixture-device-1"}} {now - 300:.3f}',
        ]
        body = ("\\n".join(rows) + "\\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def extended_rules(base_rules):
    result = json.loads(json.dumps(base_rules))
    result["groups"].append({"name": "fixture-telemetry-quality", "rules": [
        {"alert": "FixtureTelemetrySampleStale",
         "expr": f'fixture_gpu_expected_sample == 1 and on(workload,device) (fixture_gpu_sample_timestamp_seconds < time() - {STALE_AFTER})',
         "for": "2s", "labels": {"disposition": "telemetry-quality"},
         "annotations": {"reason": "sample-stale"}},
        {"alert": "FixtureTelemetryCoverageGap",
         "expr": 'fixture_gpu_expected_sample == 1 unless on(workload,device) fixture_gpu_sample_timestamp_seconds',
         "for": "2s", "labels": {"disposition": "telemetry-quality"},
         "annotations": {"reason": "expected-series-missing"}},
        {"alert": "FixtureTelemetrySourceUnavailable",
         "expr": 'up{job="fixture-source-unavailable"} == 0',
         "for": "2s", "labels": {"disposition": "telemetry-quality"},
         "annotations": {"reason": "scrape-source-unavailable"}},
    ]})
    return result


def query_data(lab, prom_api, expression):
    return prom_api(lab, "/api/v1/query?" + urlencode({"query": expression})) or {}


def rows_by_workload(data):
    return {row.get("metric", {}).get("workload"): float(row["value"][1])
            for row in data.get("result", []) if row.get("metric", {}).get("workload")}


def replace_prometheus(lab, workload, base_rules):
    workload(lab, "fixture-telemetry", PYTHON,
             {"telemetry.py": TELEMETRY_EXPORTER}, 8080, "/metrics",
             command=["python", "/fixture/telemetry.py"])

    # The published Prometheus ConfigMap is immutable. Replace only this owned
    # Prometheus Pod/service/config, after its original three checks have passed.
    lab.kubectl("delete", "pod", "fixture-prometheus", "--wait=true", "--timeout=60s", timeout=65)
    lab.kubectl("delete", "service", "fixture-prometheus")
    lab.kubectl("delete", "configmap", "fixture-prometheus")

    prometheus = {
        "global": {"scrape_interval": "1s", "scrape_timeout": "800ms", "evaluation_interval": "1s"},
        "rule_files": ["/fixture/rules.json"],
        "scrape_configs": [
            {"job_name": target, "static_configs": [{"targets": [target + ":8080"]}]}
            for target in ("fixture-activity", "fixture-context", "fixture-telemetry")
        ] + [{"job_name": "fixture-source-unavailable",
              "static_configs": [{"targets": ["fixture-source-unavailable.saf-test.svc:8080"]}]}
        ],
    }
    workload(lab, "fixture-prometheus", PROM,
             {"prom.json": json.dumps(prometheus), "rules.json": json.dumps(extended_rules(base_rules))},
             9090, "/-/ready", args=["--config.file=/fixture/prom.json", "--storage.tsdb.path=/data"])


def run(lab, workload, base_rules, prom_api, vector):
    replace_prometheus(lab, workload, base_rules)
    deadline = time.monotonic() + 60
    expected_inventory = {}
    samples = {}
    unavailable = None
    while time.monotonic() < deadline:
        expected_inventory = rows_by_workload(query_data(lab, prom_api, "fixture_gpu_expected_sample"))
        samples = rows_by_workload(query_data(lab, prom_api, "fixture_gpu_sample_timestamp_seconds"))
        unavailable = query_data(lab, prom_api, 'up{job="fixture-source-unavailable"} == 0')
        alerts = prom_api(lab, "/api/v1/alerts") or {}
        firing = [row for row in alerts.get("alerts", []) if row.get("state") == "firing"]
        names = {row.get("labels", {}).get("alertname") for row in firing}
        required = {"FixtureTelemetrySampleStale", "FixtureTelemetryCoverageGap",
                    "FixtureTelemetrySourceUnavailable"}
        if EXPECTED == set(expected_inventory) and set(samples) == {"approved-intensive", "stale-telemetry"} \
                and unavailable.get("result") and required <= names:
            break
        time.sleep(1)
    else:
        lab.block("Prometheus did not reach the expected synthetic telemetry-quality matrix")

    # Compare sample age to the same Prometheus evaluation clock. Only stable
    # age classes, labels and rule reasons are emitted into the test result.
    server_now = query_data(lab, prom_api, "time()")
    scalar = server_now.get("result", [])
    if server_now.get("resultType") != "scalar" or len(scalar) != 2:
        lab.block("Prometheus did not return an evaluation clock for the telemetry matrix")
    prom_time = float(scalar[1])
    fresh_age = prom_time - samples.get("approved-intensive", 0)
    stale_age = prom_time - samples.get("stale-telemetry", 0)
    threshold_only = vector(lab, "fixture_gpu_activity_percent > 80")
    context_metrics = vector(lab, "fixture_gpu_approved")

    alerts = prom_api(lab, "/api/v1/alerts") or {}
    firing = [row for row in alerts.get("alerts", []) if row.get("state") == "firing"]
    telemetry = {}
    for row in firing:
        labels = row.get("labels", {})
        if labels.get("disposition") != "telemetry-quality":
            continue
        name = labels.get("alertname")
        if name == "FixtureTelemetrySourceUnavailable":
            key = (name, labels.get("job"))
        else:
            key = (name, labels.get("workload"), labels.get("device"))
        telemetry[key] = row.get("annotations", {}).get("reason")
    required_alerts = {
        ("FixtureTelemetrySampleStale", "stale-telemetry", "fixture-device-1"): "sample-stale",
        ("FixtureTelemetryCoverageGap", "missing-sample", "fixture-device-2"): "expected-series-missing",
        ("FixtureTelemetrySourceUnavailable", "fixture-source-unavailable"): "scrape-source-unavailable",
    }
    approved_review_alerted = any(
        row.get("labels", {}).get("workload") == "approved-intensive"
        for row in firing if row.get("labels", {}).get("disposition") in {"review", "telemetry-quality"}
    )
    old_review_reasons = {(row.get("labels", {}).get("workload"),
                           row.get("annotations", {}).get("reason"))
                          for row in firing if row.get("labels", {}).get("disposition") == "review"}
    expected_old_reviews = {("missing-owner-context", "context-unknown"),
                            ("policy-mismatch", "context-mismatch")}
    source_is_down = len(unavailable.get("result", [])) == 1
    correct_inventory = set(expected_inventory) == EXPECTED
    sample_classes = set(samples) == {"approved-intensive", "stale-telemetry"}
    lab.check(
        "positive", "Fresh approved activity stays visible while stale, missing, and unavailable telemetry remain distinct review-quality states",
        correct_inventory and sample_classes and 0 <= fresh_age < STALE_AFTER
        and stale_age > STALE_AFTER and source_is_down and telemetry == required_alerts
        and threshold_only.get("approved-intensive") == 96
        and context_metrics.get("approved-intensive") == 1
        and not approved_review_alerted and expected_old_reviews <= old_review_reasons,
        {"expected_inventory_complete": correct_inventory,
         "fresh_sample_age_within_window": 0 <= fresh_age < STALE_AFTER,
         "stale_sample_age_exceeds_window": stale_age > STALE_AFTER,
         "missing_sample_alert": any(key[0] == "FixtureTelemetryCoverageGap" for key in telemetry),
         "unavailable_source_alert": any(key[0] == "FixtureTelemetrySourceUnavailable" for key in telemetry),
         "approved_high_activity_observed": threshold_only.get("approved-intensive") == 96,
         "approved_context_observed": context_metrics.get("approved-intensive") == 1,
         "approved_activity_review_alerted": approved_review_alerted,
         "review_reasons_preserved": expected_old_reviews <= old_review_reasons},
    )
