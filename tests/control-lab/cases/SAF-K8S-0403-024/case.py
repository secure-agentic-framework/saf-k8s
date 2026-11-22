"""Publish synthetic credential lifecycle metadata through a live metrics endpoint."""
import json
import time
from urllib.parse import quote_plus


CASE_ID = "SAF-K8S-0403-024"
NAMESPACE = "saf-test"
EXPORTER = "saf-0403-024-exporter"
PROMETHEUS = "saf-0403-024-prometheus"
WINDOW_SECONDS = 300
SCRAPE_INTERVAL_SECONDS = 2
PROMETHEUS_IMAGE = (
    "docker.io/prom/prometheus:v3.16.0@sha256:"
    "e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)

SCOPE = (
    "One case-owned Python producer serves allowlisted aggregate metrics computed from a "
    "fixed set of synthetic credential metadata events in Kind. A live digest-pinned "
    "Prometheus instance scrapes that Service every 2 seconds and queries its samples. "
    "The synthetic event window is exactly 300 seconds; issuance rate is events per "
    "second. No credential value or external scrape target is used. This tests the "
    "fixture producer and scrape/query path only, not ingestion from Vault, cloud IAM, "
    "Kubernetes token issuers, API-key stores, model registries, dashboards, review "
    "workflows, or production coverage."
)

EVENTS = {
    "window_seconds": WINDOW_SECONDS,
    "issuances": [
        {"event_id": "synthetic-issue-01", "approved": True, "ttl_seconds": 3600},
        {"event_id": "synthetic-issue-02", "approved": True, "ttl_seconds": 7200},
        {"event_id": "synthetic-issue-03", "approved": True, "ttl_seconds": None},
        {"event_id": "synthetic-issue-04", "approved": True, "ttl_seconds": 5400},
        # Exact duplicate is suppressed by event_id idempotency policy.
        {"event_id": "synthetic-issue-02", "approved": True, "ttl_seconds": 7200},
        # This attempted event is rejected and must not inflate accepted issuance.
        {"event_id": "synthetic-issue-05", "approved": False, "ttl_seconds": 1800},
    ],
    "inventory": [
        {"record": "synthetic-record-a", "workload_present": True},
        {"record": "synthetic-record-b", "workload_present": True},
        {"record": "synthetic-record-c", "workload_present": False},
        {"record": "synthetic-record-d", "workload_present": True},
    ],
    "scope_exceptions": [
        {"record": "synthetic-exception-a", "approved": True},
        {"record": "synthetic-exception-b", "approved": True},
        {"record": "synthetic-exception-c", "approved": False},
    ],
}

EXPORTER_SERVER = r'''
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

CASE = "SAF-K8S-0403-024"
DATA = Path("/fixture/events.json")

def render():
    fixture = json.loads(DATA.read_text())
    accepted = {}
    duplicate_count = 0
    unapproved_count = 0
    for event in fixture["issuances"]:
        if not event["approved"]:
            unapproved_count += 1
        elif event["event_id"] in accepted:
            duplicate_count += 1
        else:
            accepted[event["event_id"]] = event
    ttls = [event["ttl_seconds"] for event in accepted.values()
            if event["ttl_seconds"] is not None]
    inventory = fixture["inventory"]
    orphan_count = sum(not item["workload_present"] for item in inventory)
    approved_exception_count = sum(item["approved"] for item in fixture["scope_exceptions"])
    window = fixture["window_seconds"]
    issued = len(accepted)
    rate = issued / window
    mean_ttl = sum(ttls) / len(ttls) if ttls else 0
    metrics = [
        ("saf_credential_issuance_events_in_window", "gauge", issued, "events"),
        ("saf_credential_issuance_window_seconds", "gauge", window, "seconds"),
        ("saf_credential_issuance_rate_per_second", "gauge", rate, "events per second"),
        ("saf_credential_ttl_mean_seconds", "gauge", mean_ttl, "seconds; missing TTLs excluded"),
        ("saf_credential_ttl_observed_count", "gauge", len(ttls), "events with known TTL"),
        ("saf_credential_ttl_missing_count", "gauge", issued - len(ttls), "events with missing TTL"),
        ("saf_credential_orphan_records", "gauge", orphan_count, "records"),
        ("saf_credential_inventory_records", "gauge", len(inventory), "records; orphan-rate denominator"),
        ("saf_credential_orphan_rate", "gauge", orphan_count / len(inventory) if inventory else 0,
         "ratio in [0,1]"),
        ("saf_credential_approved_scope_exceptions", "gauge", approved_exception_count, "exceptions"),
        ("saf_credential_duplicate_events_rejected", "gauge", duplicate_count, "events"),
        ("saf_credential_unapproved_events_rejected", "gauge", unapproved_count, "events"),
    ]
    lines = []
    for name, kind, value, unit in metrics:
        lines.extend([f"# HELP {name} Synthetic metadata aggregate; unit: {unit}.",
                      f"# TYPE {name} {kind}", f'{name}{{case_id="{CASE}"}} {value}'])
    return "\n".join(lines) + "\n"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/baseline":
            body = b"# Synthetic empty baseline: no credential lifecycle samples.\n"
        elif self.path == "/metrics":
            body = render().encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args):
        pass

HTTPServer(("0.0.0.0", 9400), Handler).serve_forever()
'''

PROMETHEUS_CONFIG = f"""global:
  scrape_interval: {SCRAPE_INTERVAL_SECONDS}s
  scrape_timeout: 1s
  evaluation_interval: {SCRAPE_INTERVAL_SECONDS}s
scrape_configs:
  - job_name: credential-empty-baseline
    metrics_path: /baseline
    static_configs:
      - targets: ['{EXPORTER}:9400']
  - job_name: credential-metadata-fixture
    metrics_path: /metrics
    static_configs:
      - targets: ['{EXPORTER}:9400']
"""

EXPECTED_METRICS = {
    "saf_credential_issuance_events_in_window": 4,
    "saf_credential_issuance_window_seconds": WINDOW_SECONDS,
    "saf_credential_issuance_rate_per_second": 4 / WINDOW_SECONDS,
    "saf_credential_ttl_mean_seconds": 5400,
    "saf_credential_ttl_observed_count": 3,
    "saf_credential_ttl_missing_count": 1,
    "saf_credential_orphan_records": 1,
    "saf_credential_inventory_records": 4,
    "saf_credential_orphan_rate": 0.25,
    "saf_credential_approved_scope_exceptions": 2,
    "saf_credential_duplicate_events_rejected": 1,
    "saf_credential_unapproved_events_rejected": 1,
}


def labels(extra=None):
    return {"saf.example/control": CASE_ID, **(extra or {})}


def resources():
    fixture = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": f"{EXPORTER}-fixture", "labels": labels()},
        "data": {"events.json": json.dumps(EVENTS, sort_keys=True)},
    }
    config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": f"{PROMETHEUS}-config", "labels": labels()},
        "data": {"prometheus.yml": PROMETHEUS_CONFIG},
    }
    exporter = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": EXPORTER, "labels": labels()},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": EXPORTER}},
                 "template": {"metadata": {"labels": {"app": EXPORTER, **labels()}},
                              "spec": {"automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True,
                                                            "runAsUser": 65534},
                                       "containers": [{"name": "metadata-exporter",
                                                       "image": PYTHON_IMAGE,
                                                       "command": ["python", "-u", "-c", EXPORTER_SERVER],
                                                       "ports": [{"name": "metrics", "containerPort": 9400}],
                                                       "securityContext": {"allowPrivilegeEscalation": False,
                                                                           "readOnlyRootFilesystem": True},
                                                       "volumeMounts": [{"name": "fixture",
                                                                         "mountPath": "/fixture",
                                                                         "readOnly": True}]}],
                                       "volumes": [{"name": "fixture", "configMap":
                                                    {"name": f"{EXPORTER}-fixture"}}]}}},
    }
    exporter_service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": EXPORTER, "labels": labels()},
        "spec": {"selector": {"app": EXPORTER},
                 "ports": [{"name": "metrics", "port": 9400, "targetPort": 9400}]},
    }
    prom = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": PROMETHEUS, "labels": labels()},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": PROMETHEUS}},
                 "template": {"metadata": {"labels": {"app": PROMETHEUS, **labels()}},
                              "spec": {"automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True,
                                                            "runAsUser": 65534,
                                                            "fsGroup": 65534},
                                       "containers": [{"name": "prometheus",
                                                       "image": PROMETHEUS_IMAGE,
                                                       "args": ["--config.file=/etc/fixture/prometheus.yml",
                                                                "--storage.tsdb.path=/prometheus",
                                                                "--web.listen-address=:9090",
                                                                "--storage.tsdb.retention.time=1h"],
                                                       "ports": [{"name": "web", "containerPort": 9090}],
                                                       "volumeMounts": [{"name": "config",
                                                                         "mountPath": "/etc/fixture",
                                                                         "readOnly": True},
                                                                        {"name": "data",
                                                                         "mountPath": "/prometheus"}]}],
                                       "volumes": [{"name": "config", "configMap":
                                                    {"name": f"{PROMETHEUS}-config"}},
                                                   {"name": "data", "emptyDir": {}}]}}},
    }
    prom_service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": PROMETHEUS, "labels": labels()},
        "spec": {"selector": {"app": PROMETHEUS},
                 "ports": [{"name": "web", "port": 9090, "targetPort": 9090}]},
    }
    return [fixture, config, exporter, exporter_service, prom, prom_service]


def wait_ready(lab, name):
    lab.kubectl("wait", "--for=condition=Available", f"deployment/{name}",
                "--timeout=120s", timeout=125)


def query(lab, expression):
    path = (f"/api/v1/namespaces/{NAMESPACE}/services/http:{PROMETHEUS}:web/proxy"
            f"/api/v1/query?query={quote_plus(expression)}")
    result = lab.kubectl("get", f"--raw={path}", allow_failure=True, timeout=15)
    if result.returncode:
        return None
    response = json.loads(result.stdout)
    if response.get("status") != "success":
        lab.block("The case-owned Prometheus query API returned an error")
    return response["data"]["result"]


def wait_for_scrape(lab):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        results = query(lab, 'up{job=~"credential-(empty-baseline|metadata-fixture)"}') or []
        observed = {item["metric"].get("job"): item["value"][1] for item in results}
        if observed == {"credential-empty-baseline": "1", "credential-metadata-fixture": "1"}:
            return
        time.sleep(0.5)
    lab.block("Prometheus did not scrape the case-owned metrics endpoint")


def one_value(lab, expression):
    result = query(lab, expression)
    if result is None or len(result) != 1:
        return None
    return float(result[0]["value"][1])


def check_active_targets(lab):
    path = (f"/api/v1/namespaces/{NAMESPACE}/services/http:{PROMETHEUS}:web/proxy"
            "/api/v1/targets?state=active")
    result = lab.kubectl("get", f"--raw={path}", timeout=15)
    response = json.loads(result.stdout)
    if response.get("status") != "success":
        lab.block("The case-owned Prometheus target API returned an error")
    targets = response["data"].get("activeTargets", [])
    observed = sorted((item.get("labels", {}).get("job"),
                       item.get("discoveredLabels", {}).get("__address__"),
                       item.get("scrapeUrl", "").rsplit("/", 1)[-1], item.get("health"))
                      for item in targets)
    expected = sorted([
        ("credential-empty-baseline", f"{EXPORTER}:9400", "baseline", "up"),
        ("credential-metadata-fixture", f"{EXPORTER}:9400", "metrics", "up"),
    ])
    lab.check("positive", "Live Prometheus target inventory contains only the two in-cluster fixture paths",
              observed == expected,
              {"active_targets": observed, "external_targets": 0})


def run(lab):
    # This is a fixture inspection only: every field is synthetic metadata and
    # no credential value, secret material, or backend API is represented.
    lab.check("positive", "Prometheus scrape targets are only the in-cluster fixture Service",
              PROMETHEUS_CONFIG.count(f"targets: ['{EXPORTER}:9400']") == 2
              and "http://" not in PROMETHEUS_CONFIG
              and "https://" not in PROMETHEUS_CONFIG,
              {"scrape_interval_seconds": SCRAPE_INTERVAL_SECONDS,
               "target": f"{EXPORTER}:9400", "external_targets": 0})
    for obj in resources():
        lab.create(obj)
    wait_ready(lab, EXPORTER)
    wait_ready(lab, PROMETHEUS)
    wait_for_scrape(lab)
    check_active_targets(lab)

    baseline = query(lab, 'saf_credential_issuance_events_in_window{job="credential-empty-baseline"}')
    lab.check("red", "Empty baseline publishes no credential issuance sample",
              baseline == [], {"baseline_series": baseline})

    observed = {}
    for name in EXPECTED_METRICS:
        value = one_value(lab, f'{name}{{job="credential-metadata-fixture",case_id="{CASE_ID}"}}')
        observed[name] = value
    exact = all(observed[name] is not None and abs(observed[name] - expected) < 1e-9
                for name, expected in EXPECTED_METRICS.items())
    lab.check("green", "Prometheus query matches synthetic metadata totals, units, and policy exclusions",
              exact,
              {"window_seconds": WINDOW_SECONDS, "issuance_events": observed.get(
                  "saf_credential_issuance_events_in_window"),
               "issuance_rate_events_per_second": observed.get(
                   "saf_credential_issuance_rate_per_second"),
               "mean_ttl_seconds": observed.get("saf_credential_ttl_mean_seconds"),
               "ttl_observed_count": observed.get("saf_credential_ttl_observed_count"),
               "ttl_missing_count": observed.get("saf_credential_ttl_missing_count"),
               "orphan_numerator": observed.get("saf_credential_orphan_records"),
               "orphan_denominator": observed.get("saf_credential_inventory_records"),
               "orphan_rate": observed.get("saf_credential_orphan_rate"),
               "approved_exception_count": observed.get(
                   "saf_credential_approved_scope_exceptions"),
               "duplicate_rejected": observed.get("saf_credential_duplicate_events_rejected"),
               "unapproved_rejected": observed.get("saf_credential_unapproved_events_rejected")})

    # Enforce the low-cardinality, metadata-only publication contract using
    # Prometheus series labels: case_id is the only producer label.
    producer_series = query(lab, f'{{job="credential-metadata-fixture",case_id="{CASE_ID}"}}') or []
    observed_names = {item["metric"].get("__name__") for item in producer_series}
    labels_ok = (observed_names == set(EXPECTED_METRICS)
                 and len(producer_series) == len(EXPECTED_METRICS)
                 and all(set(item["metric"]) == {"__name__", "job", "instance", "case_id"}
                         and item["metric"].get("case_id") == CASE_ID
                         for item in producer_series))
    lab.check("positive", "Published series contain only bounded case/job/instance labels",
              labels_ok, {"producer_labels": ["case_id"], "event_or_credential_labels": 0})
