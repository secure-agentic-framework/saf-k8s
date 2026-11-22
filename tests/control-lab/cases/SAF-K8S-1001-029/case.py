"""Exercise sink-side SIEM-ingestion completeness checks with synthetic file sources."""
import json
from pathlib import Path
import time

CASE_DIR = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
COLLECTOR_IMAGE = "cr.fluentbit.io/fluent/fluent-bit:5.1.2@sha256:d792375ca8e53be72fc25716c28f291f32c6fc6f4f31d12d0d14bc78cefe9226"
SINK_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCOPE = (
    "One ordinary runner-owned kind cluster and namespace; a case-owned Fluent Bit 5.1.2 "
    "collector tails two structured ConfigMap-backed fixture files and posts only to a "
    "case-owned HTTP evidence sink in that namespace. Synthetic event IDs model Kubernetes "
    "audit and AI security telemetry. The case compares source-level expected IDs and counts "
    "at the sink across complete, missing-source, partial-source, and recovered runs. It does "
    "not test native Kubernetes audit generation, an AI workload, production SIEM alerting, "
    "long-term retention, high availability, or sustained/load delivery."
)


def load_fixtures():
    return json.loads((CASE_DIR / "fixtures.json").read_text())


def collector_config(*, filtered_event=None):
    config = """service:\n  flush: 1\n  log_level: warn\npipeline:\n  inputs:\n    - name: tail\n      tag: synthetic.k8s.audit\n      path: /fixtures/k8s-audit.jsonl\n      parser: structured_json\n      read_from_head: true\n      refresh_interval: 1\n    - name: tail\n      tag: synthetic.ai.security\n      path: /fixtures/ai-security.jsonl\n      parser: structured_json\n      read_from_head: true\n      refresh_interval: 1\n  outputs:\n    - name: http\n      match: '*'\n      host: evidence-sink\n      port: 8080\n      uri: /ingest\n      format: json_lines\n      json_date_key: false\n      workers: 1\nparsers:\n  - name: structured_json\n    format: json\n"""


    if filtered_event:
        filters = ("  filters:\n"
                   "    - name: grep\n"
                   "      match: synthetic.ai.security\n"
                   f"      exclude: event_id ^{filtered_event}$\n")
        config = config.replace("  outputs:\n", filters + "  outputs:\n")
    return config


def sink_program():
    return r'''from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path

STORE = Path("/data/events.jsonl")
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ready")
    def do_POST(self):
        if self.path != "/ingest":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > 1048576:
            self.send_error(413)
            return
        body = self.rfile.read(length).decode("utf-8")
        try:
            records = [json.loads(line) for line in body.splitlines() if line.strip()]
            if not records or any(not isinstance(record, dict) for record in records):
                raise ValueError("expected JSON objects")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.send_error(400)
            return
        with STORE.open("a", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        self.send_response(201)
        self.end_headers()
        self.wfile.write(b"accepted")
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def source_configmap(run_id, source_events):
    data = {}
    for source, events in source_events.items():
        if events is None:
            continue
        filename = "k8s-audit.jsonl" if source == "synthetic-k8s-audit" else "ai-security.jsonl"
        records = [dict(event, run_id=run_id) for event in events]
        data[filename] = "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n"
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "synthetic-source-files", "namespace": NAMESPACE},
        "data": data,
    }


def collector_pod(name):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": {"app": name}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "fluent-bit", "image": COLLECTOR_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "args": ["-c", "/fluent-bit/etc/fluent-bit.yaml"],
                "volumeMounts": [
                    {"name": "config", "mountPath": "/fluent-bit/etc/fluent-bit.yaml",
                     "subPath": "fluent-bit.yaml", "readOnly": True},
                    {"name": "sources", "mountPath": "/fixtures", "readOnly": True},
                ],
            }],
            "volumes": [
                {"name": "config", "configMap": {"name": "fluent-bit-config"}},
                {"name": "sources", "configMap": {"name": "synthetic-source-files"}},
            ],
        },
    }


def bootstrap_sink(lab):
    lab.kubectl("apply", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "evidence-sink-code", "namespace": NAMESPACE},
        "data": {"sink.py": sink_program()},
    }))
    lab.kubectl("apply", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "evidence-sink", "namespace": NAMESPACE,
                      "labels": {"app": "evidence-sink"}},
        "spec": {
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "sink", "image": SINK_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-u", "/app/sink.py"],
                "ports": [{"name": "http", "containerPort": 8080}],
                "volumeMounts": [
                    {"name": "code", "mountPath": "/app", "readOnly": True},
                    {"name": "data", "mountPath": "/data"},
                ],
            }],
            "volumes": [
                {"name": "code", "configMap": {"name": "evidence-sink-code"}},
                {"name": "data", "emptyDir": {}},
            ],
        },
    }))
    lab.kubectl("apply", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "evidence-sink", "namespace": NAMESPACE},
        "spec": {"selector": {"app": "evidence-sink"},
                 "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]},
    }))
    lab.kubectl("wait", "--for=condition=Ready", "pod/evidence-sink", "--timeout=90s", timeout=100)


def sink_records(lab):
    code = "import json,pathlib; p=pathlib.Path('/data/events.jsonl'); print(json.dumps([json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []))"
    result = lab.kubectl("exec", "pod/evidence-sink", "--", "python", "-c", code)
    return json.loads(result.stdout)


def phase_records(records, run_id):
    return [record for record in records if record.get("run_id") == run_id]


def source_summary(records):
    summary = {}
    for record in records:
        source = record.get("source_id", "<missing>")
        item = summary.setdefault(source, {"count": 0, "event_ids": []})
        item["count"] += 1
        item["event_ids"].append(record.get("event_id"))
    for item in summary.values():
        item["event_ids"].sort()
    return summary


def expected_for(k8s_events, ai_events):
    return {
        "synthetic-k8s-audit": sorted(event["event_id"] for event in k8s_events),
        "synthetic-ai-security": sorted(event["event_id"] for event in ai_events),
    }


def compare(expected, observed):
    if set(observed) - set(expected):
        raise ValueError("Sink reported an unexpected source in the case scope")
    result = {}
    for source, event_ids in expected.items():
        got = sorted(observed.get(source, {}).get("event_ids", []))
        if got == event_ids:
            state = "complete"
        elif not got:
            state = "missing_source"
        else:
            state = "partial_delivery"
        result[source] = {
            "expected_count": len(event_ids), "observed_count": len(got),
            "expected_event_ids": event_ids, "observed_event_ids": got,
            "state": state,
        }
    return result


def run_phase(lab, run_id, source_events, expected, *, filtered_event=None):
    lab.kubectl("apply", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "fluent-bit-config", "namespace": NAMESPACE},
        "data": {"fluent-bit.yaml": collector_config(filtered_event=filtered_event)},
    }))
    lab.kubectl("apply", "-f", "-", payload=json.dumps(source_configmap(run_id, source_events)))
    name = "collector-" + run_id
    lab.kubectl("apply", "-f", "-", payload=json.dumps(collector_pod(name)))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s", timeout=100)
    deadline = time.monotonic() + 40
    observed_records = []
    expected_ids = {event_id for ids in expected.values() for event_id in ids}
    while time.monotonic() < deadline:
        observed_records = phase_records(sink_records(lab), run_id)
        observed_ids = {record.get("event_id") for record in observed_records}
        if expected_ids.issubset(observed_ids):
            break
        time.sleep(1)
    # Let any duplicate or extra flush become visible before taking the settled snapshot.
    time.sleep(2)
    observed_records = phase_records(sink_records(lab), run_id)
    lab.kubectl("delete", "pod", name, "--wait=true", "--timeout=30s")
    return source_summary(observed_records)


def run(lab):
    fixtures = load_fixtures()
    sources = fixtures["sources"]
    expected_counts = fixtures["expected_counts_per_run"]
    fixture_counts = {"synthetic-k8s-audit": len(sources["k8s_audit"]),
                      "synthetic-ai-security": len(sources["ai_security"])}
    if expected_counts != fixture_counts:
        lab.block("Fixture source records and expected counts disagree")

    bootstrap_sink(lab)
    baseline_id = "healthy-baseline"
    baseline_expected = expected_for(sources["k8s_audit"], sources["ai_security"])
    baseline = run_phase(lab, baseline_id, {
        "synthetic-k8s-audit": sources["k8s_audit"],
        "synthetic-ai-security": sources["ai_security"],
    }, baseline_expected)
    baseline_comparison = compare(baseline_expected, baseline)
    baseline_ok = all(item["state"] == "complete" and
                      item["observed_count"] == expected_counts[source]
                      for source, item in baseline_comparison.items())
    lab.check("positive", "Both expected structured feeds reach the local sink once per event ID",
              baseline_ok, baseline_comparison)

    missing_id = "missing-ai-source"
    missing_expected = expected_for(sources["k8s_audit"], sources["ai_security"])
    missing = run_phase(lab, missing_id, {
        "synthetic-k8s-audit": sources["k8s_audit"],
        "synthetic-ai-security": None,
    }, {"synthetic-k8s-audit": missing_expected["synthetic-k8s-audit"]})
    # Include the expected but absent source when classifying sink observations.
    missing_comparison = compare(missing_expected, missing)
    missing_detected = (
        missing_comparison["synthetic-k8s-audit"]["state"] == "complete"
        and missing_comparison["synthetic-ai-security"]["state"] == "missing_source"
    )
    lab.check("red", "A case-owned missing source produces a sink-side coverage gap against the declared baseline",
              missing_detected, missing_comparison)

    partial_id = "partial-ai-delivery"
    partial_expected = expected_for(sources["k8s_audit"], sources["ai_security"])
    omitted = sources["ai_security"][1]["event_id"]
    partial = run_phase(lab, partial_id, {
        "synthetic-k8s-audit": sources["k8s_audit"],
        "synthetic-ai-security": sources["ai_security"],
    }, {**partial_expected, "synthetic-ai-security": [sources["ai_security"][0]["event_id"]]},
        filtered_event=omitted)
    partial_comparison = compare(partial_expected, partial)
    partial_detected = (
        partial_comparison["synthetic-k8s-audit"]["state"] == "complete"
        and partial_comparison["synthetic-ai-security"]["state"] == "partial_delivery"
        and partial_comparison["synthetic-ai-security"]["observed_event_ids"]
        == [sources["ai_security"][0]["event_id"]]
    )
    lab.check("green", "The sink comparison detects the exact event excluded by the collector from a complete source file",
              partial_detected, partial_comparison)

    recovery_id = "healthy-recovery"
    recovery_expected = expected_for(sources["k8s_audit"], sources["ai_security"])
    recovery = run_phase(lab, recovery_id, {
        "synthetic-k8s-audit": sources["k8s_audit"],
        "synthetic-ai-security": sources["ai_security"],
    }, recovery_expected)
    recovery_comparison = compare(recovery_expected, recovery)
    recovered = all(item["state"] == "complete" and
                    item["observed_count"] == expected_counts[source]
                    for source, item in recovery_comparison.items())
    lab.check("green", "Restoring the collector configuration returns both feeds to their exact healthy state",
              recovered, recovery_comparison)
