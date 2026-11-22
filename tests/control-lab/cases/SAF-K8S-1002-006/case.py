"""Exercise Prometheus metric ingestion and safe summary queries on fixtures."""
import json
import time

from fixtures import container, pod, ready

NAMESPACE = "saf-test"
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
PROMETHEUS_IMAGE = "prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
SCOPE = (
    "A disposable Kind v1.36.1 cluster checks a digest-pinned Prometheus 3.5.0 and synthetic "
    "training metrics. A recording rule aggregates labels while the original remains queryable. "
    "Metric relabeling stops new detail samples, and the same Prometheus process retains "
    "history while reporting changing safe aggregates. Deployed endpoints, authentication, "
    "label hashing, remote stores and historical remediation require separate evidence."
)

PROM = "saf1002-prom"
EXPORTER = "saf1002-fixtures"


def apply(lab, obj):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(obj, separators=(",", ":")))


def scrape_config(drop_sensitive):
    relabel = (
        "    metric_relabel_configs:\n"
        "      - source_labels: [__name__]\n"
        "        regex: 'saf_training_detail_seconds'\n"
        "        action: drop\n"
        if drop_sensitive else ""
    )
    return f'''global:
  scrape_interval: 2s
  evaluation_interval: 2s
rule_files: [/etc/prometheus/rules.yml]
scrape_configs:
  - job_name: synthetic
    metrics_path: /metrics
    params:
      phase: ['{'red' if not drop_sensitive else 'green'}']
    static_configs:
      - targets: ['{EXPORTER}:8080']
{relabel}'''


def rules():
    return '''groups:
  - name: safe-training-summary
    interval: 2s
    rules:
      - record: saf_training_summary_seconds
        expr: sum by (case_marker, cohort) (saf_training_detail_seconds)
'''


def deploy(lab):
    # Static fixture exposition: names and labels are invented and contain no secrets.
    content = '''from http.server import BaseHTTPRequestHandler, HTTPServer
BODY = b\"\"\"# HELP saf_training_detail_seconds Synthetic training duration\n# TYPE saf_training_detail_seconds gauge\nsaf_training_detail_seconds{case_marker=\\\"red-006\\\",cohort=\\\"alpha\\\",gpu_uuid=\\\"GPU_FIXTURE_A\\\",nvlink_group=\\\"fabric_A\\\",learning_rate=\\\"0.0017\\\",batch_shape=\\\"shape_A\\\"} 7\nsaf_training_detail_seconds{case_marker=\\\"red-006\\\",cohort=\\\"alpha\\\",gpu_uuid=\\\"GPU_FIXTURE_B\\\",nvlink_group=\\\"fabric_B\\\",learning_rate=\\\"0.0017\\\",batch_shape=\\\"shape_A\\\"} 11\nsaf_training_detail_seconds{case_marker=\\\"red-006\\\",cohort=\\\"beta\\\",gpu_uuid=\\\"GPU_FIXTURE_C\\\",nvlink_group=\\\"fabric_C\\\",learning_rate=\\\"0.0041\\\",batch_shape=\\\"shape_B\\\"} 5\n# HELP saf_training_safe_seconds Synthetic pre-aggregated safe summary\n# TYPE saf_training_safe_seconds gauge\nsaf_training_safe_seconds{case_marker=\\\"red-006\\\",cohort=\\\"alpha\\\"} 18\nsaf_training_safe_seconds{case_marker=\\\"red-006\\\",cohort=\\\"beta\\\"} 5\n\"\"\"
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  body = BODY.replace(b'red-006', b'green-006').replace(b' 7\\n', b' 13\\n').replace(b' 11\\n', b' 17\\n').replace(b' 5\\n', b' 9\\n').replace(b' 18\\n', b' 30\\n') if 'phase=green' in self.path else BODY
  self.send_response(200); self.send_header('Content-Type','text/plain; version=0.0.4'); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
HTTPServer(('0.0.0.0',8080),H).serve_forever()
'''
    apply(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": EXPORTER, "namespace": NAMESPACE},
                "data": {"server.py": content}})
    apply(lab, {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": EXPORTER, "namespace": NAMESPACE},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": EXPORTER}},
                         "template": {"metadata": {"labels": {"app": EXPORTER}}, "spec": {
                             "automountServiceAccountToken": False,
                             "containers": [{"name": "fixture", "image": "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
                                             "command": ["python", "/fixture/server.py"], "ports": [{"containerPort": 8080}],
                                             "readinessProbe": {"tcpSocket": {"port": 8080}, "periodSeconds": 2},
                                             "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                                             "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}],
                             "volumes": [{"name": "fixture", "configMap": {"name": EXPORTER}}]}}}})
    apply(lab, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": EXPORTER, "namespace": NAMESPACE},
                "spec": {"selector": {"app": EXPORTER}, "ports": [{"port": 8080, "targetPort": 8080}]}})
    config = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": PROM + "-config", "namespace": NAMESPACE},
              "data": {"prometheus.yml": scrape_config(False), "rules.yml": rules()}}
    apply(lab, config)
    apply(lab, {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": PROM, "namespace": NAMESPACE},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": PROM}}, "template": {
                    "metadata": {"labels": {"app": PROM}}, "spec": {"automountServiceAccountToken": False,
                    "securityContext": {"fsGroup": 65534},
                    "containers": [{"name": "prometheus", "image": PROMETHEUS_IMAGE,
                        "args": ["--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus",
                                 "--web.enable-lifecycle", "--storage.tsdb.retention.time=1h"],
                        "ports": [{"containerPort": 9090}],
                        "readinessProbe": {"httpGet": {"path": "/-/ready", "port": 9090}, "periodSeconds": 2}, "volumeMounts": [
                            {"name": "config", "mountPath": "/etc/prometheus", "readOnly": True},
                            {"name": "data", "mountPath": "/prometheus"}],
                        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}],
                    "volumes": [{"name": "config", "configMap": {"name": PROM + "-config"}}, {"name": "data", "emptyDir": {}}]}}}})
    apply(lab, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": PROM, "namespace": NAMESPACE},
                "spec": {"selector": {"app": PROM}, "ports": [{"port": 9090, "targetPort": 9090}]}})
    lab.kubectl("wait", "--for=condition=Available", "deployment/" + EXPORTER, "--timeout=90s", timeout=100)
    lab.kubectl("wait", "--for=condition=Available", "deployment/" + PROM, "--timeout=90s", timeout=100)


def query(lab, expr):
    # The in-cluster Python client stores only API responses in evidence; no auth headers/secrets.
    code = '''import json,sys,urllib.parse,urllib.request
url='http://saf1002-prom:9090/api/v1/query?'+urllib.parse.urlencode({'query':sys.argv[1]})
with urllib.request.urlopen(url,timeout=10) as r: print(json.dumps(json.load(r),separators=(',',':')))
'''
    result = lab.kubectl("exec", PROM + "-client", "--", "python3", "-c", code, expr, timeout=30)
    return json.loads(result.stdout)


def wait_absent(lab, expr):
    response = None
    for _ in range(30):
        response = query(lab, expr)
        if response.get("status") == "success" and not response.get("data", {}).get("result"):
            return response
        time.sleep(1)
    return response


def wait_query(lab, expr, count):
    for _ in range(45):
        response = query(lab, expr)
        rows = response.get("data", {}).get("result", [])
        if response.get("status") == "success" and len(rows) == count:
            return response
        time.sleep(1)
    return response


def result_labels(response):
    return [row.get("metric", {}) for row in response.get("data", {}).get("result", [])]


def run(lab):
    deploy(lab)
    lab.create(pod(PROM + "-client", [container("client", image="docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")], automountServiceAccountToken=False))
    ready(lab, PROM + "-client")
    raw = 'saf_training_detail_seconds{case_marker="red-006"}'
    safe_source = 'saf_training_safe_seconds{case_marker="red-006"}'
    ruled = 'saf_training_summary_seconds{case_marker="red-006"}'
    red_raw = wait_query(lab, raw, 3)
    red_safe = wait_query(lab, safe_source, 2)
    red_rule = wait_query(lab, ruled, 2)
    for name, value in (("red-raw.json", red_raw), ("red-safe-source.json", red_safe), ("red-rule.json", red_rule)):
        (lab.evidence / name).write_text(json.dumps(value, indent=2) + "\n")
    labels = result_labels(red_raw)
    red_values = sorted(float(row["value"][1]) for row in red_safe.get("data", {}).get("result", []))
    rule_values = sorted(float(row["value"][1]) for row in red_rule.get("data", {}).get("result", []))
    raw_ok = (len(labels) == 3 and all({"gpu_uuid", "nvlink_group", "learning_rate", "batch_shape"} <= set(x) for x in labels))
    safe_ok = (len(result_labels(red_safe)) == 2 and all(not ({"gpu_uuid", "nvlink_group", "learning_rate", "batch_shape"} & set(x)) for x in result_labels(red_safe)))
    lab.check("red", "Raw synthetic series expose the fixture-only sensitive dimensions and safe source path retains useful cohort aggregates",
              raw_ok and safe_ok, {"raw_series": len(labels), "safe_series": len(result_labels(red_safe)), "raw_sensitive_labels_present": raw_ok, "safe_labels_minimized": safe_ok})
    rule_ok = (len(result_labels(red_rule)) == 2 and red_values == [5.0, 18.0] and rule_values == red_values
               and all(not ({"gpu_uuid", "nvlink_group", "learning_rate", "batch_shape"} & set(x)) for x in result_labels(red_rule))
               and len(result_labels(wait_query(lab, raw, 3))) == 3)
    lab.check("positive", "Recording rule emits a safe aggregate but leaves original raw series and labels queryable",
              rule_ok, {"safe_source_values": red_values, "recorded_values": rule_values,
                        "recorded_series": len(result_labels(red_rule)), "original_raw_series_still_queryable": rule_ok})

    baseline_time = red_raw["data"]["result"][0]["value"][0]
    before_pod = lab.kubectl("get", "pods", "-l", f"app={PROM}", "-o", "jsonpath={.items[0].metadata.uid}").stdout
    expected_config = scrape_config(True)
    # This is the deliberate, case-owned configuration change under test.
    config = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": PROM + "-config", "namespace": NAMESPACE},
              "data": {"prometheus.yml": scrape_config(True), "rules.yml": rules()}}
    apply(lab, config)
    deadline = time.monotonic() + 115
    while time.monotonic() < deadline:
        projected = lab.kubectl("exec", "deployment/" + PROM, "--", "cat",
                                "/etc/prometheus/prometheus.yml", timeout=15).stdout
        if projected == expected_config:
            break
        time.sleep(2)
    else:
        lab.block("The fixture ConfigMap projection did not reach Prometheus")
    lab.kubectl("exec", PROM + "-client", "--", "python3", "-c",
                 "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://saf1002-prom:9090/-/reload',data=b'',method='POST'),timeout=10).read()", timeout=30)
    # Scrape params select a second marker and different comparator values after reload.
    green_safe = wait_query(lab, 'saf_training_safe_seconds{case_marker="green-006"}', 2)
    green_raw = query(lab, 'saf_training_detail_seconds{case_marker="green-006"}')
    green_rule = query(lab, 'saf_training_summary_seconds{case_marker="green-006"}')
    for name, value in (("green-raw.json", green_raw), ("green-safe-source.json", green_safe), ("green-rule.json", green_rule)):
        (lab.evidence / name).write_text(json.dumps(value, indent=2) + "\n")
    # Old samples may remain inside the lookback window until Prometheus observes staleness.
    # Require the target's post-change scrape and distinguish stale old raw data from new ingestion.
    up = wait_query(lab, 'up{job="synthetic"}', 1)
    fresh = query(lab, 'saf_training_detail_seconds{case_marker="green-006"}')
    stale = wait_absent(lab, 'saf_training_detail_seconds{case_marker="red-006"}')
    summaries = result_labels(green_safe)
    values = sorted(float(row["value"][1]) for row in green_safe.get("data", {}).get("result", []))
    green_ok = (len(result_labels(fresh)) == 0 and len(result_labels(stale)) == 0 and len(summaries) == 2 and values == [9.0, 30.0]
                and all(not ({"gpu_uuid", "nvlink_group", "learning_rate", "batch_shape"} & set(x)) for x in summaries)
                and len(result_labels(green_rule)) == 0 and up.get("status") == "success"
                and up["data"]["result"][0]["value"][1] == "1")
    lab.check("green", "After metric_relabel_configs reload, new detail series and rule output disappear while the independent safe aggregate remains queryable",
              green_ok, {"fresh_raw_series": len(result_labels(fresh)), "safe_values": values,
                         "safe_source_labels_minimized": all(not ({"gpu_uuid", "nvlink_group", "learning_rate", "batch_shape"} & set(x)) for x in summaries),
                         "stale_red_marker_absent_from_instant_query": len(result_labels(stale)) == 0,
                         "recording_rule_output_after_detail_drop": len(result_labels(green_rule))})

    history = query(lab, f"{raw} @ {baseline_time}")
    after_pod = lab.kubectl("get", "pods", "-l", f"app={PROM}", "-o",
                           "jsonpath={.items[0].metadata.uid}").stdout
    historical_labels = result_labels(history)
    same_pod = bool(before_pod and before_pod == after_pod)
    (lab.evidence / "history.json").write_text(json.dumps({
        "before_pod_uid": before_pod, "after_pod_uid": after_pod, "evaluation_time": baseline_time,
        "historical_samples": history, "stale_instant_query": stale, "active_target": up,
    }, indent=2) + "\n")
    lab.check("positive", "The original detail remains in historical storage after forward-only relabeling",
              same_pod and len(historical_labels) == 3
              and all({"gpu_uuid", "nvlink_group", "learning_rate", "batch_shape"} <= set(labels)
                      for labels in historical_labels),
              {"same_prometheus_pod": same_pod, "historical_detail_samples": len(historical_labels)})
