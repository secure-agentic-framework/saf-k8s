"""Verify GitOps collection history and distinct owned alert lifecycles."""
import importlib.util
import json
import time
from pathlib import Path
from urllib.parse import urlencode

HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0606-031"
SCOPE = (
    "One disposable Kind cluster, pinned Argo CD, Prometheus and Alertmanager. The fixture "
    "exercises native reconciliation status, difference between failed reconciliation and missing "
    "telemetry, retained history on a persistent volume through a Prometheus replacement, "
    "and delivered firing and resolved notifications on the two owned alert paths."
)
PROM = "saf-gitops-prometheus"
AM = "saf-gitops-alertmanager"
RECEIVER = "saf-gitops-receiver"
APP = "saf-health-fixture"
ARGO = "argocd-metrics.argocd.svc.cluster.local:8082"
PROM_IMAGE = ("docker.io/prom/prometheus:v3.5.0@sha256:"
              "63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996")
AM_IMAGE = ("docker.io/prom/alertmanager:v0.28.1@sha256:"
            "27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba")
PY_IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
            "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
UNKNOWN = "GitOpsReconcileUnknown"
MISSING = "GitOpsTelemetryMissing"

RECEIVER_SOURCE = r'''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock
events, lock = [], Lock()
class Handler(BaseHTTPRequestHandler):
 def send(self, value):
  data=json.dumps(value).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
 def do_GET(self):
  if self.path != "/events": self.send_error(404); return
  with lock: self.send(list(events))
 def do_POST(self):
  n=int(self.headers.get("Content-Length",0))
  if self.path != "/notify" or not 0<n<=32768: self.send_error(400); return
  try:
   item=json.loads(self.rfile.read(n))
   if item.get("version")!="4" or not isinstance(item.get("alerts"),list): raise ValueError()
  except Exception: self.send_error(400); return
  with lock: events.append(item)
  self.send({"accepted":True})
 def log_message(self,*args): pass
ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
'''


def json_url(lab, url):
    # Use the pinned Python receiver as an independent HTTP client inside the
    # cluster; this does not rely on a local port-forward or browser cache.
    script = ("import sys,urllib.request; ")
    script += "print(urllib.request.urlopen(sys.argv[1],timeout=5).read().decode())"
    result = lab.kubectl("-n", "saf-test", "exec", f"deployment/{RECEIVER}", "--",
                         "python", "-c", script, url, allow_failure=True, timeout=12)
    return json.loads(result.stdout) if result.returncode == 0 else None


def query(lab, expression):
    response = json_url(lab, f"http://{PROM}:9090/api/v1/query?{urlencode({'query': expression})}")
    if not response or response.get("status") != "success":
        return None
    return response["data"]["result"]


def with_labels(selector, labels):
    return selector[:-1] + "," + labels + "}"


def wait_for(probe, timeout=120, interval=2):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = probe()
        if value:
            return value
        time.sleep(interval)
    return None


def config_text():
    prometheus = {
        "global": {"scrape_interval": "2s", "evaluation_interval": "2s"},
        "rule_files": ["/saf/rules.json"],
        "scrape_configs": [{"job_name": "argocd-fixture", "static_configs": [
            {"targets": [ARGO], "labels": {"scope": "fixture"}}]}],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": [f"{AM}:9093"]}]}]}}
    rules = {"groups": [{"name": "gitops-fixture", "rules": [
        {"alert": UNKNOWN,
         "expr": f'argocd_app_info{{name="{APP}",namespace="argocd",sync_status="Unknown"}} == 1',
         "for": "4s", "labels": {"severity": "warning", "scope": "fixture"},
         "annotations": {"summary": "Owned fixture reconciliation is Unknown"}},
        {"alert": MISSING,
         "expr": f'absent_over_time(argocd_app_info{{name="{APP}",namespace="argocd"}}[12s])',
         "labels": {"severity": "warning", "scope": "fixture"},
         "annotations": {"summary": "Owned fixture reconciliation telemetry is missing"}},
    ]}]}
    alertmanager = {"route": {"receiver": "discard", "group_by": ["alertname", "name"],
        "group_wait": "1s", "group_interval": "2s", "routes": [
            {"matchers": ['scope="fixture"'], "receiver": "fixture-webhook"}]},
        "receivers": [{"name": "discard"}, {"name": "fixture-webhook",
            "webhook_configs": [{"url": f"http://{RECEIVER}:8080/notify", "send_resolved": True}]}]}
    return {"prometheus.json": json.dumps(prometheus), "rules.json": json.dumps(rules),
            "alertmanager.json": json.dumps(alertmanager), "receiver.py": RECEIVER_SOURCE}


def deploy(lab, name, image, args, port, config_name, config_key, mount_path,
           data_mount=None, persistent_data=None, command=None):
    selector = {"app": name}
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": "saf-test"},
        "spec": {"replicas": 1, "selector": {"matchLabels": selector}, "template": {
            "metadata": {"labels": selector}, "spec": {"automountServiceAccountToken": False,
            "containers": [{"name": "app", "image": image, "args": args,
                **({"command": command} if command else {}),
                "readinessProbe": {"httpGet": {"path": "/events" if name == RECEIVER else "/-/ready",
                                               "port": port}, "periodSeconds": 2},
                "ports": [{"containerPort": port}], "volumeMounts": [
                    {"name": "config", "mountPath": mount_path, "readOnly": True}]
                    + ([{"name": "data", "mountPath": data_mount}] if data_mount else []),
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "15m", "memory": "24Mi"},
                              "limits": {"cpu": "500m", "memory": "256Mi"}}}],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534, "fsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "config", "configMap": {"name": config_name,
                **({"items": [{"key": config_key, "path": config_key}]}
                   if config_key else {})}}]
                 + ([{"name": "data", "persistentVolumeClaim": {"claimName": persistent_data}}]
                   if persistent_data else [{"name": "data", "emptyDir": {}}] if data_mount else [])}}}})
    lab.create({"apiVersion": "v1", "kind": "Service",
        "metadata": {"name": name, "namespace": "saf-test"},
        "spec": {"selector": selector, "ports": [{"port": port, "targetPort": port}]}})
    lab.kubectl("-n", "saf-test", "rollout", "status", f"deployment/{name}",
                "--timeout=120s", timeout=130)


def install_monitor(lab, files=None):
    if files is None:
        files = config_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-gitops-monitor-config", "namespace": "saf-test"},
        "data": {key: value for key, value in files.items() if key != "receiver.py"}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-gitops-receiver-config", "namespace": "saf-test"},
        "data": {"receiver.py": files["receiver.py"]}})
    deploy(lab, RECEIVER, PY_IMAGE, ["/saf/receiver.py"], 8080,
           "saf-gitops-receiver-config", "receiver.py", "/saf", command=["python", "-u"])
    deploy(lab, AM, AM_IMAGE, ["--config.file=/saf/alertmanager.json", "--cluster.listen-address="],
           9093, "saf-gitops-monitor-config", "alertmanager.json", "/saf",
           data_mount="/alertmanager")
    lab.create({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {"name": PROM}, "spec": {"accessModes": ["ReadWriteOnce"],
                    "resources": {"requests": {"storage": "128Mi"}}}})
    deploy(lab, PROM, PROM_IMAGE,
           ["--config.file=/saf/prometheus.json", "--storage.tsdb.path=/prometheus",
            "--storage.tsdb.retention.time=24h"],
           9090, "saf-gitops-monitor-config", None, "/saf", data_mount="/prometheus", persistent_data=PROM)


def alerts(lab):
    response = json_url(lab, f"http://{PROM}:9090/api/v1/alerts")
    return response.get("data", {}).get("alerts", []) if response else []


def matching_notifications(lab, alert_name):
    events = json_url(lab, f"http://{RECEIVER}:8080/events") or []
    return [(event.get("receiver"), alert.get("labels", {}).get("alertname"),
             alert.get("labels", {}).get("name"), alert.get("labels", {}).get("namespace"),
             alert.get("labels", {}).get("scope"), alert.get("labels", {}).get("severity"),
             alert.get("annotations", {}).get("summary"), alert.get("status"),
             bool(alert.get("startsAt")), bool(alert.get("endsAt")))
            for event in events for alert in event.get("alerts", [])
            if alert.get("labels", {}).get("alertname") == alert_name]


def run(lab):
    source = HERE.parent / "case.py"
    spec = importlib.util.spec_from_file_location("saf_base_0606_031", source)
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    base.run(lab)
    install_monitor(lab)

    metric = f'argocd_app_info{{name="{APP}",namespace="argocd"}}'
    healthy_selector = with_labels(metric, 'sync_status="Synced",health_status="Healthy"')
    healthy = wait_for(lambda: query(lab, healthy_selector))
    def collected_three():
        samples = query(lab, f"count_over_time({healthy_selector}[12s])") or []
        return any(float(sample["value"][1]) >= 3 for sample in samples)
    repeated = wait_for(collected_three)
    targets = json_url(lab, f"http://{PROM}:9090/api/v1/targets")
    target_ok = bool(targets and any(t.get("labels", {}).get("job") == "argocd-fixture"
                                     and t.get("health") == "up"
                                     for t in targets["data"]["activeTargets"]))
    lab.check("positive", "Pinned Prometheus repeatedly collects the exact healthy Argo CD fixture metric",
              bool(healthy) and target_ok and repeated,
              {"instant_metric_present": bool(healthy), "three_actual_samples_seen": bool(repeated),
               "target_up": target_ok})

    start = int(time.time()) - 8
    baseline_workload = base.workload_observation(lab)
    lab.kubectl("-n", "argocd", "patch", "application", APP, "--type=merge",
                "-p", json.dumps({"spec": {"source": {"path": base.MISSING_PATH}}}))
    unknown_selector = with_labels(metric, 'sync_status="Unknown"')
    failed = wait_for(lambda: (query(lab, unknown_selector)
                               if query(lab, unknown_selector)
                               and any(a.get("labels", {}).get("alertname") == UNKNOWN
                                       and a.get("state") == "firing" for a in alerts(lab)) else None), 180)
    delivered_firing = wait_for(lambda: [n for n in matching_notifications(lab, UNKNOWN)
        if n[0:7] == ("fixture-webhook", UNKNOWN, APP, "argocd", "fixture", "warning",
                      "Owned fixture reconciliation is Unknown") and n[7] == "firing"], 60)
    failed_app = base.application(lab)
    failed_workload = base.workload_observation(lab)
    comparison_error = any(condition.get("type") == "ComparisonError"
                           and base.MISSING_PATH in condition.get("message", "")
                           for condition in failed_app.get("status", {}).get("conditions", []))
    lab.check("green", "Present Unknown status fires and delivers while the prior workload remains",
              bool(failed and delivered_firing and comparison_error
                   and failed_workload == baseline_workload),
              {"unknown_metric_present": bool(failed), "comparison_error_named": comparison_error,
               "workload_unchanged": failed_workload == baseline_workload,
               "firing_webhook": delivered_firing[0] if delivered_firing else None})

    lab.kubectl("-n", "argocd", "patch", "application", APP, "--type=merge",
                "-p", json.dumps({"spec": {"source": {"path": "source"}}}))
    recovered = wait_for(lambda: query(lab, healthy_selector), 240)
    resolved = wait_for(lambda: [n for n in matching_notifications(lab, UNKNOWN)
        if n[0:7] == ("fixture-webhook", UNKNOWN, APP, "argocd", "fixture", "warning",
                      "Owned fixture reconciliation is Unknown") and n[7] == "resolved"], 90)
    end = int(time.time())
    history_params = urlencode({"query": metric, "start": start, "end": end, "step": "2s"})
    range_url = f"http://{PROM}:9090/api/v1/query_range?{history_params}"
    def history():
        result = json_url(lab, range_url)
        if result and result.get("status") == "success" and result["data"]["result"]:
            return result
        return None

    history_before = wait_for(history)
    def storage_identity():
        claim = json.loads(lab.kubectl("get", "pvc", PROM, "-o", "json").stdout)
        pods = json.loads(lab.kubectl("get", "pods", "-l", f"app={PROM}", "-o", "json").stdout)
        ready = [p["metadata"]["uid"] for p in pods["items"]
                 if not p["metadata"].get("deletionTimestamp")
                 and any(c["type"] == "Ready" and c["status"] == "True"
                         for c in p.get("status", {}).get("conditions", []))]
        if claim["status"]["phase"] == "Bound" and len(ready) == 1:
            return claim["spec"]["volumeName"], ready[0]
        return None
    original_storage = wait_for(storage_identity)
    if not original_storage:
        lab.block("Prometheus has no single Ready Pod mounted to a bound fixture claim")
    lab.kubectl("scale", f"deployment/{PROM}", "--replicas=0")
    lab.kubectl("wait", "--for=delete", "pod", "-l", f"app={PROM}", "--timeout=90s", timeout=100)
    lab.kubectl("scale", f"deployment/{PROM}", "--replicas=1")
    lab.kubectl("rollout", "status", f"deployment/{PROM}", "--timeout=90s", timeout=100)
    replacement_storage = wait_for(storage_identity)
    history_after = wait_for(history)
    history_points = sorted(
        (float(sample[0]), row.get("metric", {}).get("sync_status"))
        for row in (history_after or {}).get("data", {}).get("result", [])
        for sample in row.get("values", []))
    states = []
    for _, state in history_points:
        if state and (not states or states[-1] != state):
            states.append(state)
    ordered_history = any(states[index:index + 3] == ["Synced", "Unknown", "Synced"]
                          for index in range(max(0, len(states) - 2)))
    same_volume = bool(replacement_storage and replacement_storage[0] == original_storage[0])
    new_pod = bool(replacement_storage and replacement_storage[1] != original_storage[1])
    same_history = bool(history_before and history_before == history_after)
    recovered_app = base.application(lab)
    recovered_revision = recovered_app.get("status", {}).get("sync", {}).get("revision")
    still_approved = recovered_revision == recovered_app["spec"]["source"]["targetRevision"]
    (lab.evidence / "retained-gitops-metrics.json").write_text(
        json.dumps({"before_replacement": history_before, "after_replacement": history_after},
                   indent=2) + "\n")
    lab.check("green", "Recovery clears the alert and a new Prometheus Pod reads the same retained state history",
              bool(recovered and resolved and ordered_history and still_approved
                   and same_volume and new_pod and same_history),
              {"sample_present_after_recovery": bool(recovered),
               "resolved_webhook": resolved[0] if resolved else None,
               "ordered_healthy_failed_recovered_history": ordered_history,
               "recovered_commit_matches_approved": still_approved,
               "same_volume": same_volume, "different_prometheus_pod": new_pod,
               "historical_results_identical": same_history})

    service = json.loads(lab.kubectl("-n", "argocd", "get", "service", "argocd-metrics", "-o", "json").stdout)
    original_selector = service["spec"]["selector"]

    def set_scrape_selector(selector):
        patch = [{"op": "replace", "path": "/spec/selector", "value": selector}]
        lab.kubectl("-n", "argocd", "patch", "service", "argocd-metrics", "--type=json",
                    "-p", json.dumps(patch))

    set_scrape_selector({"saf-lab.example/fixture": "no-scrape-endpoint"})
    target_down = wait_for(lambda: (lambda result: result and any(
        target.get("labels", {}).get("job") == "argocd-fixture"
        and target.get("health") == "down"
        for target in result.get("data", {}).get("activeTargets", [])))(
            json_url(lab, f"http://{PROM}:9090/api/v1/targets")), 45)
    missing_alert = wait_for(lambda: [a for a in alerts(lab)
        if a.get("labels", {}).get("alertname") == MISSING and a.get("state") == "firing"], 60)
    recent_samples = query(lab, f"{metric}[12s]")
    missing_delivery = wait_for(lambda: [n for n in matching_notifications(lab, MISSING)
        if n[0:7] == ("fixture-webhook", MISSING, APP, "argocd", "fixture", "warning",
                      "Owned fixture reconciliation telemetry is missing") and n[7] == "firing"], 60)
    present_app = base.application(lab)["status"]
    app_still_healthy = (present_app["health"]["status"] == "Healthy"
                         and present_app["sync"]["status"] == "Synced")
    set_scrape_selector(original_selector)
    scrape_restored = wait_for(lambda: query(lab, with_labels(metric, 'sync_status="Synced"')), 120)
    target_up = wait_for(lambda: (lambda result: result and any(
        target.get("labels", {}).get("job") == "argocd-fixture"
        and target.get("health") == "up"
        for target in result.get("data", {}).get("activeTargets", [])))(
            json_url(lab, f"http://{PROM}:9090/api/v1/targets")), 60)
    missing_resolved = wait_for(lambda: [n for n in matching_notifications(lab, MISSING)
        if n[0:7] == ("fixture-webhook", MISSING, APP, "argocd", "fixture", "warning",
                      "Owned fixture reconciliation telemetry is missing") and n[7] == "resolved"], 90)
    lab.check("green", "Absent telemetry has its own firing and resolved alert lifecycle",
              bool(target_down and missing_alert and missing_delivery and recent_samples == []
                   and scrape_restored and target_up and missing_resolved and app_still_healthy),
              {"missing_alert": bool(missing_alert),
               "firing_webhook": missing_delivery[0] if missing_delivery else None,
               "application_still_healthy": app_still_healthy,
               "target_down_observed": bool(target_down),
               "no_fresh_metric_samples_in_12_seconds": recent_samples == [],
               "scrape_restored": bool(scrape_restored), "target_up_restored": bool(target_up),
               "resolved_webhook": missing_resolved[0] if missing_resolved else None})
