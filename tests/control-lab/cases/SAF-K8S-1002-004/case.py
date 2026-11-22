"""Exercise AI telemetry alert evaluation and owned Alertmanager routing."""
import json
from pathlib import Path
import runpy
import time
from urllib.parse import urlencode

HERE = Path(__file__).resolve().parent
DATA = runpy.run_path(str(HERE / "telemetry-fixture.py"))
EXPECTED, FAILURES, HEALTHY = (DATA[key] for key in ("EXPECTED", "FAILURES", "HEALTHY"))
SCOPE = (
    "Synthetic telemetry served by an owned fixture workload in Kubernetes v1.36.1; "
    "real Prometheus v3.5.0 rule evaluation and Alertmanager v0.28.1 route to two "
    "case-only webhook receiver identities. No NVIDIA exporter, GPU, model, or real "
    "inference/training system is exercised. Each failure is injected independently."
)
WORKLOAD, PROM, AM = "saf-ai-telemetry", "saf-ai-prometheus", "saf-ai-alertmanager"
IMAGE = {
    WORKLOAD: "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
    PROM: "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996",
    AM: "docker.io/prom/alertmanager:v0.28.1@sha256:27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba",
}
ALERTS = [value[0] for value in EXPECTED.values()]

SERVER = r'''import json, time
from http.server import BaseHTTPRequestHandler, HTTPServer
HEALTHY = __HEALTHY__
FAILURES = __FAILURES__
state = {"mode": "healthy", "receipts": [], "loss": 0.2}
class H(BaseHTTPRequestHandler):
 def send(self, code, value):
  body=json.dumps(value).encode(); self.send_response(code); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
 def do_GET(self):
  if self.path == "/metrics":
   lines=["# TYPE training_loss gauge", "# TYPE model_last_update_seconds gauge", "# TYPE inference_accuracy_ratio gauge", "# TYPE inference_latency_p99_seconds gauge", "# TYPE training_last_checkpoint_seconds gauge", "# TYPE DCGM_FI_DEV_XID_ERRORS gauge"]
   for cohort in ("affected", "healthy"):
    values=dict(HEALTHY)
    if cohort == "affected":
     values.update(FAILURES.get(state["mode"], {}))
     if state["mode"] == "divergence": state["loss"] += 0.1; values["training_loss"] = state["loss"]
    for metric,value in values.items():
     if metric in {"model_last_update_seconds", "training_last_checkpoint_seconds"}: value=time.time()+value
     lines.append(f'{metric}{{workload="fixture",cohort="{cohort}"}} {value}')
   b=("\n".join(lines)+"\n").encode(); self.send_response(200); self.send_header("Content-Type","text/plain; version=0.0.4"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
  if self.path == "/receipts": self.send(200,state["receipts"]); return
  if self.path == "/state": self.send(200,{"mode":state["mode"]}); return
  self.send(404,{})
 def do_POST(self):
  n=int(self.headers.get("Content-Length",0)); data=json.loads(self.rfile.read(n) or b"{}")
  if self.path == "/mode" and data.get("mode") in ["healthy", *FAILURES]:
   state["mode"]=data["mode"]
   if state["mode"] == "healthy": state["loss"]=0.2
   self.send(200,{"mode":state["mode"]}); return
  if self.path.startswith("/notify/") and self.path.split("/")[-1] in ("security-operations","ml-operations"): state["receipts"].append({"receiver_identity":self.path.split("/")[-1],"payload":data}); self.send(200,{"ok":True}); return
  self.send(404,{})
 def log_message(self,*a): pass
HTTPServer(("0.0.0.0",8080),H).serve_forever()
'''

def rules():
    exprs = {
        "AITrainingDivergence": 'deriv(training_loss[8s]) > 0.02',
        "AIModelStale": 'time() - model_last_update_seconds > 300',
        "AIGPULastXIDObserved": 'DCGM_FI_DEV_XID_ERRORS > 0',
        "AIInferenceAccuracyDegraded": 'inference_accuracy_ratio < 0.90',
        "AIInferenceLatencyHigh": 'inference_latency_p99_seconds > 1',
        "AITrainingCheckpointStalled": 'time() - training_last_checkpoint_seconds > 300',
    }
    return {"groups": [{"name": "synthetic-ai-failure-modes", "interval": "2s", "rules": [
        {"alert": name, "expr": expr, "labels": {"severity": "critical" if name in ALERTS[:4] else "warning",
         "receiver_class": "security-operations" if name in ALERTS[:4] else "ml-operations",
         "fixture": "saf-k8s-1002-004"}, "annotations": {"summary": f"Synthetic fixture: {name}"}}
        for name, expr in exprs.items()]}]}

def configs():
    prom = {"global": {"scrape_interval": "2s", "evaluation_interval": "2s"},
            "scrape_configs": [{"job_name": "synthetic-ai", "static_configs": [{"targets": [f"{WORKLOAD}:8080"]}]}],
            "rule_files": ["/saf/rules.json"],
            "alerting": {"alertmanagers": [{"static_configs": [{"targets": [f"{AM}:9093"]}]}]}}
    am = {"route": {"receiver": "discard", "group_by": ["alertname", "cohort"], "group_wait": "1s",
          "group_interval": "2s", "repeat_interval": "1h", "routes": [
          {"matchers": ['receiver_class="security-operations"'], "receiver": "security-operations"},
          {"matchers": ['receiver_class="ml-operations"'], "receiver": "ml-operations"}]},
          "receivers": [{"name": "discard"},
          {"name": "security-operations", "webhook_configs": [{"url": f"http://{WORKLOAD}:8080/notify/security-operations", "send_resolved": True}]},
          {"name": "ml-operations", "webhook_configs": [{"url": f"http://{WORKLOAD}:8080/notify/ml-operations", "send_resolved": True}]}]}
    return {"prom.json": json.dumps(prom), "rules.json": json.dumps(rules()), "am.json": json.dumps(am),
            "server.py": SERVER.replace("__HEALTHY__", json.dumps(HEALTHY)).replace("__FAILURES__", json.dumps(FAILURES))}

def pod_manifest(name, image, args, config_name, config_files, port, command=None):
    selector = {"app": name}
    container = {
        "name": "app", "image": image, "args": args,
        "ports": [{"containerPort": port}],
        "readinessProbe": {"tcpSocket": {"port": port}, "periodSeconds": 2},
        "volumeMounts": [{"name": "config", "mountPath": "/saf", "readOnly": True},
                         {"name": "data", "mountPath": "/data"}],
        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "20m", "memory": "32Mi"},
                      "limits": {"cpu": "500m", "memory": "256Mi"}},
    }
    if command:
        container["command"] = command
    pod = {
        "automountServiceAccountToken": False, "containers": [container],
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumes": [{"name": "config", "configMap": {"name": config_name}},
                    {"name": "data", "emptyDir": {}}],
    }
    return [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": config_name},
         "data": config_files},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
         "spec": {"replicas": 1, "selector": {"matchLabels": selector},
                  "template": {"metadata": {"labels": selector}, "spec": pod}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
         "spec": {"selector": selector, "ports": [{"port": port, "targetPort": port}]}},
    ]


def deploy(lab, name, image, args, config_name, files, port, command=None):
    for resource in pod_manifest(name,image,args,config_name,files,port,command): lab.create(resource)
    lab.kubectl("rollout","status",f"deployment/{name}","--timeout=120s",timeout=130)

def http(lab, path, data=None):
    script = "import json,sys,urllib.request; u=sys.argv[1]; d=None if sys.argv[2]=='-' else sys.argv[2].encode(); r=urllib.request.Request(u,data=d,headers={'Content-Type':'application/json'} if d else {},method='POST' if d else 'GET'); print(urllib.request.urlopen(r,timeout=4).read().decode())"
    raw = lab.kubectl("exec",f"deployment/{WORKLOAD}","--","python","-c",script,
        f"http://{WORKLOAD}:8080{path}",json.dumps(data) if data is not None else "-",timeout=15)
    return json.loads(raw.stdout)

def prom_query(lab, expr):
    url=f"http://{PROM}:9090/api/v1/query?{urlencode({'query':expr})}"
    return query_via_workload(lab,url)

def query_via_workload(lab,url):
    script="import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1],timeout=4).read().decode())"
    r=lab.kubectl("exec",f"deployment/{WORKLOAD}","--","python","-c",script,url,timeout=15,allow_failure=True)
    return json.loads(r.stdout) if not r.returncode else None

def wait_until(fn, timeout=45):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        value=fn()
        if value: return value
        time.sleep(1)
    return None

def run(lab):
    files=configs()
    deploy(lab,WORKLOAD,IMAGE[WORKLOAD],["/saf/server.py"],"saf-ai-workload",{"server.py":files["server.py"]},8080,["python"])
    deploy(lab,AM,IMAGE[AM],["--config.file=/saf/am.json","--cluster.listen-address=","--storage.path=/data"],"saf-ai-am",{"am.json":files["am.json"]},9093)
    args = ["--config.file=/saf/prom.json", "--storage.tsdb.path=/data"]
    disabled = json.loads(files["prom.json"])
    disabled.pop("rule_files")
    deploy(lab, PROM, IMAGE[PROM], args, "saf-ai-prom",
           {"prom.json": json.dumps(disabled)}, 9090)
    http(lab, "/mode", {"mode": "staleness"})
    old_model = wait_until(lambda: vector(
        lab, 'time() - model_last_update_seconds{cohort="affected"} > 300'))
    no_rule = vector(lab, 'ALERTS{alertstate="firing"}')
    deliveries = http(lab, "/receipts")
    evidence = {"disabled": {"old_model": old_model, "firing": no_rule, "deliveries": deliveries},
                "scenarios": {}}
    lab.check("red", "A scraped stale model yields no alert before rule installation",
              bool(old_model) and len(old_model) == 1 and no_rule == [] and not deliveries,
              {"stale_models": len(old_model or []), "firing": len(no_rule or []), "delivered": len(deliveries)})

    http(lab, "/mode", {"mode": "healthy"})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "saf-ai-prom-enabled"},
                "data": {key: files[key] for key in ("prom.json", "rules.json")}})
    patch = {"spec": {"template": {"spec": {"volumes": [
        {"name": "config", "configMap": {"name": "saf-ai-prom-enabled"}},
    ]}}}}
    lab.kubectl("patch", "deployment", PROM, "--type=strategic", "-p", json.dumps(patch))
    lab.kubectl("rollout", "status", f"deployment/{PROM}", "--timeout=100s", timeout=110)
    baseline = wait_until(lambda: vector(lab, 'training_loss{job="synthetic-ai"}'))
    cohorts = sorted(row["metric"]["cohort"] for row in baseline or [])
    lab.check("positive", "Both exact seeded cohorts are scraped with the rules enabled",
              cohorts == ["affected", "healthy"] and active(lab) == [], {"cohorts": cohorts})
    for mode,(alert,receiver) in EXPECTED.items():
        http(lab,"/mode",{"mode":"healthy"})
        wait_until(lambda: active(lab) == [],timeout=25)
        http(lab,"/mode",{"mode":mode})
        firing=wait_until(lambda: active(lab),timeout=45)
        exact=bool(firing and len(firing)==1 and firing[0]["labels"].get("alertname")==alert
            and firing[0]["labels"].get("cohort")=="affected"
            and firing[0]["labels"].get("fixture")=="saf-k8s-1002-004"
            and firing[0]["labels"].get("receiver_class")==receiver
            and firing[0]["labels"].get("severity")==("critical" if receiver=="security-operations" else "warning")
            and firing[0]["annotations"].get("summary")==f"Synthetic fixture: {alert}")
        lab.check("green",f"{mode}: exact alert identity and affected cohort fire",exact,
            {"scenario":mode,"alertname":alert,"cohort":"affected","receiver_class":receiver,"firing":exact})
        delivered=wait_until(lambda: receiver_seen(lab,alert,receiver),timeout=35)
        lab.check("green",f"{mode}: Alertmanager delivers to its owned receiver identity",bool(delivered),
            {"scenario":mode,"receiver_identity":receiver,"delivered":bool(delivered)})
        healthy_clear=wait_until(lambda: cohort_clear(lab,alert),timeout=20)
        lab.check("positive",f"{mode}: healthy cohort remains non-firing",bool(healthy_clear),{"healthy_cohort_clear":bool(healthy_clear)})
        http(lab,"/mode",{"mode":"healthy"})
        recovered=wait_until(lambda: active(lab) == [],timeout=25)
        resolved = wait_until(lambda: receiver_seen(lab, alert, receiver, "resolved"), timeout=35)
        lab.check("positive", f"{mode}: rule clears and receiver observes resolution",
                  bool(recovered and resolved), {"recovered": bool(recovered), "resolved": bool(resolved)})
        evidence["scenarios"][mode] = {"firing": firing, "notification": delivered, "resolved": resolved}
        (lab.evidence / "alert-decisions.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")

def vector(lab, expression):
    reply = prom_query(lab, expression)
    return reply["data"]["result"] if reply and reply.get("status") == "success" else None


def active(lab):
    reply = query_via_workload(lab, f"http://{PROM}:9090/api/v1/alerts")
    if not reply or reply.get("status") != "success":
        return None
    return [row for row in reply["data"]["alerts"] if row["state"] == "firing"]


def cohort_clear(lab, alert):
    expression = f'ALERTS{{alertname="{alert}",cohort="healthy",alertstate="firing"}}'
    return vector(lab, expression) == []


def receiver_seen(lab, alert, receiver, state="firing"):
    for receipt in http(lab, "/receipts"):
        payload = receipt["payload"]
        if receipt["receiver_identity"] != receiver or payload.get("receiver") != receiver:
            continue
        for item in payload.get("alerts", []):
            labels = item.get("labels", {})
            if (item["status"] == state and labels.get("alertname") == alert
                    and labels.get("cohort") == "affected" and labels.get("receiver_class") == receiver
                    and labels.get("fixture") == "saf-k8s-1002-004"):
                return receipt
    return None
