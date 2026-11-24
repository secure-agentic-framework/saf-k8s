"""Synthetic end-to-end trace propagation across ingestion, Job, registry, inference."""
import json
import re
import runpy
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind cluster runs a digest-pinned OpenTelemetry "
    "Collector and synthetic Python OpenTelemetry SDK ingestion, registry and inference "
    "services plus native asynchronous training Jobs. The raw Collector output proves exact "
    "parentage, separation when the Job omits context, and an inference error marker "
    "on the intended trace. An additional fixture tests a native Job and KServe Standard-mode "
    "predictor annotation handoff with exact W3C parentage. Deployed orchestration "
    "coverage, telemetry governance and durable backends require separate evidence."
)

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
COLLECTOR_IMAGE = "ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib:0.136.0@sha256:45392d534c1edcc809c2d112394029246bc679d2ae5ea7081414a1fc74f2c621"
NS = "saf-test"
SDK = "opentelemetry-api==1.38.0 opentelemetry-sdk==1.38.0 opentelemetry-exporter-otlp-proto-http==1.38.0"

# Every application uses the official Python SDK, W3C Trace Context propagator and OTLP/HTTP.
APP = r'''import json, os, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from opentelemetry import trace, propagate
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
provider=TracerProvider(resource=Resource.create({"service.name":os.environ["SERVICE_NAME"],"saf.synthetic":"true"}))
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint="http://otel:4318/v1/traces")))
trace.set_tracer_provider(provider); tracer=trace.get_tracer("saf.synthetic.pipeline")
def post(url, payload, ctx=None):
 h={"Content-Type":"application/json"}
 if ctx is not None: propagate.inject(h, context=ctx)
 req=urllib.request.Request(url, data=json.dumps(payload).encode(), headers=h)
 with urllib.request.urlopen(req, timeout=8) as r: return json.loads(r.read())
def server(port, action):
 class H(BaseHTTPRequestHandler):
  def do_POST(self):
   n=int(self.headers.get("Content-Length","0")); data=json.loads(self.rfile.read(n) or b"{}")
   parent=propagate.extract({k.lower(): v for k, v in self.headers.items()})
   with tracer.start_as_current_span(action, context=parent) as span:
    span.set_attribute("saf.synthetic", True); span.set_attribute("pipeline.stage", action)
    if action == "inference" and data.get("inert_error"): span.set_attribute("error.type", "synthetic_fixture_error"); span.set_attribute("error.message", "SAF_SYNTHETIC_INERT_MARKER")
    out=dispatch(action,data,trace.set_span_in_context(span))
   body=json.dumps(out).encode(); self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
  def log_message(self,*a): pass
 HTTPServer(("0.0.0.0",port),H).serve_forever()
def dispatch(action,data,ctx):
 if action=="ingestion":
  # Return W3C context for this actual ingestion span so the supervisor can create a native Job.
  carrier={}; propagate.inject(carrier,context=ctx)
  return {"traceparent":carrier["traceparent"],"dataset":"synthetic-dataset-002","accepted":True}
 if action=="registry": return post("http://inference:8080/infer",{"model":"synthetic-model-002","record":"synthetic-row-1","inert_error":data.get("inert_error")},ctx)
 return {"served":True,"model":"synthetic-model-002","record":"synthetic-row-1"}
role=os.environ["ROLE"]
if role=="job":
 parent=propagate.extract({"traceparent":os.environ.get("TRACEPARENT","")})
 with tracer.start_as_current_span("training.job",context=parent) as s:
  s.set_attribute("pipeline.stage","training"); s.set_attribute("k8s.job.name",os.environ["JOB_NAME"]); s.set_attribute("saf.synthetic",True)
  result=post("http://registry:8080/register",{"model":"synthetic-model-002","inert_error":os.environ.get("INERT_ERROR")=="1"},trace.set_span_in_context(s))
 print(json.dumps({"status":"completed","result":result,"trace_id":format(s.get_span_context().trace_id,"032x")},sort_keys=True),flush=True)
 provider.force_flush(); provider.shutdown()
else: server(int(os.environ["PORT"]),role)
'''


def _security():
    return {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True, "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"}}


def _wait_ready(lab, name, seconds=75):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", f"--timeout={seconds}s", timeout=seconds+10)


def _app_deploy(lab, name, role, port):
    lab.create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":name+"-code"},"data":{"app.py":APP}})
    labels={"app":name}
    lab.create({"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":name},"spec":{"replicas":1,"selector":{"matchLabels":labels},"template":{"metadata":{"labels":labels},"spec":{"automountServiceAccountToken":False,"containers":[{"name":"app","image":PYTHON_IMAGE,"command":["sh","-c",f"pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: --target /tmp/saf-otel {SDK} && PYTHONPATH=/tmp/saf-otel exec python /code/app.py"],"env":[{"name":"SERVICE_NAME","value":role},{"name":"ROLE","value":role},{"name":"PORT","value":str(port)}],"ports":[{"containerPort":port}],"readinessProbe":{"tcpSocket":{"port":port},"periodSeconds":2},"volumeMounts":[{"name":"code","mountPath":"/code","readOnly":True}],"resources":{"requests":{"cpu":"25m","memory":"96Mi"},"limits":{"cpu":"500m","memory":"256Mi"}},"securityContext":_security()}],"volumes":[{"name":"code","configMap":{"name":name+"-code"}}]}}}})
    lab.create({"apiVersion":"v1","kind":"Service","metadata":{"name":name},"spec":{"selector":labels,"ports":[{"port":8080,"targetPort":port}]}})
    lab.kubectl("rollout","status",f"deployment/{name}","--timeout=100s",timeout=110)


def _collector(lab):
    cfg="""receivers:\n  otlp:\n    protocols:\n      http:\n        endpoint: 0.0.0.0:4318\nexporters:\n  debug:\n    verbosity: detailed\nservice:\n  pipelines:\n    traces:\n      receivers: [otlp]\n      exporters: [debug]\n"""
    lab.create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"otel-config"},"data":{"config.yaml":cfg}})
    lab.create({"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"otel"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"otel"}},"template":{"metadata":{"labels":{"app":"otel"}},"spec":{"automountServiceAccountToken":False,"containers":[{"name":"collector","image":COLLECTOR_IMAGE,"args":["--config=/etc/otelcol-contrib/config.yaml"],"ports":[{"containerPort":4318}],"readinessProbe":{"tcpSocket":{"port":4318},"periodSeconds":2},"volumeMounts":[{"name":"config","mountPath":"/etc/otelcol-contrib","readOnly":True}],"resources":{"requests":{"cpu":"50m","memory":"96Mi"},"limits":{"cpu":"500m","memory":"256Mi"}},"securityContext":_security()}],"volumes":[{"name":"config","configMap":{"name":"otel-config"}}]}}}})
    lab.create({"apiVersion":"v1","kind":"Service","metadata":{"name":"otel"},"spec":{"selector":{"app":"otel"},"ports":[{"port":4318,"targetPort":4318}]}})
    lab.kubectl("rollout","status","deployment/otel","--timeout=100s",timeout=110)


def _job(lab, name, traceparent="", inert=False):
    env=[{"name":"SERVICE_NAME","value":"training-job"},{"name":"ROLE","value":"job"},{"name":"JOB_NAME","value":name},{"name":"TRACEPARENT","value":traceparent},{"name":"INERT_ERROR","value":"1" if inert else "0"}]
    job={"apiVersion":"batch/v1","kind":"Job","metadata":{"name":name,"labels":{"saf.synthetic":"true"}},"spec":{"backoffLimit":0,"activeDeadlineSeconds":150,"template":{"metadata":{"labels":{"saf.synthetic":"true"}},"spec":{"restartPolicy":"Never","automountServiceAccountToken":False,"containers":[{"name":"trainer","image":PYTHON_IMAGE,"command":["sh","-c",f"pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: --target /tmp/saf-otel {SDK} && PYTHONPATH=/tmp/saf-otel exec python /code/app.py"],"env":env,"volumeMounts":[{"name":"code","mountPath":"/code","readOnly":True}],"resources":{"requests":{"cpu":"25m","memory":"96Mi"},"limits":{"cpu":"500m","memory":"256Mi"}},"securityContext":_security()}],"volumes":[{"name":"code","configMap":{"name":"job-code"}}]}}}}
    lab.create(job)
    wait=lab.kubectl("wait","--for=condition=Complete",f"job/{name}","--timeout=165s",timeout=175,allow_failure=True)
    logs=lab.kubectl("logs",f"job/{name}",allow_failure=True).stdout
    if wait.returncode: lab.block(f"Synthetic training Job {name} did not complete: {logs[-1000:]}")
    rows=[json.loads(line) for line in logs.splitlines() if line.startswith("{")]
    if len(rows)!=1 or rows[0].get("status")!="completed": lab.block(f"Unexpected training Job receipt for {name}")
    return rows[0]


def _span_rows(raw):
    spans = []
    for block in re.split(r"(?=Span #[0-9]+)", raw):
        fields = {}
        for output_name, field in (("Name", "name"), ("Trace ID", "trace_id"),
                                   ("ID", "span_id"), ("Parent ID", "parent_id")):
            match = re.search(r"^[ \t]*" + output_name + r"[ \t]*:[ \t]*([^\r\n]*)", block, re.M)
            fields[field] = match.group(1).strip() if match else ""
        if re.fullmatch(r"[0-9a-f]{32}", fields["trace_id"]) and re.fullmatch(r"[0-9a-f]{16}", fields["span_id"]):
            fields["marked_error"] = "SAF_SYNTHETIC_INERT_MARKER" in block
            spans.append(fields)
    return spans


def _collector_traces(lab, expected):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        output = lab.kubectl("logs", "deployment/otel", "--tail=1500", allow_failure=True)
        if not output.returncode:
            raw = output.stdout
            spans = _span_rows(raw)
            if expected <= {(row["trace_id"], row["name"]) for row in spans}:
                return raw, spans
        time.sleep(1)
    lab.block("Collector output did not contain every expected trace stage before the deadline")


def _ingest(lab, name):
    client = (
        "import urllib.request; "
        "request=urllib.request.Request('http://ingestion:8080/ingest',data=b'{}',"
        "headers={'Content-Type':'application/json'}); "
        "print(urllib.request.urlopen(request,timeout=8).read().decode())"
    )
    result = lab.kubectl("exec", "deployment/inference", "--", "python", "-c", client, timeout=20)
    value = json.loads(result.stdout)
    traceparent = value["traceparent"]
    lab.check("positive", f"{name} ingestion emits a valid sampled W3C traceparent",
              bool(re.fullmatch(r"00-[0-9a-f]{32}-[0-9a-f]{16}-01", traceparent))
              and value["accepted"] is True, {"valid": True})
    return value


def _chain(spans, trace_id, stages, parent=""):
    sequence = {row["name"]: row for row in spans if row["trace_id"] == trace_id}
    if list(sorted(sequence)) != sorted(stages):
        return False
    if len([row for row in spans if row["trace_id"] == trace_id]) != len(stages):
        return False
    for stage in stages:
        row = sequence[stage]
        if row["parent_id"] != parent:
            return False
        parent = row["span_id"]
    return True


def run(lab):
    _collector(lab)
    for name in ("ingestion", "registry", "inference"):
        _app_deploy(lab, name, name, 8080)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "job-code"}, "data": {"app.py": APP}})

    ingested = _ingest(lab, "Primary")
    traceparent = ingested["traceparent"]
    trace_id, ingest_id = traceparent.split("-")[1:3]
    missing = _job(lab, "training-missing-context")
    stages = ["training.job", "registry", "inference"]
    missing_id = missing["trace_id"]
    expected = {(missing_id, stage) for stage in stages} | {(trace_id, "ingestion")}
    _, by_stage = _collector_traces(lab, expected)
    isolated = missing_id != trace_id and _chain(by_stage, missing_id, stages)
    lab.check("red", "A completed Job without context creates its own trace while ingestion stays separate",
              isolated and missing["result"]["served"] is True,
              {"missing_trace_separate": isolated, "completed": missing["status"] == "completed"})

    linked = _job(lab, "training-linked", traceparent, inert=True)
    expected.update((trace_id, stage) for stage in stages)
    healthy_ingest = _ingest(lab, "Comparison")
    healthy_parent = healthy_ingest["traceparent"]
    healthy = _job(lab, "training-healthy-comparator", healthy_parent)
    healthy_id = healthy_parent.split("-")[1]
    full_chain = ["ingestion", *stages]
    expected.update((healthy_id, stage) for stage in full_chain)
    raw, spans = _collector_traces(lab, expected)
    (lab.evidence / "collector-debug.txt").write_text(raw)
    receipt = {"ingestion": ingested, "missing_context": missing, "linked": linked,
               "healthy_ingestion": healthy_ingest, "healthy": healthy, "spans": spans}
    (lab.evidence / "trace-receipts.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")

    actual_ingestion = next(row for row in spans if row["trace_id"] == trace_id and row["name"] == "ingestion")
    recorded = _chain(spans, trace_id, full_chain)
    lab.check("green", "Collector confirms exact parentage from ingestion across the native Job to inference",
              recorded and actual_ingestion["span_id"] == ingest_id and linked["trace_id"] == trace_id,
              {"correct_parent_chain": recorded, "stages": full_chain})
    markers = [(row["trace_id"], row["name"]) for row in spans if row["marked_error"]]
    lab.check("green", "The inert error marker belongs to the linked trace's inference span",
              markers == [(trace_id, "inference")], {"inference_only": markers == [(trace_id, "inference")]})
    comparison = healthy_id not in {missing_id, trace_id} and _chain(spans, healthy_id, full_chain)
    lab.check("positive", "The healthy comparator retains its own complete trace and serves the fixture",
              comparison and healthy["trace_id"] == healthy_id and healthy["result"]["served"] is True,
              {"independent_trace": comparison, "served": healthy["result"]["served"]})

    kserve = runpy.run_path(str(HERE / "kserve" / "case.py"))
    dispatch_source = _ingest(lab, "KServe dispatch")
    kserve["run"](lab, dispatch_source, PYTHON_IMAGE, SDK, _security, _collector_traces, _chain)
