"""Draft end-to-end tenant/workload metadata preservation test."""
import json
import time
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent
NAMESPACE = "saf-031-sink"
SCOPE = (
    "Two fixture namespaces and five synthetic app records in one disposable cluster. "
    "Fluent Bit enriches and forwards the events using actual Pod labels. The case verifies "
    "preserved context and exact query membership at a fixture receiver. Production SIEM "
    "authorization, collector rollout, and label governance need separate evidence."
)
COLLECTOR_IMAGE = "cr.fluentbit.io/fluent/fluent-bit:5.1.2@sha256:d792375ca8e53be72fc25716c28f291f32c6fc6f4f31d12d0d14bc78cefe9226"
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def obj(lab, value):
    namespace = value["metadata"].get("namespace", "saf-test")
    lab.kubectl("-n", namespace, "apply", "-f", "-", payload=json.dumps(value))


def sink_code():
    return r'''from http.server import BaseHTTPRequestHandler, HTTPServer
import json
STORE=[]
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args): pass
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200); self.end_headers(); self.wfile.write(b"ready"); return
        if self.path == "/events":
            body=json.dumps(STORE,sort_keys=True).encode()
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
        self.send_error(404)
    def do_POST(self):
        if self.path != "/ingest": self.send_error(404); return
        length=int(self.headers.get("Content-Length","0"))
        if length < 1 or length > 1048576: self.send_error(413); return
        try:
            rows=[json.loads(x) for x in self.rfile.read(length).decode().splitlines() if x.strip()]
            if not rows or any(not isinstance(x,dict) for x in rows): raise ValueError()
        except Exception:
            self.send_error(400); return
        STORE.extend(rows); self.send_response(201); self.end_headers(); self.wfile.write(b"accepted")
HTTPServer(("0.0.0.0",8080),Handler).serve_forever()
'''


def apply_sink(lab):
    obj(lab, {"apiVersion":"v1","kind":"Namespace","metadata":{"name":NAMESPACE}})
    obj(lab, {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"sink-code","namespace":NAMESPACE},"data":{"sink.py":sink_code()}})
    obj(lab, {"apiVersion":"v1","kind":"Pod","metadata":{"name":"evidence-sink","namespace":NAMESPACE,"labels":{"app":"evidence-sink"}},"spec":{"automountServiceAccountToken":False,"securityContext":{"runAsNonRoot":True,"runAsUser":1000},"containers":[{"name":"sink","image":PYTHON_IMAGE,"imagePullPolicy":"IfNotPresent","command":["python","-u","/app/sink.py"],"securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True},"ports":[{"containerPort":8080}],"volumeMounts":[{"name":"code","mountPath":"/app","readOnly":True}]}],"volumes":[{"name":"code","configMap":{"name":"sink-code"}}]}})
    obj(lab, {"apiVersion":"v1","kind":"Service","metadata":{"name":"evidence-sink","namespace":NAMESPACE},"spec":{"selector":{"app":"evidence-sink"},"ports":[{"port":8080,"targetPort":8080}]}})
    lab.kubectl("wait","--for=condition=Ready","pod/evidence-sink","-n",NAMESPACE,"--timeout=90s",timeout=100)


def receiver_records(lab):
    result=lab.kubectl("exec","-n",NAMESPACE,"pod/evidence-sink","--","python","-c",
                       "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/events').read().decode())")
    return json.loads(result.stdout)


def collector_config(namespace, pod, enabled):
    filters = """  filters:
    - name: kubernetes
      match: 'saf031.*'
      kube_tag_prefix: saf031.
      regex_parser: kube_tag
      kube_url: https://kubernetes.default.svc:443
      kube_ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      kube_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      tls.verify: true
      tls.verify_hostname: true
      labels: true
      annotations: false
      namespace_labels: false
""" if enabled else ""
    return f"""service:
  flush: 1
  log_level: warn
pipeline:
  inputs:
    - name: tail
      tag: saf031.{namespace}.{pod}.fixture-app
      path: /shared/events.jsonl
      parser: structured_json
      read_from_head: true
      refresh_interval: 1
{filters}  outputs:
    - name: http
      match: '*'
      host: evidence-sink.{NAMESPACE}.svc
      port: 8080
      uri: /ingest
      format: json_lines
      json_date_key: false
      workers: 1
parsers:
  - name: structured_json
    format: json
  - name: kube_tag
    format: regex
    regex: '^(?<namespace_name>[^.]+)\\.(?<pod_name>[^.]+)\\.(?<container_name>[^.]+)$'
"""


def create_fixture_pod(lab, fixture, phase, enabled):
    namespace = fixture["namespace"]
    identity = {"name": "metadata-reader", "namespace": namespace}
    rbac_api = "rbac.authorization.k8s.io"
    obj(lab, {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
    obj(lab, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": identity,
              "automountServiceAccountToken": False})
    obj(lab, {"apiVersion": f"{rbac_api}/v1", "kind": "Role", "metadata": identity,
              "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]})
    obj(lab, {"apiVersion": f"{rbac_api}/v1", "kind": "RoleBinding", "metadata": identity,
              "subjects": [{"kind": "ServiceAccount", **identity}],
              "roleRef": {"apiGroup": rbac_api, "kind": "Role", "name": identity["name"]}})

    # Fresh names isolate tail offsets, Pod metadata and files between phases.
    name = fixture["pod"] + ("-enriched" if enabled else "-raw")
    event = {key: fixture[key] for key in ("event_id", "marker")}
    event["event_id"] += "-" + phase
    source_name = "source-" + name
    config_name = "collector-" + name
    labels = {key: fixture[key] for key in ("tenant", "workload") if key in fixture}
    for map_name, data in (
        (source_name, {"events.jsonl": json.dumps(event, sort_keys=True) + "\n"}),
        (config_name, {"fluent-bit.yaml": collector_config(namespace, name, enabled)}),
    ):
        obj(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": map_name, "namespace": namespace}, "data": data})
    api_volume = {"name": "api-credentials", "projected": {"sources": [
        {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
        {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
        {"downwardAPI": {"items": [{"path": "namespace", "fieldRef": {"fieldPath": "metadata.namespace"}}]}},
    ]}}
    security = {"runAsNonRoot": True, "runAsUser": 1000,
                "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True}
    writer = (
        "from pathlib import Path\n"
        "from time import sleep\n"
        "Path('/shared/events.jsonl').write_bytes(Path('/fixture/events.jsonl').read_bytes())\n"
        "sleep(3600)\n"
    )
    collector_config_path = "/fluent-bit/etc/fluent-bit.yaml"
    obj(lab, {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "serviceAccountName": identity["name"], "automountServiceAccountToken": False,
            "restartPolicy": "Never", "securityContext": {"fsGroup": 1000},
            "containers": [
                {
                    "name": "fixture-app", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "-c", writer], "securityContext": security,
                    "volumeMounts": [
                        {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                        {"name": "shared", "mountPath": "/shared"},
                    ],
                }, {
                    "name": "fluent-bit", "image": COLLECTOR_IMAGE, "imagePullPolicy": "IfNotPresent",
                    "args": ["-c", collector_config_path], "securityContext": security,
                    "volumeMounts": [
                        {"name": "config", "mountPath": collector_config_path,
                         "subPath": "fluent-bit.yaml", "readOnly": True},
                        {"name": "shared", "mountPath": "/shared", "readOnly": True},
                        {"name": "api-credentials", "readOnly": True,
                         "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"},
                    ],
                },
            ],
            "volumes": [
                {"name": "fixture", "configMap": {"name": source_name}},
                {"name": "config", "configMap": {"name": config_name}},
                {"name": "shared", "emptyDir": {}},
                api_volume,
            ],
        },
    })


def phase_snapshot(lab, fixtures, phase, enabled):
    for fixture in fixtures:
        create_fixture_pod(lab,fixture,phase,enabled)
    expected={f["event_id"]+"-"+phase for f in fixtures}
    deadline=time.monotonic()+75
    records=[]
    while time.monotonic()<deadline:
        records=receiver_records(lab)
        got={x.get("event_id") for x in records}
        if expected <= got: break
        time.sleep(1)
    time.sleep(2)
    records=receiver_records(lab)
    selected=[x for x in records if x.get("event_id") in expected]
    missing = expected - {record.get("event_id") for record in selected}
    if missing:
        for fixture in fixtures:
            if fixture["event_id"] + "-" + phase not in missing:
                continue
            pod = fixture["pod"] + ("-enriched" if enabled else "-raw")
            namespace = fixture["namespace"]
            lab.kubectl("-n", namespace, "describe", "pod", pod, allow_failure=True)
            for container in ("fixture-app", "fluent-bit"):
                lab.kubectl("-n", namespace, "logs", pod, "-c", container, allow_failure=True)
        lab.block(f"Receiver did not observe fixture events {sorted(missing)}")
    return selected


def run(lab):
    spec = json.loads((CASE_DIR / "fixtures.json").read_text())
    fixtures = spec["fixtures"]
    apply_sink(lab)
    raw=phase_snapshot(lab,fixtures,"unenriched",False)
    raw_ids=[x.get("event_id") for x in raw]
    raw_missing=all(not isinstance(x.get("kubernetes"),dict) for x in raw) and len(raw_ids)==len(fixtures) and len(set(raw_ids))==len(fixtures)
    lab.check("red","Without metadata enrichment, fixture receiver identifies missing Kubernetes context",raw_missing,{"event_ids":sorted(raw_ids),"context_missing":raw_missing})

    enriched=phase_snapshot(lab,fixtures,"enriched",True)
    by_id={x.get("event_id"):x for x in enriched}
    duplicate_free=len(by_id)==len(fixtures) and len(enriched)==len(fixtures)
    context_ok=duplicate_free
    observed={}
    for f in fixtures:
        event_id=f["event_id"]+"-enriched"
        row=by_id.get(event_id,{})
        k8s=row.get("kubernetes") or {}
        labels=k8s.get("labels") or {}
        expected_tenant=f.get("tenant")
        expected_workload=f.get("workload")
        context_ok &= row.get("marker")==f["marker"]
        context_ok &= k8s.get("namespace_name")==f["namespace"]
        context_ok &= k8s.get("pod_name")==f["pod"]+"-enriched"
        # The tag records the fixture app container whose synthetic log file is being tailed.
        context_ok &= k8s.get("container_name")=="fixture-app"
        if f.get("missing") == "tenant":
            context_ok &= "tenant" not in labels
        else:
            context_ok &= labels.get("tenant")==expected_tenant
        context_ok &= labels.get("workload")==expected_workload
        observed[event_id]={"tenant":labels.get("tenant"),"workload":labels.get("workload"),"namespace":k8s.get("namespace_name"),"pod":k8s.get("pod_name"),"marker":row.get("marker")}
    lab.check("positive","Receiver records retain source identity and receive tenant/workload only from fixture Pod labels",bool(context_ok),observed)

    searches = {}
    for key, expected_ids in spec["expected_searches"].items():
        tenant, _, workload = key.partition("/")
        got = sorted(event_id for event_id, row in observed.items()
                     if row["tenant"] == tenant and (not workload or row["workload"] == workload))
        want = sorted(event_id + "-enriched" for event_id in expected_ids)
        searches[key] = {"expected": want, "observed": got, "exact": got == want}
    expected_missing = sorted(item["event_id"] + "-enriched" for item in fixtures
                              if item.get("missing") == "tenant")
    observed_missing = sorted(event_id for event_id, row in observed.items() if row["tenant"] is None)
    exact = all(search["exact"] for search in searches.values()) and observed_missing == expected_missing
    searches["unattributed_events"] = {"expected": expected_missing, "observed": observed_missing}
    lab.check("green", "Exact tenant searches isolate event membership and identify missing tenant labels",
              exact, searches)
