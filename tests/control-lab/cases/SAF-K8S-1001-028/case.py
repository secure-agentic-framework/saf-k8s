"""Verify a real Kubernetes audit source and synthetic AI source routes."""
import json
import re
import tempfile
import time
from pathlib import Path

from lab import NODE_IMAGE

HERE = Path(__file__).resolve().parent
FIXTURE_IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
                 "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
SINK_CODE = r'''from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
STORE = Path("/data/events.jsonl")
class H(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        if self.path != "/ingest": self.send_error(404); return
        n = int(self.headers.get("Content-Length", "0"))
        try:
            event = json.loads(self.rfile.read(n))
            if not isinstance(event, dict): raise ValueError()
        except (ValueError, json.JSONDecodeError): self.send_error(400); return
        with STORE.open("a") as f: f.write(json.dumps(event, sort_keys=True) + "\n")
        self.send_response(201); self.end_headers()
HTTPServer(("0.0.0.0", 8081), H).serve_forever()
'''
ROUTER_CODE = r'''from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import json, urllib.request
ROUTES = Path("/config/routes.json")
class H(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        source = self.path.removeprefix("/")
        routes = json.loads(ROUTES.read_text())
        if source not in routes: self.send_error(404, "route disabled"); return
        n = int(self.headers.get("Content-Length", "0")); body = self.rfile.read(n)
        try:
            event = json.loads(body)
            if not isinstance(event, dict): raise ValueError()
            req = urllib.request.Request("http://evidence-sink:8081/ingest", data=body,
                                         headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=5) as response: code = response.status
        except Exception: self.send_error(502, "receiver rejected event"); return
        self.send_response(code); self.end_headers()
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
'''
PRODUCER_CODE = r'''import json, os, time, urllib.error, urllib.request
url = os.environ["ROUTER_URL"]
event = json.loads(os.environ["EVENT_JSON"])
expected = int(os.environ["EXPECTED_STATUS"])
for attempt in range(30):
    try:
        req = urllib.request.Request(url, data=json.dumps(event).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as response: code = response.status
    except urllib.error.HTTPError as error: code = error.code
    except Exception:
        time.sleep(1); continue
    if code == expected: print(json.dumps({"event_id": event["event_id"], "status": code})); break
    raise SystemExit("unexpected router status " + str(code))
else: raise SystemExit("router did not become ready")
'''
SCOPE = (
    "One case-owned kind cluster with the v1.36.1 node image, a metadata-only audit policy, "
    "one successful ConfigMap create, five in-cluster synthetic AI fixture Jobs, and an owned "
    "router plus HTTP receiver in one namespace. The first AI submissions use the same fixed "
    "events as replay and receive 404 while their routes are absent; after enabling those routes, "
    "the exact events reach the receiver. The Kubernetes event is read from the API server audit "
    "file and keeps its real auditID and explicit source_origin. No training, inference, registry "
    "service, policy engine, production SIEM, or SIEM completeness monitoring is exercised."
)


def load_fixtures():
    return json.loads((HERE / "fixtures.json").read_text())


def audit_id(stderr):
    found = re.findall(r"(?i)\baudit-id\s*:\s*([a-f0-9-]{36})", stderr)
    if len(set(found)) != 1:
        raise RuntimeError("expected one API response Audit-Id")
    return found[0]


def audit_event(audit_dir, expected_id, fixture):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        path = audit_dir / "audit.log"
        if path.exists():
            for line in path.read_text().splitlines():
                try: record = json.loads(line)
                except json.JSONDecodeError: continue
                ref = record.get("objectRef") or {}
                if (record.get("auditID") == expected_id and record.get("verb") == "create"
                        and ref.get("resource") == "configmaps"
                        and ref.get("name") == fixture["metadata"]["name"]
                        and ref.get("namespace") == fixture["metadata"]["namespace"]
                        and record.get("stage") == "ResponseComplete"):
                    return {
                        "event_id": "k8s-1001-028-" + expected_id,
                        "source_origin": "kube-apiserver/audit-policy-file",
                        "event_type": "kubernetes_audit", "synthetic": False,
                        "auditID": record["auditID"], "verb": record["verb"],
                        "resource": ref["resource"], "name": ref["name"],
                        "namespace": ref["namespace"],
                        "response_code": (record.get("responseStatus") or {}).get("code"),
                    }
        time.sleep(0.2)
    raise RuntimeError("API response Audit-Id did not appear in the audit file")


def apply_json(api, obj):
    return api("apply", "-f", "-", payload=json.dumps(obj))


def pod(name, image, command, env=None, volumes=None):
    container = {"name": name, "image": image, "imagePullPolicy": "IfNotPresent",
                 "command": command, "env": env or []}
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "saf-1001-028"},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "containers": [container], "volumes": volumes or []}}


def wait_pod(api, name):
    api("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
        "--timeout=60s", timeout=70)


def producer(api, name, source, event, status):
    obj = pod(name, FIXTURE_IMAGE, ["python", "-c", PRODUCER_CODE], [
        {"name": "ROUTER_URL", "value": f"http://source-router:8080/{source}"},
        {"name": "EVENT_JSON", "value": json.dumps(event, sort_keys=True)},
        {"name": "EXPECTED_STATUS", "value": str(status)},
    ])
    apply_json(api, obj)
    wait_pod(api, name)
    return json.loads(api("logs", f"pod/{name}").stdout)


def receiver_records(api):
    code = "import json,pathlib; p=pathlib.Path('/data/events.jsonl'); print(json.dumps([json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []))"
    return json.loads(api("exec", "evidence-sink", "--", "python", "-c", code).stdout)


def routes_config(routes):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "source-router-config", "namespace": "saf-1001-028"},
            "data": {"routes.json": json.dumps(routes, sort_keys=True)}}


def wait_for_routes(lab, api, expected):
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        mounted = api("exec", "source-router", "--", "python", "-c",
                      "from pathlib import Path; print(Path('/config/routes.json').read_text())")
        if json.loads(mounted.stdout) == expected:
            return
        time.sleep(3)
    lab.block("The fixture router did not observe the new source routes")


def router_pod():
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "source-router", "namespace": "saf-1001-028",
                         "labels": {"name": "source-router"}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "containers": [{"name": "router", "image": FIXTURE_IMAGE,
                                     "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-u", "-c", ROUTER_CODE],
                                     "ports": [{"containerPort": 8080}],
                                     "volumeMounts": [{"name": "config", "mountPath": "/config", "readOnly": True}]}],
                     "volumes": [{"name": "config", "configMap": {"name": "source-router-config"}}]}}


def sink_pod():
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "evidence-sink", "namespace": "saf-1001-028",
                         "labels": {"name": "evidence-sink"}},
            "spec": {"automountServiceAccountToken": False,
                     "containers": [{"name": "sink", "image": FIXTURE_IMAGE,
                                     "imagePullPolicy": "IfNotPresent", "command": ["python", "-u", "-c", SINK_CODE],
                                     "ports": [{"containerPort": 8081}],
                                     "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                     "volumes": [{"name": "data", "emptyDir": {}}]}}


def run(lab):
    f = load_fixtures(); ns = f["namespace"]
    cluster = lab.cluster + "-1001-028"
    with tempfile.TemporaryDirectory(prefix="saf-1001-028-") as tmp:
        root = Path(tmp); audit_dir = root / "audit"; audit_dir.mkdir()
        kubeconfig = root / "kubeconfig"
        template = (HERE / "kind.yaml.in").read_text()
        config = root / "kind.yaml"
        config.write_text(template.replace("@POLICY_PATH@", json.dumps(str(HERE / "audit-policy.yaml")))
                          .replace("@AUDIT_DIR@", json.dumps(str(audit_dir))))
        existing = lab.command("kind", "get", "clusters").stdout.splitlines()
        if cluster in existing: lab.block("Case-owned cluster name is already in use")
        try:
            lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                        "--config", str(config), "--kubeconfig", str(kubeconfig), "--wait", "90s", timeout=480)
            api = lambda *args, **kwargs: lab.command("kubectl", "--kubeconfig", str(kubeconfig),
                    "--context", f"kind-{cluster}", "--namespace", ns, "--request-timeout=15s",
                    *args, **kwargs)
            api("create", "namespace", ns)
            # Direct API request, with the server response's Audit-Id matched to file output.
            response = api("create", "--raw", f"/api/v1/namespaces/{ns}/configmaps", "-f", "-", "--v=8",
                           payload=json.dumps(f["audit_object"]), timeout=25)
            real_id = audit_id(response.stderr)
            k8s_event = audit_event(audit_dir, real_id, f["audit_object"])

            # Receiver and route fixture run only inside this case-owned cluster.
            apply_json(api, routes_config({f["audit_route"]: True}))
            for obj in [sink_pod(), router_pod(),
                        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "evidence-sink", "namespace": ns}, "spec": {"selector": {"name": "evidence-sink"}, "ports": [{"port": 8081, "targetPort": 8081}]}},
                        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "source-router", "namespace": ns}, "spec": {"selector": {"name": "source-router"}, "ports": [{"port": 8080, "targetPort": 8080}]}}]:
                apply_json(api, obj)
            api("wait", "--for=condition=Ready", "pod/evidence-sink", "--timeout=60s", timeout=70)
            api("wait", "--for=condition=Ready", "pod/source-router", "--timeout=60s", timeout=70)

            # AI origins are absent from the enabled route map. Each in-cluster fixture
            # app sends its fixed event once and expects the router's 404.
            blocked = []
            for event in f["ai_events"]:
                blocked.append(producer(api, "before-" + event["event_type"],
                                        "ai." + event["event_type"], event, 404))
            audit_submission = producer(api, "audit-source", f["audit_route"], k8s_event, 201)
            before = receiver_records(api)
            no_ai = not any(e.get("event_type") in {x["event_type"] for x in f["ai_events"]} for e in before)
            lab.check("red", "AI fixture event classes have no enabled source routes and are absent at the receiver",
                      no_ai, {"route_map": [f["audit_route"]], "blocked_submissions": blocked,
                              "ai_event_ids_absent": [e["event_id"] for e in f["ai_events"]],
                              "observed_count": len(before)})
            audit_seen = [e for e in before if e.get("auditID") == real_id]
            audit_ok = (len(audit_seen) == 1 and audit_seen[0] == k8s_event
                        and audit_seen[0]["source_origin"] == f["expected_audit_origin"]
                        and audit_seen[0]["event_type"] == f["expected_audit_event_type"]
                        and audit_seen[0]["response_code"] == 201)
            lab.check("positive", "The real API audit record reaches the receiver with expected origin and unchanged auditID",
                      audit_ok, {"response_id_matched_audit_and_receiver": audit_ok,
                                 "receiver_events": len(audit_seen),
                                 "source_origin": f["expected_audit_origin"]})

            enabled = {f["audit_route"]: True, **{source: True for source in f["ai_routes"]}}
            apply_json(api, routes_config(enabled))
            wait_for_routes(lab, api, enabled)
            replayed = []
            for event, source in zip(f["ai_events"], f["ai_routes"]):
                replayed.append(producer(api, "after-" + event["event_type"], source, event, 201))
            records = receiver_records(api)
            routed = [e for e in records if e.get("event_id", "").startswith("ai-1001-028-")]
            routed.sort(key=lambda event: event["event_id"])
            expected_ai = sorted(f["ai_events"], key=lambda event: event["event_id"])
            exact_ai = routed == expected_ai
            audit_still = sum(e.get("auditID") == real_id and e.get("source_origin") == f["expected_audit_origin"] for e in records) == 1
            lab.check("green", "Enabling source routes delivers the same five event types with expected origin; audit ID remains intact",
                      exact_ai and audit_still,
                      {"expected_ai": expected_ai, "replay_submissions": replayed,
                       "observed_ai": routed, "audit_id_preserved": audit_still})
            (lab.evidence / "source-routing-observations.json").write_text(json.dumps({
                "response_audit_id": real_id, "audit_source_event": k8s_event,
                "initial_routes": [f["audit_route"]], "blocked_ai_submissions": blocked,
                "receiver_before_route_enable": before, "enabled_routes": sorted(enabled),
                "replay_submissions": replayed, "receiver_after_replay": records,
            }, indent=2, sort_keys=True) + "\n")
        finally:
            lab.command("kind", "delete", "cluster", "--name", cluster,
                        "--kubeconfig", str(kubeconfig), timeout=90)
