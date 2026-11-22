"""Collect only three case-owned Kubernetes Pod log streams and test routing."""
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE

CASE_DIR = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "SAF-K8S-1001-030 uses one runner-owned kind v1.36.1 cluster and the saf-test "
    "namespace. A Job, a "
    "Service-backed running Pod, and a staged pipeline Job each write one fixed "
    "synthetic JSON event to container stdout. A case-owned collector ServiceAccount "
    "gets only pods/log for the three exact fixture Pod names and posts those records "
    "to a case-owned route and receiver. The case checks the missing route, enables "
    "the fixture route, then independently compares collected records with host-side "
    "kubectl logs. It does not test a production collector, enterprise backend, log "
    "retention, source completeness beyond these three fixtures, or real AI systems."
)


def read_fixtures():
    return json.loads((CASE_DIR / "fixtures.json").read_text())


def apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource))


def workload_pod(name, workload_type, event):
    line = json.dumps(event, sort_keys=True, separators=(",", ":"))
    command = ["sh", "-c", "printf '%s\\n' \"$1\"", "fixture", line]
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {
                "saf-k8s.example/control-case": "SAF-K8S-1001-030",
                "saf-k8s.example/workload-type": workload_type,
            },
        },
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "workload",
                "image": BUSYBOX_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": command,
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
        },
    }
    if workload_type == "inference":
        endpoint = """from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            return
        if self.path != "/infer":
            self.send_error(404)
            return
        print(sys.argv[1], flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"fixture-inference-ok")

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""
        container = pod["spec"]["containers"][0]
        container.update(image=PYTHON_IMAGE, command=["python", "-u", "-c", endpoint, line],
                         readinessProbe={"tcpSocket": {"port": 8080}, "periodSeconds": 1})
    return pod


def workload_job(name, workload_type, event):
    pod = workload_pod(name + "-template", workload_type, event)
    pod["metadata"].pop("name")
    pod["metadata"].pop("namespace")
    pod["metadata"]["labels"]["job-name"] = name
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "backoffLimit": 0,
            "template": {"metadata": pod["metadata"], "spec": pod["spec"]},
        },
    }


def router_program():
    return r'''from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

APPROVED = False
RECORDS = []
CASE_ID = "SAF-K8S-1001-030"
ROUTE_ID = "fixture-pod-logs"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, value):
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self.reply(200, {"ready": True})
        elif self.path == "/state":
            self.reply(200, {"approved": APPROVED, "records": RECORDS})
        else:
            self.reply(404, {"error": "not_found"})

    def do_POST(self):
        global APPROVED
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > 65536:
            self.reply(413, {"error": "invalid_size"})
            return
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.reply(400, {"error": "invalid_json"})
            return
        if self.path == "/approve":
            if value != {"case_id": CASE_ID, "route_id": ROUTE_ID}:
                self.reply(400, {"error": "approval_scope_mismatch"})
                return
            APPROVED = True
            self.reply(200, {"approved": True, "route_id": ROUTE_ID})
            return
        if self.path != "/ingest":
            self.reply(404, {"error": "not_found"})
            return
        if not APPROVED:
            self.reply(404, {"error": "route_missing", "route_id": ROUTE_ID})
            return
        if not isinstance(value, dict) or set(value) != {"source", "event"}:
            self.reply(400, {"error": "invalid_record_shape"})
            return
        RECORDS.append(value)
        self.reply(201, {"accepted": True})

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def collector_program():
    return r'''import json
from pathlib import Path
import ssl
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

API = "https://kubernetes.default.svc"
ROUTER = "http://evidence-router:8080"
TOKEN_FILE = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
FIXTURE_FILE = Path("/fixtures/sources.json")

def api_get(path, token, context):
    request = Request(API + path, headers={"Authorization": "Bearer " + token})
    with urlopen(request, context=context, timeout=20) as response:
        return response.read().decode("utf-8")

def route_post(record):
    body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = Request(ROUTER + "/ingest", data=body, method="POST",
                      headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=20) as response:
            return response.status, response.read().decode("utf-8")
    except HTTPError as error:
        return error.code, error.read().decode("utf-8")

def main():
    phase = __import__("sys").argv[1]
    fixtures = json.loads(FIXTURE_FILE.read_text())
    namespace = fixtures["namespace"]
    token = TOKEN_FILE.read_text().strip()
    context = ssl.create_default_context(cafile=CA_FILE)
    observations = []
    for fixture in fixtures["sources"]:
        pod = quote(fixture["pod"], safe="")
        container = quote(fixture["container"], safe="")
        path = (f"/api/v1/namespaces/{quote(namespace, safe='')}/pods/{pod}/log"
                f"?container={container}&timestamps=false")
        raw = api_get(path, token, context)
        lines = [line for line in raw.splitlines() if line]
        if len(lines) != 1:
            raise RuntimeError(f"expected one fixture log line for {fixture['pod']}")
        event = json.loads(lines[0])
        if event != fixture["event"]:
            raise RuntimeError(f"fixture log did not match expected event for {fixture['pod']}")
        record = {
            "source": {
                "namespace": namespace,
                "pod": fixture["pod"],
                "container": fixture["container"],
                "workload_type": fixture["workload_type"],
            },
            "event": event,
        }
        status, body = route_post(record)
        result = json.loads(body)
        observations.append({
            "event_id": event["event_id"],
            "workload_type": fixture["workload_type"],
            "status": status,
            "route_result": result.get("error", "accepted"),
        })
        expected = 404 if phase == "missing-route" else 201
        if status != expected:
            raise RuntimeError(f"route returned {status} in phase {phase}")
    print(json.dumps({"phase": phase, "observations": observations}, sort_keys=True))

if __name__ == "__main__":
    main()
'''


def apply_router(lab):
    apply(lab, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-1001-030-router-code", "namespace": NAMESPACE},
        "data": {"router.py": router_program()},
    })
    apply(lab, {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "evidence-router", "namespace": NAMESPACE,
                      "labels": {"app": "evidence-router"}},
        "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000},
            "containers": [{
                "name": "router", "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-u", "/app/router.py"],
                "ports": [{"name": "http", "containerPort": 8080}],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                },
                "volumeMounts": [{"name": "code", "mountPath": "/app", "readOnly": True}],
            }],
            "volumes": [{"name": "code", "configMap": {"name": "saf-1001-030-router-code"}}],
        },
    })
    apply(lab, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "evidence-router", "namespace": NAMESPACE},
        "spec": {
            "selector": {"app": "evidence-router"},
            "ports": [{"name": "http", "port": 8080, "targetPort": 8080}],
        },
    })
    lab.kubectl("wait", "--for=condition=Ready", "pod/evidence-router", "--timeout=90s", timeout=100)


def job_pod_name(lab, job_name):
    result = json.loads(lab.kubectl(
        "get", "pods", "-l", f"job-name={job_name}", "-o", "json"
    ).stdout)
    items = result.get("items", [])
    if len(items) != 1:
        lab.block(f"Expected exactly one Pod for case-owned Job {job_name}")
    return items[0]["metadata"]["name"]


def wait_for_workloads(lab, fixtures):
    for fixture in fixtures:
        if fixture["workload_type"] == "inference":
            apply(lab, workload_pod(
                fixture["pod_name"], "inference", fixture["event"]
            ))
            apply(lab, {
                "apiVersion": "v1", "kind": "Service",
                "metadata": {"name": fixture["service_name"], "namespace": NAMESPACE},
                "spec": {
                    "selector": {
                        "saf-k8s.example/control-case": "SAF-K8S-1001-030",
                        "saf-k8s.example/workload-type": "inference",
                    },
                    "ports": [{"name": "http", "port": 8080, "targetPort": 8080}],
                },
            })
            lab.kubectl("wait", "--for=condition=Ready", f"pod/{fixture['pod_name']}",
                        "--timeout=90s", timeout=100)
            lab.kubectl("wait", "--for=jsonpath={.subsets[0].addresses[0].ip}",
                        f"endpoints/{fixture['service_name']}", "--timeout=30s")
            url = f"http://{fixture['service_name']}:8080"
            probe = """import sys, time, urllib.error, urllib.request
url = sys.argv[1]
deadline = time.monotonic() + 25
while True:
    try:
        with urllib.request.urlopen(url + "/healthz", timeout=2) as ready:
            if ready.status == 200:
                break
    except urllib.error.URLError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(1)
with urllib.request.urlopen(url + "/infer", timeout=5) as inference:
    print(inference.read().decode())
"""
            response = lab.kubectl("exec", "pod/evidence-router", "--", "python", "-c", probe, url)
            served = response.stdout.strip() == "fixture-inference-ok"
            lab.check("positive", "A request through the owned inference Service reaches the logging workload",
                      served, {"fixture_response_matched": served})
            fixture["pod"] = fixture["pod_name"]
        else:
            apply(lab, workload_job(
                fixture["job_name"], fixture["workload_type"], fixture["event"]
            ))
            lab.kubectl("wait", "--for=condition=complete", f"job/{fixture['job_name']}",
                        "--timeout=90s", timeout=100)
            fixture["pod"] = job_pod_name(lab, fixture["job_name"])
        fixture["container"] = "workload"


def apply_collector(lab, fixtures):
    identity = {"name": "saf-1001-030-log-reader", "namespace": NAMESPACE}
    apply(lab, {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": identity,
        "automountServiceAccountToken": True,
    })
    resource_names = sorted(fixture["pod"] for fixture in fixtures)
    role_name = "saf-1001-030-log-reader"
    apply(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": role_name, "namespace": NAMESPACE},
        "rules": [{
            "apiGroups": [""],
            "resources": ["pods/log"],
            "resourceNames": resource_names,
            "verbs": ["get"],
        }],
    })
    apply(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": role_name, "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", **identity}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": role_name},
    })
    sources = {
        "namespace": NAMESPACE,
        "sources": [{key: fixture[key] for key in (
            "workload_type", "pod", "container", "event"
        )} for fixture in fixtures],
    }
    apply(lab, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-1001-030-collector", "namespace": NAMESPACE},
        "data": {"collector.py": collector_program(),
                 "sources.json": json.dumps(sources, sort_keys=True)},
    })


def run_collector(lab, phase):
    name = "log-collector-" + phase
    apply(lab, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "backoffLimit": 0,
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "serviceAccountName": "saf-1001-030-log-reader",
                    "automountServiceAccountToken": True,
                    "restartPolicy": "Never",
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 1000},
                    "containers": [{
                        "name": "collector", "image": PYTHON_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/app/collector.py", phase],
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                        },
                        "volumeMounts": [
                            {"name": "code", "mountPath": "/app", "readOnly": True},
                            {"name": "fixtures", "mountPath": "/fixtures", "readOnly": True},
                        ],
                    }],
                    "volumes": [
                        {"name": "code", "configMap": {"name": "saf-1001-030-collector",
                                                              "items": [{"key": "collector.py", "path": "collector.py"}]}},
                        {"name": "fixtures", "configMap": {"name": "saf-1001-030-collector",
                                                                  "items": [{"key": "sources.json", "path": "sources.json"}]}},
                    ],
                },
            },
        },
    })
    lab.kubectl("wait", "--for=condition=complete", f"job/{name}", "--timeout=90s", timeout=100)
    pod_name = job_pod_name(lab, name)
    output = lab.kubectl("logs", f"pod/{pod_name}", "-c", "collector").stdout.strip()
    result = json.loads(output)
    raw_path = lab.evidence / f"raw-collector-{phase}.json"
    raw_path.write_text(json.dumps({"pod": pod_name, "stdout": output}, indent=2) + "\n")
    return result


def router_state(lab):
    code = (
        "import json,urllib.request; "
        "print(urllib.request.urlopen('http://127.0.0.1:8080/state').read().decode())"
    )
    raw = lab.kubectl("exec", "pod/evidence-router", "--", "python", "-c", code).stdout
    return json.loads(raw)


def approve_route(lab):
    code = (
        "import urllib.request; "
        "data=b'{\"case_id\":\"SAF-K8S-1001-030\",\"route_id\":\"fixture-pod-logs\"}'; "
        "r=urllib.request.Request('http://127.0.0.1:8080/approve',data=data,method='POST',"
        "headers={'Content-Type':'application/json'}); "
        "print(urllib.request.urlopen(r).read().decode())"
    )
    raw = lab.kubectl("exec", "pod/evidence-router", "--", "python", "-c", code).stdout
    (lab.evidence / "raw-route-approval.json").write_text(raw)
    return json.loads(raw)


def source_log_comparison(lab, fixtures):
    comparisons = []
    raw_sources = []
    for fixture in fixtures:
        pod_name = fixture["pod"]
        pod_json = lab.kubectl("get", "pod", pod_name, "-o", "json").stdout
        raw_log = lab.kubectl("logs", f"pod/{pod_name}", "-c", "workload").stdout
        lines = [line for line in raw_log.splitlines() if line]
        events = [json.loads(line) for line in lines]
        raw_sources.append({"pod": json.loads(pod_json), "stdout": raw_log})
        comparisons.append({
            "workload_type": fixture["workload_type"],
            "event_id": fixture["event"]["event_id"],
            "one_exact_fixture_line": events == [fixture["event"]],
            "source_identity": {
                "namespace": NAMESPACE,
                "pod": pod_name,
                "container": "workload",
                "workload_type": fixture["workload_type"],
            },
        })
    (lab.evidence / "raw-source-logs.json").write_text(
        json.dumps(raw_sources, indent=2, sort_keys=True) + "\n"
    )
    return comparisons


def expected_records(fixtures):
    return [{
        "source": {
            "namespace": NAMESPACE,
            "pod": fixture["pod"],
            "container": "workload",
            "workload_type": fixture["workload_type"],
        },
        "event": fixture["event"],
    } for fixture in fixtures]


def run(lab):
    spec = read_fixtures()
    fixtures = spec["fixtures"]
    apply_router(lab)
    wait_for_workloads(lab, fixtures)
    apply_collector(lab, fixtures)

    missing = run_collector(lab, "missing-route")
    state_before = router_state(lab)
    expected_ids = sorted(fixture["event"]["event_id"] for fixture in fixtures)
    missing_items = missing["observations"]
    missing_ok = (
        missing["phase"] == "missing-route"
        and sorted(item["event_id"] for item in missing_items) == expected_ids
        and all(item["status"] == 404 and item["route_result"] == "route_missing"
                for item in missing_items)
        and state_before == {"approved": False, "records": []}
    )
    lab.check("red", "The collector reads all three fixture logs but the absent route rejects every event",
              missing_ok, {
                  "event_ids": expected_ids,
                  "all_route_missing": all(item["status"] == 404 and
                                            item["route_result"] == "route_missing"
                                            for item in missing_items),
                  "receiver_empty": state_before["records"] == [],
              })

    approval = approve_route(lab)
    approved = run_collector(lab, "approved-route")
    state_after = router_state(lab)
    expected = expected_records(fixtures)
    source_comparison = source_log_comparison(lab, fixtures)
    receiver_records = state_after["records"]
    exact_routes = (
        approval == {"approved": True, "route_id": "fixture-pod-logs"}
        and approved["phase"] == "approved-route"
        and receiver_records == expected
        and sorted(item["event_id"] for item in approved["observations"]) == expected_ids
        and all(item["status"] == 201 and item["route_result"] == "accepted"
                for item in approved["observations"])
    )
    source_exact = len(source_comparison) == len(fixtures) and all(
        item["one_exact_fixture_line"] for item in source_comparison
    )
    identities_preserved = [
        row["source"] == source["source_identity"]
        and row["event"] == next(fixture["event"] for fixture in fixtures
                                 if fixture["workload_type"] == source["workload_type"])
        for row, source in zip(receiver_records, source_comparison)
    ]
    lab.check("green", "Approved routing preserves each exact source identity and stdout event once",
              exact_routes and source_exact and all(identities_preserved), {
                  "event_ids": expected_ids,
                  "workload_types": [fixture["workload_type"] for fixture in fixtures],
                  "source_lines_match_fixtures": source_exact,
                  "receiver_matches_independent_source": all(identities_preserved),
                  "one_record_per_source": len(receiver_records) == len(fixtures),
              })

    (lab.evidence / "raw-receiver-state.json").write_text(
        json.dumps(state_after, indent=2, sort_keys=True) + "\n"
    )
