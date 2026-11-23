"""Exercise the pinned APISIX request-validation plugin against an owned backend."""
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

SCOPE = (
    "A pinned APISIX 3.21.0 standalone gateway in a fresh Kubernetes v1.36.1 Kind cluster. "
    "Its method, path and header route matching is already active before a separate JSON "
    "body contract is loaded. Exact owned requests verify out-of-schema rejection before "
    "backend processing. Other protocol, authentication, schema and deployment paths need "
    "separate evidence."
)

HERE = Path(__file__).resolve().parent
GATEWAY_IMAGE = (
    "docker.io/apache/apisix:3.21.0-debian@sha256:"
    "1741a8e1186e5c39ea10e6b4fb3e682534d1705efb8328195de5b41ad0657380"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
BACKEND = "saf-contract-backend"
GATEWAY = "saf-contract-gateway"
CLIENT = "saf-contract-client"
HEADER = "fixture-api"
ERROR = "Fixed fixture request violates the JSON body contract"
TYPE_ERROR = '{"marker":"type-1","quantity":"7"}'
FIELDS_ERROR = '{"marker":"field-2","quantity":5,"extra":true}'
RANGE_ERROR = '{"marker":"range-3","quantity":100}'
VALID = '{ "quantity": 99, "marker": "good-1" }'
PROTECTED = "/submit"


def apply(lab, obj):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(obj))


def config(lab, name, files):
    apply(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": files})


def deploy(lab, name, spec, port, volume):
    labels = {"app": name}
    spec.update(ports=[{"name": "http", "containerPort": port}],
                readinessProbe={"tcpSocket": {"port": "http"}, "periodSeconds": 1})
    apply(lab, {
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
        "spec": {
            "replicas": 1, "selector": {"matchLabels": labels},
            "template": {"metadata": {"labels": labels}, "spec": {
                "automountServiceAccountToken": False, "containers": [spec],
                "volumes": [{"name": "config", "configMap": {"name": volume}}],
            }},
        },
    })
    apply(lab, {
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
        "spec": {"type": "ClusterIP", "selector": labels,
                 "ports": [{"port": port, "targetPort": "http"}]},
    })
    wait_deployment(lab, name)


def wait_deployment(lab, name):
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=115s", timeout=125)


def gateway_routes(schema):
    backend = {"type": "roundrobin", "nodes": {f"{BACKEND}.saf-test.svc.cluster.local:8080": 1}}
    protected = {"id": "contract-submission", "uri": PROTECTED, "methods": ["POST"],
                 "vars": [["http_x_api_client", "==", HEADER]], "upstream": backend}
    if schema is not None:
        protected["plugins"] = {
            "request-validation": {
                "body_schema": schema,
                "header_schema": {"type": "object", "required": ["Content-Type"],
                                  "properties": {"Content-Type": {"type": "string", "enum": ["application/json"]}}},
                "max_req_body_size": 1024, "rejected_code": 422, "rejected_msg": ERROR,
            },
        }
    return {"routes": [protected, {"id": "health", "uri": "/health", "methods": ["GET"], "upstream": backend}]}


def gateway_config(lab, schema):
    config(lab, GATEWAY, {"config.yaml": (HERE / "gateway.yaml").read_text(),
                          "apisix.json": json.dumps(gateway_routes(schema))})


def request(lab, body="", *, method="POST", path=PROTECTED, header=HEADER, allow_unready=False):
    result = lab.kubectl("exec", CLIENT, "--", "python", "-c", (HERE / "probe.py").read_text(),
                         method, path, header, body, timeout=15, allow_failure=allow_unready)
    return json.loads(result.stdout) if result.returncode == 0 else {}


def wait_route(lab):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        response = request(lab, method="GET", path="/health", allow_unready=True)
        if response.get("status") == 200 and json.loads(response["body"]) == {"healthy": True}:
            return
        time.sleep(0.5)
    lab.block("Owned APISIX health route did not become active")


def arrivals(lab):
    log = lab.kubectl("logs", f"deployment/{BACKEND}").stdout
    return [json.loads(line)["arrival"] for line in log.splitlines()]


def backend_response(result, marker):
    return result["status"] == 200 and json.loads(result["body"]) == {"arrived": marker}


def run(lab):
    config(lab, BACKEND, {"backend.py": (HERE / "backend.py").read_text()})
    deploy(lab, BACKEND, container(
        "backend", image=PYTHON_IMAGE, command=["python", "-u", "/fixture/backend.py"],
        volumeMounts=[{"name": "config", "mountPath": "/fixture", "readOnly": True}],
    ), 8080, BACKEND)
    lab.create(pod(CLIENT, [container(
        "client", image=PYTHON_IMAGE, command=["python", "-c", "import time; time.sleep(600)"],
    )], automountServiceAccountToken=False))
    ready(lab, CLIENT)

    gateway_config(lab, None)
    deploy(lab, GATEWAY, {
        "name": "gateway", "image": GATEWAY_IMAGE,
        "securityContext": {"allowPrivilegeEscalation": False},
        "volumeMounts": [
            {"name": "config", "mountPath": f"/usr/local/apisix/conf/{name}", "subPath": name, "readOnly": True}
            for name in ("config.yaml", "apisix.json")
        ],
    }, 9080, GATEWAY)
    wait_route(lab)
    cases = {"type": (TYPE_ERROR, "type-1"), "additional_field": (FIELDS_ERROR, "field-2"),
             "range": (RANGE_ERROR, "range-3")}
    baseline = {case: backend_response(request(lab, body), marker)
                for case, (body, marker) in cases.items()}
    baseline_arrivals = arrivals(lab)
    lab.check("red", "The same three JSON contract violations reach the backend before schema enforcement",
              all(baseline.values()) and baseline_arrivals == [marker for _, marker in cases.values()],
              {"marker_checks": baseline, "backend_arrivals": baseline_arrivals})
    wrong_header = request(lab, VALID, header="fixture-other")
    lab.check("positive", "The existing route matcher rejects a wrong header without body validation",
              wrong_header["status"] == 404 and arrivals(lab) == baseline_arrivals,
              {"http_status": wrong_header["status"], "backend_unchanged": arrivals(lab) == baseline_arrivals})

    gateway_config(lab, json.loads((HERE / "schema.json").read_text()))
    lab.kubectl("rollout", "restart", f"deployment/{GATEWAY}")
    wait_deployment(lab, GATEWAY)
    wait_route(lab)
    rejected = {case: request(lab, body) for case, (body, _) in cases.items()}
    proof = {
        name: {"http_status": response["status"], "exact_policy_response": response["body"] == ERROR}
        for name, response in rejected.items()
    }
    unchanged = arrivals(lab) == baseline_arrivals
    lab.check("green", "APISIX emits exact 422 policy results and no contract violation reaches the backend",
              unchanged and all(value == {"http_status": 422, "exact_policy_response": True}
                                for value in proof.values()),
              {"contract_rejections": proof, "backend_unchanged": unchanged})
    allowed = request(lab, VALID)
    marker_ok = backend_response(allowed, "good-1")
    final_arrivals = arrivals(lab)
    lab.check("positive", "A schema-valid request with alternative JSON formatting reaches the backend",
              marker_ok and final_arrivals == [*baseline_arrivals, "good-1"],
              {"marker_matched": marker_ok, "http_status": allowed["status"], "backend_arrivals": final_arrivals})
    (lab.evidence / "contract-observations.json").write_text(
        json.dumps({"rejected": proof, "valid_marker_matched": marker_ok, "backend_arrivals": final_arrivals},
                   indent=2, sort_keys=True) + "\n"
    )
