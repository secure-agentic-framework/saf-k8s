"""Verify the selected metadata-control evidence model and an inert session fixture."""

import json
from pathlib import Path

SCOPE = "Read synthetic inventory records and exercise session-required access to a case-owned public marker."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
INVENTORY = {
    "approved-current": {"declared_tokens": "required", "live": {"HttpEndpoint": "enabled", "HttpTokens": "required", "State": "applied"}},
    "declared-only": {"declared_tokens": "required"},
    "drifted-current": {"declared_tokens": "required", "live": {"HttpEndpoint": "enabled", "HttpTokens": "optional", "State": "applied"}},
    "pending-change": {"declared_tokens": "required", "live": {"HttpEndpoint": "enabled", "HttpTokens": "required", "State": "pending"}},
    "disabled-endpoint": {"declared_tokens": "optional", "live": {"HttpEndpoint": "disabled", "HttpTokens": "optional", "State": "applied"}},
}
CLIENT = '''import json, time
from urllib.request import Request, urlopen
from urllib.error import HTTPError

def fetch(url, method='GET', token=None):
    req = Request(url, method=method)
    if token:
        req.add_header('X-Fixture-Session', token)
    try:
        with urlopen(req, timeout=4) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)

strict = 'http://session-required:8080'
legacy = 'http://session-optional:8080'
legacy_status, legacy_body = fetch(legacy + '/marker')
missing_status, _ = fetch(strict + '/marker')
created, session = fetch(strict + '/fixture-session', method='POST')
issued = session['fixture_session']
allowed_status, allowed_body = fetch(strict + '/marker', token=issued)
time.sleep(2.3)
expired_status, _ = fetch(strict + '/marker', token=issued)
print(json.dumps({'optional_public_marker': legacy_status == 200 and legacy_body.get('fixture') == 'public-node-marker',
                  'missing_status': missing_status, 'session_issued': created == 201,
                  'approved_public_marker': allowed_status == 200 and allowed_body.get('fixture') == 'public-node-marker',
                  'expired_status': expired_status}))
'''


def add_server(lab, name, mode):
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                         "volumes": [{"name": "fixture", "configMap": {"name": "metadata-fixture"}}],
                         "containers": [{"name": "fixture", "image": IMAGE, "command": ["python", "/fixture/fixture.py"],
                                         "env": [{"name": "REQUIRE_SESSION", "value": mode}],
                                         "readinessProbe": {"httpGet": {"path": "/health", "port": 8080}, "periodSeconds": 1},
                                         "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                                         "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                       "limits": {"cpu": "100m", "memory": "64Mi"}},
                                         "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                             "capabilities": {"drop": ["ALL"]}}}]}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                "spec": {"selector": {"app": name}, "ports": [{"port": 8080, "targetPort": 8080}]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=60s", timeout=70)


def current_result(record):
    settings = record.get("live", {})
    if settings.get("State") != "applied":
        return "unverified"
    if settings.get("HttpEndpoint") == "disabled":
        return "no-endpoint"
    if settings.get("HttpEndpoint") != "enabled":
        return "unverified"
    return {"required": "session-required", "optional": "session-not-required"}.get(settings.get("HttpTokens"), "unverified")


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "metadata-fixture"}, "immutable": True,
                "data": {"fixture.py": Path(__file__).with_name("fixture.py").read_text(), "inventory.json": json.dumps(INVENTORY)}})
    add_server(lab, "session-optional", "no")
    add_server(lab, "session-required", "yes")
    observed = json.loads(lab.kubectl("exec", "session-optional", "--", "python", "-c", CLIENT, timeout=40).stdout)
    lab.check("red", "Without the fixture session requirement the owned public marker is returned",
              observed["optional_public_marker"], {"optional_marker_visible": observed["optional_public_marker"]})
    denied = observed["missing_status"] == observed["expired_status"] == 401
    lab.check("green", "The session-required fixture rejects missing and expired sessions",
              denied, {"missing_status": observed["missing_status"], "expired_status": observed["expired_status"]})
    read = json.loads(lab.kubectl("get", "configmap", "metadata-fixture", "-o", "json").stdout)
    inventory = json.loads(read["data"]["inventory.json"])
    categories = {node: current_result(row) for node, row in inventory.items()}
    expected = {"approved-current": "session-required", "declared-only": "unverified", "drifted-current": "session-not-required",
                "pending-change": "unverified", "disabled-endpoint": "no-endpoint"}
    lab.check("green", "The evidence gate separates effective settings, drift, endpoint disabled and incomplete observations",
              categories == expected, {"invented_inventory_classification": categories})
    lab.check("positive", "The live fixture returns the marker during its issued session",
              observed["session_issued"] and observed["approved_public_marker"], {"in_session_public_marker": observed["approved_public_marker"]})
    (lab.evidence / "metadata-fixture-observations.json").write_text(json.dumps({
        "scope": "synthetic endpoint and inventory", "fixture_response": observed, "inventory": categories,
    }, indent=2) + "\n")
