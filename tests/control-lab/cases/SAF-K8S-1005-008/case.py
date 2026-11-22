"""Exercise defensive playbook readiness with synthetic metadata and owned fixtures."""
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAMESPACE = "saf-test"
APP = "saf1005008-responder"
SCOPE = (
    "Disposable Kind v1.36.1 and one digest-pinned Python mock responder. The case submits only "
    "checked-in synthetic alert envelopes, checks four defensive playbook records, and removes or "
    "restores only explicitly named case-owned ConfigMaps and one mock Service in saf-test. No real "
    "AI workload, model, GPU, DCGM/driver telemetry, inference endpoint, attack input, or external "
    "containment target is used. This tests a local readiness/exercise gate, not production IR capability."
)

REQUIRED = (
    "scenario", "title", "owner", "trigger", "verify", "response_action", "response", "response_action", "recovery",
    "escalation", "evidence", "exercise_cadence",
)
PLANNED_ACTIONS = {
    "training_job_integrity_review": "pause_mock_training",
    "model_artifact_integrity_review": "quarantine_mock_candidate",
    "gpu_resource_anomaly_review": "escalate_gpu_anomaly",
    "inference_route_abuse_review": "disable_mock_inference_route",
}

SERVER = r'''import json
from http.server import BaseHTTPRequestHandler, HTTPServer
PLAYBOOKS = __PLAYBOOKS__
receipts = []
by_scenario = {item["scenario"]: item for item in PLAYBOOKS}
actions = __ACTIONS__
triggers = __TRIGGERS__
class H(BaseHTTPRequestHandler):
 def reply(self, code, value):
  body=json.dumps(value,sort_keys=True).encode()
  self.send_response(code); self.send_header("Content-Type","application/json")
  self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
 def do_GET(self):
  if self.path == "/health": self.reply(200,{"ready":True,"fixture_only":True}); return
  if self.path == "/receipts": self.reply(200,receipts); return
  self.reply(404,{"error":"not_found"})
 def do_POST(self):
  if self.path != "/evaluate": self.reply(404,{"error":"not_found"}); return
  length=int(self.headers.get("Content-Length",0))
  try: event=json.loads(self.rfile.read(length))
  except Exception: self.reply(400,{"error":"invalid_json"}); return
  playbook=by_scenario.get(event.get("scenario"))
  trigger=triggers.get(event.get("scenario"), {})
  matched=bool(playbook and trigger and all(event.get(key)==value for key,value in trigger.items()))
  receipt={"event":event,"matched":matched,"owner":playbook["owner"] if matched else None,
    "scenario":event.get("scenario"),"planned_action":actions.get(event.get("scenario")) if matched else None,
    "fixture_only":True}
  receipts.append(receipt)
  self.reply(200,receipt)
 def log_message(self,*args): pass
HTTPServer(("0.0.0.0",8080),H).serve_forever()
'''


def load_fixtures():
    playbook_doc = json.loads((FIXTURES / "playbooks.json").read_text())
    alert_doc = json.loads((FIXTURES / "alert-envelopes.json").read_text())
    return playbook_doc["playbooks"], alert_doc["envelopes"], alert_doc["mock_model_artifact"]


def validate_playbooks(playbooks):
    scenarios = [item.get("scenario") for item in playbooks]
    complete = len(playbooks) == 4 and len(set(scenarios)) == 4 and set(scenarios) == set(PLANNED_ACTIONS)
    for item in playbooks:
        complete = complete and item.get("response_action") == PLANNED_ACTIONS.get(item.get("scenario"))
        complete = complete and all(key in item and item[key] for key in REQUIRED)
        complete = complete and item.get("response_action") == PLANNED_ACTIONS.get(item.get("scenario"))
        complete = complete and all(isinstance(item[key], list) and item[key] for key in
                                    ("verify", "response", "recovery", "evidence"))
    return complete


def _resource(kind, name, spec, *, labels=None):
    metadata = {"name": name, "namespace": NAMESPACE,
                "labels": {"saf-k8s-control": "SAF-K8S-1005-008", "fixture-only": "true"}}
    if labels:
        metadata["labels"].update(labels)
    result = {"apiVersion": "v1", "kind": kind, "metadata": metadata}
    result.update(spec)
    return result


def resources(artifact_text):
    return {
        "training_job_integrity_review": _resource("ConfigMap", "saf-fixture-training-run", {"data": {"state": "synthetic-running"}}),
        "model_artifact_integrity_review": _resource("ConfigMap", "saf-fixture-model-candidate", {"data": {"state": "synthetic-candidate", "artifact": artifact_text}}),
        "gpu_resource_anomaly_review": _resource("ConfigMap", "saf-fixture-gpu-observation", {"data": {"state": "synthetic-observation-only"}}),
        "inference_route_abuse_review": _resource("Service", "saf-fixture-inference-route", {"spec": {"ports": [{"name": "mock", "port": 8081, "targetPort": 8081}]}}),
    }


def _apply(lab, item):
    lab.create(item)


def _exists(lab, kind, name):
    result = lab.kubectl("get", kind, name, "-o", "json", "--ignore-not-found")
    return json.loads(result.stdout) if result.stdout.strip() else None


def _delete_exact(lab, kind, name):
    # This allowlist is the complete set of mutations the exercise can make.
    allowed = {("configmap", "saf-fixture-training-run"),
               ("configmap", "saf-fixture-model-candidate"),
               ("service", "saf-fixture-inference-route")}
    if (kind, name) not in allowed:
        lab.block("Refusing a fixture action outside the exact case-owned resource allowlist")
    current = _exists(lab, kind, name)
    labels = current.get("metadata", {}).get("labels", {}) if current else {}
    if labels.get("saf-k8s-control") != "SAF-K8S-1005-008" or labels.get("fixture-only") != "true":
        lab.block("Refusing to remove a resource without this case's fixture ownership labels")
    obj = _exists(lab, kind, name)
    if (obj is None or obj["metadata"]["namespace"] != NAMESPACE
            or obj["metadata"].get("labels", {}).get("saf-k8s-control") != "SAF-K8S-1005-008"
            or obj["metadata"].get("labels", {}).get("fixture-only") != "true"):
        lab.block("Refusing to modify a resource without the fixture ownership labels")
    lab.kubectl("delete", kind, name, "--wait=true")


def _http(lab, path, envelope=None):
    data = json.dumps(envelope, sort_keys=True) if envelope is not None else "-"
    script = "import json,sys,urllib.request; u=sys.argv[1]; d=None if sys.argv[2]=='-' else sys.argv[2].encode(); q=urllib.request.Request(u,data=d,headers={'Content-Type':'application/json'} if d else {},method='POST' if d else 'GET'); print(urllib.request.urlopen(q,timeout=5).read().decode())"
    result = lab.kubectl("exec", f"deployment/{APP}", "--", "python3", "-c", script,
                         f"http://{APP}:8080{path}", data, timeout=15)
    return json.loads(result.stdout)


def _wait_ready(lab):
    lab.kubectl("rollout", "status", f"deployment/{APP}", "--timeout=90s", timeout=100)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if _http(lab, "/health").get("ready"):
                return True
        except Exception:
            time.sleep(.5)
    return False


def _deployment(config_name, config, envelopes):
    triggers = {row["scenario"]: {key: row[key] for key in (
        "fixture_id", "source_class", "severity", "alert_name", "resource_ref", "evidence_ref",
    )} for row in envelopes if row["scenario"] in PLANNED_ACTIONS}
    script = SERVER.replace("__PLAYBOOKS__", repr(config)).replace(
        "__ACTIONS__", repr(PLANNED_ACTIONS)).replace("__TRIGGERS__", repr(triggers))
    cm = _resource("ConfigMap", config_name, {"data": {"server.py": script}})
    selector = {"app": APP}
    pod = {"automountServiceAccountToken": False,
           "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                               "seccompProfile": {"type": "RuntimeDefault"}},
           "containers": [{"name": "responder", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                           "command": ["python3", "/saf/server.py"], "ports": [{"containerPort": 8080}],
                           "readinessProbe": {"httpGet": {"path": "/health", "port": 8080}, "periodSeconds": 2},
                           "securityContext": {"allowPrivilegeEscalation": False,
                                               "readOnlyRootFilesystem": True,
                                               "capabilities": {"drop": ["ALL"]}},
                           "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                         "limits": {"cpu": "250m", "memory": "96Mi"}},
                           "volumeMounts": [{"name": "config", "mountPath": "/saf", "readOnly": True}]}],
           "volumes": [{"name": "config", "configMap": {"name": config_name}}]}
    deployment = {"apiVersion": "apps/v1", "kind": "Deployment",
                  "metadata": {"name": APP, "namespace": NAMESPACE,
                               "labels": {"saf-k8s-control": "SAF-K8S-1005-008", "fixture-only": "true"}},
                  "spec": {"replicas": 1, "selector": {"matchLabels": selector},
                           "template": {"metadata": {"labels": selector}, "spec": pod}}}
    service = _resource("Service", APP, {"spec": {"selector": selector,
                     "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})
    return cm, deployment, service


def _write_evidence(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _create_responder(lab, config_name, config, envelopes):
    for item in _deployment(config_name, config, envelopes):
        _apply(lab, item)
    if not _wait_ready(lab):
        lab.block("The case-owned synthetic responder did not become ready")


def _observe_recovery(lab, scenario, item, original, mutated):
    kind, name = item["kind"].lower(), item["metadata"]["name"]
    restored = _exists(lab, kind, name)
    if restored is None:
        return {"scenario": scenario, "recovered": False}
    expected = item.get("data")
    actual = restored.get("data")
    if kind == "service":
        expected = item["spec"]["ports"]
        actual = [{key: row[key] for key in ("name", "port", "targetPort")}
                  for row in restored["spec"]["ports"]]
    same_uid = restored["metadata"]["uid"] == original["metadata"]["uid"]
    return {"scenario": scenario, "recovered": actual == expected and same_uid != mutated
            and restored["metadata"]["labels"] == item["metadata"]["labels"],
            "resource_kind": kind, "resource_name": name, "same_uid": same_uid}


def run(lab):
    playbooks, envelopes, artifact = load_fixtures()
    expected_digest = hashlib.sha256(artifact["content"].encode()).hexdigest()
    digest_matches = expected_digest == artifact["sha256"]
    lab.check("positive", "The synthetic model artifact fixture matches its checked-in SHA-256",
              digest_matches, {"fixture_only": True, "expected_sha256": artifact["sha256"],
                               "observed_sha256": expected_digest})
    incomplete = [dict(item) for item in playbooks]
    incomplete[0].pop("owner")
    lab.check("red", "A missing responder owner blocks a four-scenario playbook package",
              not validate_playbooks(incomplete), {"missing_owner_rejected": True})
    readiness = validate_playbooks(playbooks)
    lab.check("positive", "Four scenario playbooks have owner, trigger, response, recovery, escalation, evidence and cadence fields",
              readiness, {"playbook_count": len(playbooks), "scenarios": sorted(p.get("scenario", "") for p in playbooks),
                          "required_fields": list(REQUIRED)})

    _create_responder(lab, "saf1005008-policy-disabled", [], envelopes)
    all_resources = resources(artifact["content"])
    for item in all_resources.values():
        _apply(lab, item)
    by_scenario = {item["scenario"]: item for item in playbooks}
    by_event = {item["scenario"]: item for item in envelopes}
    training = by_event["training_job_integrity_review"]
    before = _exists(lab, "configmap", "saf-fixture-training-run")
    red = _http(lab, "/evaluate", training)
    unchanged = _exists(lab, "configmap", "saf-fixture-training-run") is not None
    lab.check("red", "A synthetic incident envelope is not routed while response playbooks are disabled",
              not red["matched"] and before is not None and unchanged and red["planned_action"] is None,
              {"raw_envelope": training, "response": red, "resource_unchanged": unchanged})

    for resource in ("deployment", "service", "configmap"):
        if resource == "deployment":
            lab.kubectl("delete", "deployment", APP, "--wait=true")
        elif resource == "service":
            lab.kubectl("delete", "service", APP, "--wait=true")
        else:
            lab.kubectl("delete", "configmap", "saf1005008-policy-disabled", "--wait=true")
    _create_responder(lab, "saf1005008-policy-enabled", playbooks, envelopes)

    wrong = dict(training, resource_ref="saf-fixture-unrelated-reference")
    bad_scope = _http(lab, "/evaluate", wrong)
    lab.check("red", "A known scenario with a mismatched fixture resource is not routed",
              not bad_scope["matched"] and bad_scope["planned_action"] is None,
              {"response": bad_scope})
    observations = {"wrong_scope": bad_scope, "readiness": {"complete": readiness},
                    "disabled_baseline": {"raw_envelope": training, "raw_receipt": red,
                                          "resource_present_before": before is not None,
                                          "resource_unchanged": unchanged},
                    "scenarios": {},
                    "raw_envelopes": [], "raw_receipts": []}
    for scenario in PLANNED_ACTIONS:
        envelope = by_event[scenario]
        playbook = by_scenario[scenario]
        seed = all_resources[scenario]
        name = seed["metadata"]["name"]
        kind = seed["kind"].lower()
        before_object = _exists(lab, kind, name)
        response = _http(lab, "/evaluate", envelope)
        expected_action = PLANNED_ACTIONS[scenario]
        exact = (response.get("matched") is True and response.get("event") == envelope
                 and response.get("owner") == playbook["owner"]
                 and response.get("planned_action") == playbook["response_action"] == expected_action
                 and playbook.get("response_action") == expected_action
                 and response.get("fixture_only") is True)
        lab.check("green", f"{scenario}: envelope routes to the exact fictional playbook owner and action",
                  exact and before_object is not None,
                  {"scenario": scenario, "raw_envelope": envelope, "response": response,
                   "owner": playbook["owner"], "planned_action": expected_action,
                   "resource_present_before": before_object is not None})

        action_observation = {"action": expected_action, "resource_mutated": False}
        if scenario in ("training_job_integrity_review", "model_artifact_integrity_review"):
            _delete_exact(lab, "configmap", name)
            action_observation["resource_mutated"] = _exists(lab, "configmap", name) is None
        elif scenario == "inference_route_abuse_review":
            _delete_exact(lab, "service", name)
            action_observation["resource_mutated"] = _exists(lab, "service", name) is None
        else:
            current = _exists(lab, "configmap", name)
            action_observation["no_device_or_workload_action"] = current == before_object
        lab.check("green", f"{scenario}: only its case-owned response boundary is observed",
                  action_observation["resource_mutated"]
                  or action_observation.get("no_device_or_workload_action", False), action_observation)

        if scenario in ("training_job_integrity_review", "model_artifact_integrity_review"):
            _apply(lab, seed)
        elif scenario == "inference_route_abuse_review":
            _apply(lab, seed)
        recovery = _observe_recovery(lab, scenario, seed, before_object, action_observation["resource_mutated"])
        lab.check("positive", f"{scenario}: safe fixture recovery restores the exact case-owned resource",
                  recovery["recovered"], recovery)
        observations["raw_envelopes"].append(envelope)
        observations["raw_receipts"].append(response)
        observations["scenarios"][scenario] = {"response": response,
            "action_observation": action_observation, "recovery": recovery}
        _write_evidence(lab, "playbook-exercise.json", observations)

    healthy = by_event["healthy_observation"]
    before_names = {scenario: _exists(lab, item["kind"].lower(), item["metadata"]["name"]) is not None
                    for scenario, item in all_resources.items()}
    quiet = _http(lab, "/evaluate", healthy)
    after_names = {scenario: _exists(lab, item["kind"].lower(), item["metadata"]["name"]) is not None
                   for scenario, item in all_resources.items()}
    lab.check("positive", "A non-incident synthetic observation creates no response and changes no fixture resources",
              quiet.get("matched") is False and quiet.get("planned_action") is None and before_names == after_names,
              {"raw_envelope": healthy, "response": quiet, "resources_unchanged": before_names == after_names,
               "before": before_names, "after": after_names})
    observations["positive_control"] = {"envelope": healthy, "response": quiet,
                                         "resources_before": before_names, "resources_after": after_names}
    _write_evidence(lab, "playbook-exercise.json", observations)
