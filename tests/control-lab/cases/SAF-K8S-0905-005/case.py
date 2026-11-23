"""Exercise four synthetic promotion observations and evidence identity at a deployed gate."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

from fixtures import container


HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
REPORTER = "gate-reporter"
UNAPPROVED = "unapproved-reporter"
GATE_SA = "promotion-gate"
REPORTER_USERNAME = f"system:serviceaccount:{NAMESPACE}:{REPORTER}"
UNAPPROVED_USERNAME = f"system:serviceaccount:{NAMESPACE}:{UNAPPROVED}"
EVIDENCE_NAME = "promotion-evidence"
AUDIENCE = "https://promotion.saf.invalid"
IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
MODEL_BYTES = b"SAF inert model fixture v1\n"
MODEL_DIGEST = hashlib.sha256(MODEL_BYTES).hexdigest()
GATES = ("security", "bias", "performance", "robustness")
SCOPE = (
    "A disposable Kubernetes v1.36.1 cluster runs two copies of a case-owned HTTP promotion "
    "gate against the same inert model identity: one enforcement-disabled baseline and one "
    "enforcing gate. The enabled gate authenticates a short-lived reporter ServiceAccount "
    "token with authentication.k8s.io/v1 TokenReview, accepts evidence only from that exact "
    "principal and audience, persists the submitted fixed evidence in a namespace-scoped "
    "ConfigMap, reads it back, and requires pass results for security, bias, performance and "
    "robustness plus matching builder/model/predicate digests. It records signature verification "
    "as unverified. This proves the fixture API/RBAC/TokenReview and deterministic policy path "
    "for fixed synthetic records only; it does not prove evaluator efficacy, genuine model "
    "quality, cryptographic signature trust, report-writer audit attribution, or production "
    "promotion workflow coverage."
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _evidence(gate=None, outcome=None):
    results = {name: {"status": "pass"} for name in GATES}
    if gate is not None:
        if outcome == "missing":
            del results[gate]
        else:
            results[gate] = {"status": "fail"}
    artifact = {"name": "saf-fixture-model-v1", "sha256": MODEL_DIGEST}
    predicate_digest = hashlib.sha256(_canonical({"artifact": artifact, "gates": results})).hexdigest()
    return {"artifact": artifact,
            "gates": results,
            "attestation": {"builder": "fixture://saf-k8s/0905-005",
                            "subject_sha256": MODEL_DIGEST,
                            "predicate_sha256": predicate_digest,
                            "signature_verification": "unverified"}}


def _safe_token(lab, service_account):
    """Mint a token without persisting or logging its value."""
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
            f"kind-{lab.cluster}", "--namespace", NAMESPACE, "create", "token",
            service_account, "--audience", AUDIENCE, "--duration=10m"]
    try:
        result = subprocess.run(args, text=True, capture_output=True,
                                env=dict(lab.env), timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("TokenRequest did not complete")
    if result.returncode or not result.stdout.strip():
        lab.block("TokenRequest failed")
    return result.stdout.strip()


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_http(url, process, lab, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            lab.block("Promotion gate port-forward exited before readiness")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    lab.block("Promotion gate readiness timed out")


def _post(url, token, evidence_name, evidence):
    body = json.dumps({"evidence_name": evidence_name, "evidence": evidence},
                      sort_keys=True).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url + "/evaluate", data=body,
                                     headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, result = response.status, json.load(response)
    except urllib.error.HTTPError as response:
        try:
            result = json.load(response)
        except (ValueError, OSError):
            raise RuntimeError("promotion endpoint returned a non-JSON error") from None
        status = response.code
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        raise RuntimeError("promotion endpoint request failed") from None
    if status not in (200, 403):
        raise RuntimeError("promotion endpoint returned an unexpected HTTP status")
    if not isinstance(result, dict) or "error" in result:
        raise RuntimeError("promotion endpoint returned a fixture or server error")
    return status, result


def _start_forward(lab, service):
    port = _free_port()
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
            f"kind-{lab.cluster}", "--namespace", NAMESPACE, "port-forward",
            f"service/{service}", f"{port}:8080", "--address=127.0.0.1"]
    try:
        process = subprocess.Popen(args, env=dict(lab.env), stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
    except OSError:
        lab.block("Promotion gate port-forward could not start")
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_http(url + "/healthz", process, lab)
    except Exception:
        _stop(process)
        raise
    return process, url


def _stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def _deployment(name, enforce):
    labels = {"app": name}
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name},
            "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                     "template": {"metadata": {"labels": labels}, "spec": {
                         "serviceAccountName": GATE_SA,
                         "containers": [container(
                             "gate", image=IMAGE,
                             command=["python", "/fixture/gate.py"],
                             env=[{"name": "ENFORCE_GATES", "value": enforce},
                                  {"name": "PROMOTION_AUDIENCE", "value": AUDIENCE},
                                  {"name": "REPORTER_USERNAME", "value": REPORTER_USERNAME}],
                             ports=[{"name": "http", "containerPort": 8080}],
                             volumeMounts=[{"name": "fixture", "mountPath": "/fixture",
                                            "readOnly": True}])],
                         "volumes": [{"name": "fixture", "configMap": {"name": "promotion-gate"}}]}}}}


def _service(name):
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
            "spec": {"selector": {"app": name},
                     "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}}


def run(lab):
    for name in (REPORTER, UNAPPROVED, GATE_SA):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                    "metadata": {"name": name, "namespace": NAMESPACE}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": "saf-promotion-gate-tokenreview"},
                "rules": [{"apiGroups": ["authentication.k8s.io"],
                           "resources": ["tokenreviews"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": "saf-promotion-gate-tokenreview"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                            "name": "saf-promotion-gate-tokenreview"},
                "subjects": [{"kind": "ServiceAccount", "name": GATE_SA,
                              "namespace": NAMESPACE}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "saf-promotion-evidence"},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": [EVIDENCE_NAME],
                           "verbs": ["get", "update"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "saf-promotion-evidence"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": "saf-promotion-evidence"},
                "subjects": [{"kind": "ServiceAccount", "name": GATE_SA,
                              "namespace": NAMESPACE}]})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "promotion-gate", "namespace": NAMESPACE},
                "data": {"gate.py": (HERE / "gate.py").read_text()}})

    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": EVIDENCE_NAME, "namespace": NAMESPACE,
                             "labels": {"saf.example/evidence": "promotion-gate"}},
                "data": {}})

    for name, enforce in (("promotion-gate-off", "false"),
                          ("promotion-gate-on", "true")):
        lab.create(_deployment(name, enforce))
        lab.create(_service(name))
        lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)

    reporter_token = _safe_token(lab, REPORTER)
    other_token = _safe_token(lab, UNAPPROVED)
    forwards = []
    try:
        off_process, off_url = _start_forward(lab, "promotion-gate-off")
        forwards.append(off_process)
        on_process, on_url = _start_forward(lab, "promotion-gate-on")
        forwards.append(on_process)
        observations = {}
        baseline = _evidence("security", "fail")
        status, body = _post(off_url, reporter_token, EVIDENCE_NAME, baseline)
        observations["enforcement_absent"] = {"http_status": status, "response": body,
                                              "evidence": baseline}

        for gate in GATES:
            for state in ("missing", "fail"):
                evidence = _evidence(gate, state)
                status, body = _post(on_url, reporter_token, EVIDENCE_NAME, evidence)
                observations[f"{gate}_{state}"] = {"http_status": status,
                                                    "response": body, "evidence": evidence}

        valid = _evidence()
        status, body = _post(on_url, other_token, EVIDENCE_NAME, valid)
        observations["unauthorized_reporter"] = {"http_status": status, "response": body}
        wrong_subject = _evidence()
        wrong_subject["artifact"]["sha256"] = "0" * 64
        status, body = _post(on_url, reporter_token, EVIDENCE_NAME, wrong_subject)
        observations["wrong_subject_digest"] = {"http_status": status, "response": body,
                                                "evidence": wrong_subject}
        wrong_predicate = _evidence()
        wrong_predicate["attestation"]["predicate_sha256"] = "0" * 64
        status, body = _post(on_url, reporter_token, EVIDENCE_NAME, wrong_predicate)
        observations["wrong_predicate_digest"] = {"http_status": status, "response": body,
                                                  "evidence": wrong_predicate}
        status, body = _post(on_url, reporter_token, EVIDENCE_NAME, valid)
        observations["positive"] = {"http_status": status, "response": body, "evidence": valid}
    except RuntimeError as error:
        lab.block(str(error))
    finally:
        for process in forwards:
            _stop(process)

    (lab.evidence / "promotion-gate-observations.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n")
    baseline = observations["enforcement_absent"]
    lab.check("red", "The same inert model record is accepted when enforcement is absent",
              baseline["http_status"] == 200 and
              baseline["response"].get("reason") == "enforcement-disabled",
              {"http_status": baseline["http_status"],
               "gate": "disabled", "synthetic_security_result": "fail"})

    for gate in GATES:
        for state in ("missing", "fail"):
            observation = observations[f"{gate}_{state}"]
            result = observation["response"]
            expected = "missing" if state == "missing" else "fail"
            lab.check("green", f"The enforcing gate rejects {state} {gate} evidence",
                      observation["http_status"] == 403 and result.get("accepted") is False and
                      result.get("gate_results", {}).get(gate) == expected and
                      result.get("evidence_read_back") is True,
                      {"gate": gate, "expected": expected,
                       "observed": result.get("gate_results", {}).get(gate),
                       "http_status": observation["http_status"],
                       "evidence_read_back": result.get("evidence_read_back")})

    unauthorized = observations["unauthorized_reporter"]
    lab.check("green", "An authenticated but unapproved reporting principal is denied",
              unauthorized["http_status"] == 403 and
              unauthorized["response"].get("reason") == "reporter-not-authorized",
              {"http_status": unauthorized["http_status"],
               "reason": unauthorized["response"].get("reason")})

    for key, label in (("wrong_subject_digest", "artifact subject digest"),
                       ("wrong_predicate_digest", "predicate digest")):
        observation = observations[key]
        result = observation["response"]
        lab.check("green", f"The enforcing gate rejects a mismatched {label}",
                  observation["http_status"] == 403 and result.get("accepted") is False and
                  result.get("provenance_matches") is False,
                  {"http_status": observation["http_status"],
                   "accepted": result.get("accepted"),
                   "provenance_matches": result.get("provenance_matches")})

    positive = observations["positive"]
    accepted = positive["response"]
    lab.check("positive", "Matching fixed evidence and artifact/predicate digests permit the inert promotion",
              positive["http_status"] == 200 and accepted.get("accepted") is True and
              accepted.get("reporter") == REPORTER_USERNAME and
              accepted.get("gate_results") == {gate: "pass" for gate in GATES} and
              accepted.get("model_sha256") == MODEL_DIGEST and
              accepted.get("artifact_matches") is True and
              accepted.get("predicate_sha256") == valid["attestation"]["predicate_sha256"] and
              accepted.get("provenance_matches") is True and
              accepted.get("signature_verification") == "unverified" and
              accepted.get("evidence_read_back") is True,
              {"http_status": positive["http_status"], "accepted": accepted.get("accepted"),
               "reporter": accepted.get("reporter"),
               "gate_results": accepted.get("gate_results"),
               "artifact_sha256_matches": accepted.get("model_sha256") == MODEL_DIGEST,
               "artifact_matches": accepted.get("artifact_matches"),
               "predicate_sha256_matches": accepted.get("predicate_sha256") ==
                   valid["attestation"]["predicate_sha256"],
               "provenance_matches": accepted.get("provenance_matches"),
               "signature_verification": accepted.get("signature_verification"),
               "evidence_read_back": accepted.get("evidence_read_back")})
