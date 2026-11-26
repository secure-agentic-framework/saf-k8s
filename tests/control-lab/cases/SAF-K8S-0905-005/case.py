"""Exercise synthetic promotion decisions and a pinned Ed25519 evidence verifier."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from fixtures import container, pod
from signature_format import public_key_id


NAMESPACE = "saf-test"
REPORTER = "gate-reporter"
UNAPPROVED = "unapproved-reporter"
GATE_SA = "promotion-gate"
REPORTER_USERNAME = f"system:serviceaccount:{NAMESPACE}:{REPORTER}"
UNAPPROVED_USERNAME = f"system:serviceaccount:{NAMESPACE}:{UNAPPROVED}"
EVIDENCE_NAME = "promotion-evidence"
AUDIENCE = "https://promotion.saf.invalid"
IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
SIGNER_IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
                "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
SIGNER_POD = "promotion-signature-worker"
SIGNER_CONFIG = "promotion-signature-input"
TRUST_CONFIG = "promotion-approved-signer"
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
    "robustness plus matching builder/model/predicate digests and a valid Ed25519 signature "
    "under a case-pinned ephemeral public key. Wrong-key and signed-then-rebound envelopes are "
    "refused before evidence persistence. This proves only the fixture signature-verification "
    "decision over fixed synthetic records; it does not prove evaluator efficacy, real model "
    "quality, independently administered key custody, report-writer audit attribution, or a "
    "production promotion workflow."
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
                            "predicate_sha256": predicate_digest}}


SIGNER_COMMAND = "exec python /fixture/signature_worker.py"


def _signer_pod():
    mounts = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "fixture", "configMap": {"name": SIGNER_CONFIG}}]
    return pod(SIGNER_POD, [container(
        "signer", image=SIGNER_IMAGE, command=["sh", "-ec", SIGNER_COMMAND],
        env=[{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
        volumeMounts=mounts,
        resources={"requests": {"cpu": "25m", "memory": "64Mi"},
                   "limits": {"cpu": "500m", "memory": "256Mi"}})],
        automountServiceAccountToken=False, volumes=volumes)


def _signed(evidence, label, signing_material):
    result = json.loads(json.dumps(evidence))
    result["attestation"]["signature"] = signing_material["signatures"][label]
    result["attestation"]["signer_key_id"] = signing_material["approved_key_id"]
    return result


def _resource_version(lab):
    resource = json.loads(lab.kubectl(
        "get", "configmap", EVIDENCE_NAME, "-o", "json").stdout)
    return resource["metadata"]["resourceVersion"]


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
                                            "readOnly": True},
                                           {"name": "trust", "mountPath": "/trust",
                                            "readOnly": True}])],
                         "volumes": [{"name": "fixture", "configMap": {"name": "promotion-gate"}},
                                     {"name": "trust", "configMap": {"name": TRUST_CONFIG}}]}}}}


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
                "metadata": {"name": EVIDENCE_NAME, "namespace": NAMESPACE,
                             "labels": {"saf.example/evidence": "promotion-gate"}},
                "data": {}})

    requests = {"enforcement_absent": _evidence("security", "fail")}
    for gate in GATES:
        for state in ("missing", "fail"):
            requests[f"{gate}_{state}"] = _evidence(gate, state)
    requests["unauthorized_reporter"] = _evidence()
    requests["wrong_subject_digest"] = _evidence()
    requests["wrong_subject_digest"]["artifact"]["sha256"] = "0" * 64
    requests["wrong_predicate_digest"] = _evidence()
    requests["wrong_predicate_digest"]["attestation"]["predicate_sha256"] = "0" * 64
    requests["positive"] = _evidence()

    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": SIGNER_CONFIG, "namespace": NAMESPACE},
                "data": {
                    "signing-input.json": json.dumps({"evidence": requests}, sort_keys=True),
                    "signature_worker.py": (HERE / "signature_worker.py").read_text(),
                    "signature_format.py": (HERE / "signature_format.py").read_text(),
                    "report_crypto.py": (HERE / "report_crypto.py").read_text(),
                }})
    lab.create(_signer_pod())
    signer_wait = lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded",
                              f"pod/{SIGNER_POD}", "--timeout=120s", timeout=130,
                              allow_failure=True)
    if signer_wait.returncode:
        lab.kubectl("describe", "pod", SIGNER_POD, allow_failure=True)
        lab.kubectl("logs", SIGNER_POD, allow_failure=True)
        lab.block("Ephemeral signature fixture did not complete")
    try:
        signing_material = json.loads(lab.kubectl("logs", SIGNER_POD).stdout)
        if (set(signing_material["signatures"]) != set(requests) or
                signing_material["approved_key_id"] !=
                public_key_id(signing_material["approved_public_pem"]) or
                signing_material["unapproved_key_id"] == signing_material["approved_key_id"]):
            raise ValueError("signature fixture output did not match the scoped inputs")
    except (ValueError, KeyError, TypeError):
        lab.block("Ephemeral signature fixture output was invalid")
    lab.kubectl("delete", "pod", SIGNER_POD, "--wait=true", "--timeout=30s")
    lab.kubectl("delete", "configmap", SIGNER_CONFIG)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": TRUST_CONFIG, "namespace": NAMESPACE},
                "immutable": True,
                "data": {"approved-public.pem": signing_material["approved_public_pem"],
                         "approved-key-id": signing_material["approved_key_id"]}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "promotion-gate", "namespace": NAMESPACE},
                "data": {"gate.py": (HERE / "gate.py").read_text(),
                         "signature_format.py": (HERE / "signature_format.py").read_text(),
                         "report_crypto.py": (HERE / "report_crypto.py").read_text()}})

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
        baseline = _signed(requests["enforcement_absent"], "enforcement_absent", signing_material)
        status, body = _post(off_url, reporter_token, EVIDENCE_NAME, baseline)
        observations["enforcement_absent"] = {"http_status": status, "response": body,
                                              "evidence": baseline}

        for gate in GATES:
            for state in ("missing", "fail"):
                label = f"{gate}_{state}"
                evidence = _signed(requests[label], label, signing_material)
                status, body = _post(on_url, reporter_token, EVIDENCE_NAME, evidence)
                observations[f"{gate}_{state}"] = {"http_status": status,
                                                    "response": body, "evidence": evidence}

        valid = _signed(requests["unauthorized_reporter"], "unauthorized_reporter", signing_material)
        status, body = _post(on_url, other_token, EVIDENCE_NAME, valid)
        observations["unauthorized_reporter"] = {"http_status": status, "response": body}
        wrong_subject = _signed(requests["wrong_subject_digest"], "wrong_subject_digest", signing_material)
        status, body = _post(on_url, reporter_token, EVIDENCE_NAME, wrong_subject)
        observations["wrong_subject_digest"] = {"http_status": status, "response": body,
                                                "evidence": wrong_subject}
        wrong_predicate = _signed(requests["wrong_predicate_digest"], "wrong_predicate_digest", signing_material)
        status, body = _post(on_url, reporter_token, EVIDENCE_NAME, wrong_predicate)
        observations["wrong_predicate_digest"] = {"http_status": status, "response": body,
                                                  "evidence": wrong_predicate}
        valid = _signed(requests["positive"], "positive", signing_material)
        status, body = _post(on_url, reporter_token, EVIDENCE_NAME, valid)
        observations["positive"] = {"http_status": status, "response": body, "evidence": valid}

        version_before_wrong_signer = _resource_version(lab)
        wrong_signer = json.loads(json.dumps(valid))
        wrong_signer["attestation"]["signature"] = signing_material["unapproved_signature"]
        wrong_signer["attestation"]["signer_key_id"] = signing_material["unapproved_key_id"]
        status, body = _post(on_url, reporter_token, EVIDENCE_NAME, wrong_signer)
        version_after_wrong_signer = _resource_version(lab)
        observations["wrong_signer"] = {
            "http_status": status, "response": body,
            "key_id_differs_from_approved": signing_material["unapproved_key_id"] !=
                signing_material["approved_key_id"],
            "resource_version_unchanged": version_before_wrong_signer == version_after_wrong_signer,
        }

        version_before_rebound = _resource_version(lab)
        rebound = json.loads(json.dumps(valid))
        rebound_digest = hashlib.sha256(b"SAF inert rebound marker v2\n").hexdigest()
        rebound["artifact"] = {"name": "saf-fixture-model-rebound-v2", "sha256": rebound_digest}
        rebound["attestation"]["subject_sha256"] = rebound_digest
        rebound["attestation"]["predicate_sha256"] = hashlib.sha256(
            _canonical({"artifact": rebound["artifact"], "gates": rebound["gates"]})
        ).hexdigest()
        status, body = _post(on_url, reporter_token, EVIDENCE_NAME, rebound)
        version_after_rebound = _resource_version(lab)
        observations["rebound_evidence"] = {
            "http_status": status, "response": body,
            "resource_version_unchanged": version_before_rebound == version_after_rebound,
        }
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
              accepted.get("signature_verification") == "verified" and
              valid["attestation"]["signer_key_id"] == signing_material["approved_key_id"] and
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
               "approved_key_id_matches": valid["attestation"]["signer_key_id"] ==
                   signing_material["approved_key_id"],
               "evidence_read_back": accepted.get("evidence_read_back")})

    wrong_signer = observations["wrong_signer"]
    wrong_signer_result = wrong_signer["response"]
    lab.check("green", "The enforcing gate rejects a complete envelope signed by the unapproved fixture key before persistence",
              wrong_signer["http_status"] == 403 and
              wrong_signer_result.get("accepted") is False and
              wrong_signer_result.get("signature_verification") == "failed" and
              wrong_signer_result.get("reason") == "unapproved-signing-key" and
              wrong_signer_result.get("evidence_read_back") is False and
              wrong_signer["key_id_differs_from_approved"] and
              wrong_signer["resource_version_unchanged"],
              {"http_status": wrong_signer["http_status"],
               "accepted": wrong_signer_result.get("accepted"),
               "signature_verification": wrong_signer_result.get("signature_verification"),
               "reason": wrong_signer_result.get("reason"),
               "evidence_read_back": wrong_signer_result.get("evidence_read_back"),
               "key_id_differs_from_approved": wrong_signer["key_id_differs_from_approved"],
               "resource_version_unchanged": wrong_signer["resource_version_unchanged"]})

    rebound = observations["rebound_evidence"]
    rebound_result = rebound["response"]
    lab.check("green", "The enforcing gate rejects a signed evidence envelope rebound to a different inert model before persistence",
              rebound["http_status"] == 403 and
              rebound_result.get("accepted") is False and
              rebound_result.get("signature_verification") == "failed" and
              rebound_result.get("reason") == "invalid-signature" and
              rebound_result.get("evidence_read_back") is False and
              rebound["resource_version_unchanged"],
              {"http_status": rebound["http_status"],
               "accepted": rebound_result.get("accepted"),
               "signature_verification": rebound_result.get("signature_verification"),
               "reason": rebound_result.get("reason"),
               "evidence_read_back": rebound_result.get("evidence_read_back"),
               "resource_version_unchanged": rebound["resource_version_unchanged"]})
