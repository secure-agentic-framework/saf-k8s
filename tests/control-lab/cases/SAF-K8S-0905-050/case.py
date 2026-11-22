"""Exercise authenticated reviewer identity at a fixed Kubernetes promotion gate."""
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
REVIEWER = "model-reviewer"
OTHER = "other-reviewer"
USERNAME = f"system:serviceaccount:{NAMESPACE}:{REVIEWER}"
PROMOTION_AUDIENCE = "https://promotion.saf.invalid"
OTHER_AUDIENCE = "https://other.saf.invalid"
DECISION = {"model": "saf-fixture-model-v1", "environment": "production"}
IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
SCOPE = (
    "Kubernetes v1.36.1 runs two case-owned copies of a small promotion API. Both receive the "
    "same case-minted ServiceAccount token and fixed inert decision; the disabled gate accepts it, "
    "while the enabled gate uses authentication.k8s.io/v1 TokenReview with a fixed audience and "
    "an exact reviewer allowlist. The enabled gate rejects wrong-audience, missing, and "
    "authenticated-but-unapproved identities and accepts the allowlisted reviewer. This proves "
    "the Kubernetes token identity/audience boundary for one inert decision only; external OIDC/SSO, "
    "human session binding, audit binding, and deployed workflow coverage need separate evidence."
)


def _safe_token(lab, service_account, audience):
    """Mint a real API-server-issued token without persisting or logging its value."""
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
            f"kind-{lab.cluster}", "--namespace", NAMESPACE, "create", "token",
            service_account, "--audience", audience, "--duration=10m"]
    try:
        result = subprocess.run(args, text=True, capture_output=True, env=dict(lab.env), timeout=30)
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
            lab.block("Port-forward exited before the gate became reachable")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    lab.block("Promotion gate readiness timed out")


def _post_decision(url, token):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url + "/decision", data=json.dumps(DECISION).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status, body = response.status, json.load(response)
    except urllib.error.HTTPError as response:
        # The server returns JSON for policy denials; transport/server failures are not controls.
        try:
            body = json.load(response)
        except (ValueError, OSError):
            raise RuntimeError("promotion endpoint returned a non-JSON error") from None
        status = response.code
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        raise RuntimeError("promotion endpoint request failed") from None
    if status not in (200, 403):
        raise RuntimeError("promotion endpoint returned an unexpected HTTP status")
    if not isinstance(body, dict) or "error" in body:
        raise RuntimeError("promotion endpoint returned a fixture or server error")
    return status, body


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


def run(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": REVIEWER, "namespace": NAMESPACE}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": OTHER, "namespace": NAMESPACE}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": "promotion-gate", "namespace": NAMESPACE}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": "saf-promotion-tokenreview"},
                "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"],
                           "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": "saf-promotion-tokenreview"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                            "name": "saf-promotion-tokenreview"},
                "subjects": [{"kind": "ServiceAccount", "name": "promotion-gate",
                              "namespace": NAMESPACE}]})

    gate_code = (HERE / "gate.py").read_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "promotion-gate"},
                "data": {"gate.py": gate_code}})
    for name, enforce in (("promotion-gate-off", "false"), ("promotion-gate-on", "true")):
        label = {"app": name}
        lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                    "metadata": {"name": name},
                    "spec": {"replicas": 1, "selector": {"matchLabels": label},
                             "template": {"metadata": {"labels": label}, "spec": {
                                 "serviceAccountName": "promotion-gate",
                                 "containers": [container(
                                     "gate", image=IMAGE,
                                     command=["python", "/fixture/gate.py"],
                                     env=[{"name": "ENFORCE_REVIEWER", "value": enforce},
                                          {"name": "REVIEWER_USERNAME", "value": USERNAME},
                                          {"name": "PROMOTION_AUDIENCE", "value": PROMOTION_AUDIENCE}],
                                     ports=[{"name": "http", "containerPort": 8080}],
                                     volumeMounts=[{"name": "fixture", "mountPath": "/fixture",
                                                    "readOnly": True}])],
                                 "volumes": [{"name": "fixture", "configMap": {"name": "promotion-gate"}}]}}}})
        lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                    "spec": {"selector": label, "ports": [{"name": "http", "port": 8080,
                                                              "targetPort": 8080}]}})
        lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)

    wrong_audience = _safe_token(lab, REVIEWER, OTHER_AUDIENCE)
    allowed_token = _safe_token(lab, REVIEWER, PROMOTION_AUDIENCE)
    unapproved_token = _safe_token(lab, OTHER, PROMOTION_AUDIENCE)
    forwards = []
    try:
        off_process, off_url = _start_forward(lab, "promotion-gate-off")
        forwards.append(off_process)
        on_process, on_url = _start_forward(lab, "promotion-gate-on")
        forwards.append(on_process)

        red_status, red = _post_decision(off_url, wrong_audience)
        green_status, green = _post_decision(on_url, wrong_audience)
        unapproved_status, unapproved = _post_decision(on_url, unapproved_token)
        missing_status, missing = _post_decision(on_url, "")
        positive_status, positive = _post_decision(on_url, allowed_token)
    except RuntimeError as error:
        lab.block(str(error))
    finally:
        for process in forwards:
            _stop(process)

    observations = {"decision": DECISION,
                    "gate_disabled_wrong_audience": {"http_status": red_status, **red},
                    "wrong_audience": {"http_status": green_status, **green},
                    "unapproved_identity": {"http_status": unapproved_status, **unapproved},
                    "missing_credential": {"http_status": missing_status, **missing},
                    "authorized_reviewer": {"http_status": positive_status, **positive}}
    (lab.evidence / "reviewer-identity-observations.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n")

    lab.check("red", "With the deployed gate disabled, the same fixed decision accepts its case-minted wrong-audience credential",
              red_status == 200 and red.get("accepted") is True and
              red.get("reason") == "gate-disabled",
              {"decision_accepted": red.get("accepted"), "gate": "disabled", "http_status": red_status})
    identity = green.get("identity", {})
    lab.check("green", "The deployed gate rejects that credential because TokenReview does not authenticate it for the promotion audience",
              green_status == 403 and green.get("accepted") is False and
              identity.get("http_status") == 201 and identity.get("authenticated") is False and
              PROMOTION_AUDIENCE not in identity.get("audiences", []),
              {"decision_accepted": False, "tokenreview_authenticated": identity.get("authenticated"),
               "returned_audiences": identity.get("audiences", []), "http_status": green_status})
    identity = unapproved.get("identity", {})
    lab.check("green", "A different authenticated ServiceAccount cannot approve the fixed decision",
              unapproved_status == 403 and unapproved.get("accepted") is False and
              identity.get("authenticated") is True and
              identity.get("username") == f"system:serviceaccount:{NAMESPACE}:{OTHER}" and
              PROMOTION_AUDIENCE in identity.get("audiences", []),
              {"tokenreview_authenticated": identity.get("authenticated"),
               "reviewer_allowlist_match": False, "audiences": identity.get("audiences", [])})
    lab.check("green", "The deployed gate rejects a request with no reviewer credential",
              missing_status == 403 and missing.get("accepted") is False and
              missing.get("reason") == "missing-credential",
              {"decision_accepted": False, "credential_present": False, "http_status": missing_status})
    identity = positive.get("identity", {})
    lab.check("positive", "The allowlisted reviewer is authenticated for the promotion audience and accepted",
              positive_status == 200 and positive.get("accepted") is True and
              identity.get("http_status") == 201 and identity.get("authenticated") is True and
              identity.get("username") == USERNAME and
              PROMOTION_AUDIENCE in identity.get("audiences", []),
              {"decision_accepted": positive.get("accepted"),
               "tokenreview_authenticated": identity.get("authenticated"),
               "reviewer_allowlist_match": True, "audiences": identity.get("audiences", [])})
