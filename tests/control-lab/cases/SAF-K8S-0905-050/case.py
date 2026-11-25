"""Exercise authenticated reviewer identity at a fixed Kubernetes promotion gate."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
import time
import urllib.error
import urllib.request

from fixtures import container
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("saf_0905_050_native_human", HERE / "native_human.py")
human = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(human)
NAMESPACE = "saf-test"
REVIEWER = "model-reviewer"
OTHER = "other-reviewer"
USERNAME = f"system:serviceaccount:{NAMESPACE}:{REVIEWER}"
PROMOTION_AUDIENCE = "https://promotion.saf.invalid"
OTHER_AUDIENCE = "https://other.saf.invalid"
DECISION = {"model": "saf-fixture-model-v1", "environment": "production"}
HUMAN_DECISION = {**DECISION, "artifact_digest": "sha256:" + "a" * 64}
HUMAN_USERNAME = "oidc-fixture:human-probe"
IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
SCOPE = (
    "Kubernetes v1.36.1 runs case-owned copies of a small promotion API. The original two receive the "
    "same case-minted ServiceAccount token and fixed inert decision; the disabled gate accepts it, "
    "while the enabled gate uses authentication.k8s.io/v1 TokenReview with a fixed audience and "
    "an exact reviewer allowlist. The enabled gate rejects wrong-audience, missing, and "
    "authenticated-but-unapproved identities and accepts the allowlisted reviewer. This proves "
    "the Kubernetes token identity and audience boundary for one inert decision. "
    "A third copy validates an owned synthetic OIDC JWT through native API-server JWT authentication "
    "and TokenReview, binds its session and exact artifact digest at the gate, and checks a narrowly "
    "scoped native SubjectAccessReview grant that the case withdraws. This remains synthetic lab "
    "evidence; enterprise identity provider login, MFA, human session issuance, and production "
    "workflow coverage require separate evidence."
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


class FixtureUnavailable(RuntimeError):
    """The case endpoint is temporarily unable to use its backing reviewer."""


def _post_decision(url, token, decision=DECISION, *, comparison="decision"):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url + "/decision", data=json.dumps(decision).encode(),
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
        known_errors = {"identity-review-unavailable", "authorization-review-unavailable",
                        "not-found", "invalid-decision"}
        reason = body.get("error") if isinstance(body, dict) else None
        if reason not in known_errors:
            reason = "unexpected-fixture-response"
        if status == 503 and reason == "identity-review-unavailable":
            detail = body.get("reason")
            allowed = {"tokenreview-http-400", "tokenreview-http-401", "tokenreview-http-403",
                       "tokenreview-http-500", "tokenreview-http-503",
                       "tokenreview-transport-or-response", "tokenreview-failed"}
            detail = detail if isinstance(detail, str) and detail in allowed else "tokenreview-failed"
            message = f"Promotion {comparison} returned HTTP {status}: {reason} ({detail})"
            if detail not in {"tokenreview-http-400", "tokenreview-http-401", "tokenreview-http-403"}:
                raise FixtureUnavailable(message)
            raise RuntimeError(message)
        raise RuntimeError(f"Promotion {comparison} returned HTTP {status}: {reason}")
    if not isinstance(body, dict) or "error" in body:
        raise RuntimeError("promotion endpoint returned a fixture or server error")
    return status, body


def _post_after_api_restart(url, token, comparison):
    deadline = time.monotonic() + 45
    while True:
        try:
            return _post_decision(url, token, HUMAN_DECISION, comparison=comparison)
        except FixtureUnavailable:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


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
                           "verbs": ["create"]},
                          {"apiGroups": ["authorization.k8s.io"],
                           "resources": ["subjectaccessreviews"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": "saf-promotion-tokenreview"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                            "name": "saf-promotion-tokenreview"},
                "subjects": [{"kind": "ServiceAccount", "name": "promotion-gate",
                              "namespace": NAMESPACE}]})

    gate_code = (HERE / "gate.py").read_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "promotion-gate"},
                "data": {"gate.py": gate_code}})
    for name, enforce, human_mode in (("promotion-gate-off", "false", False),
                                      ("promotion-gate-on", "true", False),
                                      ("promotion-gate-human", "true", True)):
        label = {"app": name}
        lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                    "metadata": {"name": name},
                    "spec": {"replicas": 1, "selector": {"matchLabels": label},
                             "template": {"metadata": {"labels": label}, "spec": {
                                 "serviceAccountName": "promotion-gate",
                                 "containers": [container(
                                     "gate", image=IMAGE,
                                     command=["python", "/fixture/gate.py"],
                                     env=([{"name": "ENFORCE_REVIEWER", "value": enforce},
                                           {"name": "REVIEWER_USERNAME", "value": USERNAME},
                                           {"name": "PROMOTION_AUDIENCE", "value": PROMOTION_AUDIENCE}] +
                                          ([{"name": "HUMAN_REVIEWER_USERNAME", "value": HUMAN_USERNAME}]
                                           if human_mode else [])),
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

    _run_native_human_checks(lab)


def _run_native_human_checks(lab):
    """Use API-server JWT authentication, TokenReview, session/path checks, and native SAR."""
    node = lab.cluster + "-control-plane"
    reviewer_group = "oidc-fixture:reviewers"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "promotion-approval"},
                "data": {"fixture": "synthetic-review-target"}})
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "saf-human-review"},
            "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                       "resourceNames": ["promotion-approval"], "verbs": ["get"]}]}
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
               "metadata": {"name": "saf-human-review"},
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                           "name": "saf-human-review"},
               "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group",
                             "name": reviewer_group}]}
    lab.create(role)
    lab.create(binding)

    with TemporaryDirectory(prefix="saf-human-oidc-") as dirname:
        temp = Path(dirname)
        human.start_issuer(lab, node, temp, HERE / "issuer.py")
        now = int(time.time())
        claims = {"iss": "https://127.0.0.1:17443", "aud": human.AUDIENCE,
                  "sub": "human-probe", "iat": now - 10, "exp": now + 300,
                  "groups": ["reviewers"], "fixture_class": "human-review",
                  "session": "session-fixture-01", "approval_path": HUMAN_DECISION}
        approved_key = temp / "approved.key"
        approved = human.mint_jwt(lab, approved_key, claims)
        baseline_process, baseline_url = _start_forward(lab, "promotion-gate-human")
        try:
            baseline_status, baseline = _post_decision(baseline_url, approved, HUMAN_DECISION, comparison="before issuer registration")
        finally:
            _stop(baseline_process)
        old_api = human.api_container(lab, node)
        if old_api is None:
            lab.block("The disposable API container is unavailable before configuration")
        try:
            human.configure_api(lab, node, temp)
            human.wait_api_replacement(lab, node, old_api)

            wrong_path = human.mint_jwt(lab, approved_key,
                                  {**claims, "approval_path": {**HUMAN_DECISION,
                                                                "artifact_digest": "sha256:" + "b" * 64}})
            wrong_session = human.mint_jwt(lab, approved_key,
                                     {**claims, "session": "session-fixture-other"})
            wrong_reviewer = human.mint_jwt(lab, approved_key,
                                      {**claims, "sub": "other-human"})
            wrong_audience = human.mint_jwt(lab, approved_key, {**claims, "aud": OTHER_AUDIENCE})
            forwards = []
            try:
                process, url = _start_forward(lab, "promotion-gate-human")
                forwards.append(process)
                positive_status, positive = _post_after_api_restart(
                    url, approved, "approved native reviewer")
                path_status, path_result = _post_decision(url, wrong_path, HUMAN_DECISION, comparison="wrong signed path")
                session_status, session_result = _post_decision(url, wrong_session, HUMAN_DECISION, comparison="wrong signed session")
                reviewer_status, reviewer_result = _post_decision(url, wrong_reviewer, HUMAN_DECISION, comparison="different reviewer")
                audience_status, audience_result = _post_decision(
                    url, wrong_audience, HUMAN_DECISION, comparison="wrong JWT audience")
                lab.kubectl("delete", "rolebinding/saf-human-review")
                revoked_status, revoked = _post_decision(url, approved, HUMAN_DECISION, comparison="withdrawn grant")
                lab.create(binding)
            finally:
                for process in forwards:
                    _stop(process)
        finally:
            active_api = human.api_container(lab, node)
            human.restore_api(lab, node)
        human.wait_api_replacement(lab, node, active_api)
        restored_ready = True
        restored_process, restored_url = _start_forward(lab, "promotion-gate-human")
        try:
            disabled_status, disabled = _post_after_api_restart(
                restored_url, approved, "restored API")
        finally:
            _stop(restored_process)

    identity = positive.get("identity", {})
    restored_identity = disabled.get("identity", {})
    (lab.evidence / "native-human-session-observations.json").write_text(json.dumps({
        "pre_auth_http": baseline_status,
        "native_authenticated_username": identity.get("username"),
        "native_authenticated_group_present": reviewer_group in identity.get("groups", []),
        "approved_http": positive_status,
        "wrong_path_http": path_status,
        "wrong_session_http": session_status,
        "wrong_reviewer_http": reviewer_status,
        "wrong_native_jwt_audience_http": audience_status,
        "revoked_native_rbac_grant_http": revoked_status,
        "revoked_reason": revoked.get("reason"),
        "restored_api_ready": restored_ready,
        "temporary_issuer_disabled_http": disabled_status,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("green", "The native Kubernetes API rejects the synthetic human JWT before its issuer is configured",
              baseline_status == 403 and baseline.get("accepted") is False,
              {"http_status": baseline_status, "accepted": baseline.get("accepted")})
    lab.check("positive", "Kubernetes JWT authentication plus TokenReview binds the approved reviewer session and exact artifact path",
              positive_status == 200 and positive.get("accepted") is True and
              identity.get("authenticated") is True and identity.get("username") == HUMAN_USERNAME and
              reviewer_group in identity.get("groups", []) and
              identity.get("http_status") == 201 and
              positive.get("reason") == "native-rbac-grant",
              {"http_status": positive_status, "authenticated": identity.get("authenticated"),
               "username_match": identity.get("username") == HUMAN_USERNAME,
               "reviewer_group_present": reviewer_group in identity.get("groups", []),
               "native_tokenreview_http": identity.get("http_status"),
               "reason": positive.get("reason")})
    lab.check("green", "A cryptographically valid reviewer JWT cannot approve a different artifact path",
              path_status == 403 and path_result.get("reason") == "session-or-path-rejected",
              {"http_status": path_status, "reason": path_result.get("reason")})
    lab.check("green", "A cryptographically valid reviewer JWT from another session is denied",
              session_status == 403 and session_result.get("reason") == "session-or-path-rejected",
              {"http_status": session_status, "reason": session_result.get("reason")})
    lab.check("green", "A different native human subject cannot use the approved reviewer's grant",
              reviewer_status == 403 and reviewer_result.get("reason") == "identity-or-group-rejected",
              {"http_status": reviewer_status, "reason": reviewer_result.get("reason")})
    wrong_identity = audience_result.get("identity", {})
    lab.check("green", "The native JWT authenticator rejects a signed reviewer token with the wrong audience",
              audience_status == 403 and wrong_identity.get("http_status") == 201
              and wrong_identity.get("authenticated") is False,
              {"http_status": audience_status, "native_tokenreview_http": wrong_identity.get("http_status"),
               "native_authenticated": wrong_identity.get("authenticated")})
    lab.check("green", "Removing the case RoleBinding withdraws native SAR authorization for the exact review target",
              revoked_status == 403 and revoked.get("reason") == "native-rbac-grant-withdrawn" and
              revoked.get("identity", {}).get("authenticated") is True,
              {"http_status": revoked_status, "reason": revoked.get("reason"),
               "identity_still_authenticated": revoked.get("identity", {}).get("authenticated")})
    lab.check("positive", "The disposable API is ready after restoration and no longer accepts the fixture issuer",
              restored_ready and disabled_status == 403 and restored_identity.get("http_status") == 201
              and restored_identity.get("authenticated") is False,
              {"api_ready": restored_ready, "fixture_issuer_disabled_http": disabled_status,
               "fixture_issuer_authenticated": restored_identity.get("authenticated")})
