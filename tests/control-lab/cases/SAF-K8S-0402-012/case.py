"""Defensive synthetic test of projected ServiceAccount token lifetime."""
import base64
from datetime import datetime, timezone
import json
import subprocess
import time


NAMESPACE = "saf-test"
ACCOUNT = "saf-0402-012-reader"
TOKEN_AUDIENCE = "https://kubernetes.default.svc"
TTL_SECONDS = 600
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
SCOPE = (
    "Fresh runner-owned Kind cluster using Kubernetes v1.36.1. Synthetic Jobs "
    "project an explicit relying-party audience with expirationSeconds=600. "
    "A completed Job's retained Pod token still authenticates to TokenReview "
    "while within its issued TTL. A second Job's original token is checked "
    "before and after expiry on its still-running bound Pod; a fresh credential "
    "from another Job continues to authenticate. No changed clocks, external "
    "systems, or persistent credentials."
)


def quiet_kubectl(lab, *args, payload=None, timeout=30):
    """Run token-bearing reads without transcript, stdout, argv, or evidence."""
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        f"--request-timeout={max(1, timeout - 5)}s", "-n", NAMESPACE, *args,
    ]
    try:
        result = subprocess.run(command, input=payload, capture_output=True, text=True,
                                env=lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Credential-safe kubectl operation failed: {type(error).__name__}")
    if result.returncode:
        lab.block(f"Credential-safe kubectl operation failed with exit {result.returncode}")
    return result


def job(name, seconds=None):
    command = (f'exec sleep {seconds}' if seconds is not None else
               'while [ ! -f /tmp/saf-complete ]; do sleep 1; done')
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name},
        "spec": {"backoffLimit": 0,
                 "template": {
                     "metadata": {"labels": {"app": name}},
                     "spec": {
                         "serviceAccountName": ACCOUNT,
                         "automountServiceAccountToken": False,
                         "restartPolicy": "Never",
                         "containers": [{
                             "name": "work", "image": IMAGE,
                             "command": ["sh", "-ec", command],
                             "volumeMounts": [{"name": "token", "mountPath": "/var/run/saf-token",
                                               "readOnly": True}],
                             "securityContext": {
                                 "allowPrivilegeEscalation": False,
                                 "capabilities": {"drop": ["ALL"]},
                                 "runAsNonRoot": True, "runAsUser": 65534,
                                 "seccompProfile": {"type": "RuntimeDefault"},
                             },
                         }],
                         "volumes": [{"name": "token", "projected": {"sources": [{
                             "serviceAccountToken": {"audience": TOKEN_AUDIENCE,
                                                      "expirationSeconds": TTL_SECONDS,
                                                      "path": "token"}
                         }]}}],
                     },
                 }},
    }


def pod_for(lab, job_name):
    selector = f"job-name={job_name}"
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "pods", "-l", selector,
                             "-o", "jsonpath={.items[0].metadata.name}", allow_failure=True)
        name = result.stdout.strip()
        if result.returncode == 0 and name:
            return name
        time.sleep(1)
    lab.block(f"Job {job_name} did not create a Pod within 90 seconds")


def wait_ready(lab, pod_name):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{pod_name}", "--timeout=90s", timeout=100)


def freeze_projected_token(lab, pod_name):
    # Only the supervisor subprocess's captured memory holds the token bytes.
    result = quiet_kubectl(lab, "exec", pod_name, "--", "cat", "/var/run/saf-token/token")
    token = result.stdout.strip()
    if not token or token.count(".") != 2:
        lab.block("Projected token was empty or was not a JWT")
    return token


def jwt_exp(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        exp = int(claims["exp"])
        issued = int(claims["iat"])
        aud = claims.get("aud", [])
        if isinstance(aud, str):
            aud = [aud]
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("Projected JWT claims could not be decoded") from error
    if TOKEN_AUDIENCE not in aud:
        raise RuntimeError("Projected JWT did not contain the requested audience")
    return exp, exp - issued


def review(lab, token, pod_name):
    body = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                       "spec": {"audiences": [TOKEN_AUDIENCE], "token": token}})
    response = quiet_kubectl(lab, "create", "-f", "-", "-o", "json", payload=body)
    status = json.loads(response.stdout)["status"]
    accepted = status.get("authenticated") is True
    if accepted:
        user = status.get("user", {})
        if (user.get("username") != f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}"
                or user.get("extra", {}).get("authentication.kubernetes.io/pod-name") != [pod_name]
                or status.get("audiences") != [TOKEN_AUDIENCE]):
            lab.block("TokenReview returned the wrong bound workload identity")
    return accepted


def run(lab):
    lab.kubectl("create", "serviceaccount", ACCOUNT)

    # Baseline: completion alone does not expire an unexpired bound token.
    lab.kubectl("create", "-f", "-", payload=json.dumps(job("saf-0402-012-early")))
    early_pod = pod_for(lab, "saf-0402-012-early")
    wait_ready(lab, early_pod)
    early_token = freeze_projected_token(lab, early_pod)
    early_exp, early_ttl = jwt_exp(early_token)
    before_completion = review(lab, early_token, early_pod)
    lab.kubectl("exec", early_pod, "--", "touch", "/tmp/saf-complete")
    lab.kubectl("wait", "--for=condition=complete", "job/saf-0402-012-early",
                "--timeout=90s", timeout=100)
    retained = json.loads(lab.kubectl("get", f"pod/{early_pod}", "-o", "json").stdout)
    pod_retained = (retained["status"]["phase"] == "Succeeded"
                    and "deletionTimestamp" not in retained["metadata"])
    early_result = review(lab, early_token, early_pod)
    lab.check("red", "A completed Job's retained Pod token remains usable before its requested TTL expires",
              early_result and before_completion
              and early_ttl == TTL_SECONDS and int(time.time()) < early_exp and pod_retained,
              {"job_complete": True, "pod_retained": pod_retained, "issued_ttl_seconds": early_ttl,
               "authenticated_before_completion": before_completion, "authenticated_after_completion": early_result})

    # Implementation probe: keep a separate Pod alive, freezing its original token
    # while kubelet is free to rotate the projected file in place.
    lab.kubectl("create", "-f", "-", payload=json.dumps(job("saf-0402-012-running", 720)))
    running_pod = pod_for(lab, "saf-0402-012-running")
    wait_ready(lab, running_pod)
    frozen = freeze_projected_token(lab, running_pod)
    exp, issued_ttl = jwt_exp(frozen)
    active_uid = lab.kubectl('get', f'pod/{running_pod}', '-o', 'jsonpath={.metadata.uid}').stdout
    before = review(lab, frozen, running_pod)
    lab.check("red", "The original projected token is accepted before its own exp while the Job is running",
              before and issued_ttl == TTL_SECONDS and exp > time.time(),
              {"authenticated": before, "issued_ttl_seconds": issued_ttl})

    # The authenticator allows 60 seconds of JWT clock skew. Bound the poll
    # while keeping the original Job and bound Pod in place.
    while time.time() < exp:
        time.sleep(min(5, max(0.1, exp - time.time())))
    deadline = exp + 70
    expired = review(lab, frozen, running_pod)
    while expired and time.time() < deadline:
        time.sleep(3)
        expired = review(lab, frozen, running_pod)
    current = json.loads(lab.kubectl("get", f"pod/{running_pod}", "-o", "json").stdout)
    retained_uid = (current["metadata"]["uid"] == active_uid
                    and current["status"]["phase"] == "Running"
                    and "deletionTimestamp" not in current["metadata"])
    lab.check("green", "The API rejects the original token after expiration with its bound Pod still running",
              not expired and retained_uid and time.time() >= exp,
              {"authenticated": expired, "same_bound_pod_running": retained_uid})
    (lab.evidence / "expiry-timing.json").write_text(json.dumps({
        "issued_unix": exp - issued_ttl, "expiration_unix": exp,
        "rejection_checked_at": datetime.now(timezone.utc).isoformat(),
    }) + "\n")

    # Check a newly projected credential after expiry against the same verifier.
    lab.kubectl("create", "-f", "-", payload=json.dumps(job("saf-0402-012-fresh", 90)))
    fresh_pod = pod_for(lab, "saf-0402-012-fresh")
    wait_ready(lab, fresh_pod)
    fresh_token = freeze_projected_token(lab, fresh_pod)
    fresh_result = review(lab, fresh_token, fresh_pod)
    lab.check("positive", "A fresh same-scope projected token still performs TokenReview authentication after old-token expiry",
              fresh_result and fresh_pod != running_pod,
              {"authenticated": fresh_result,
               "same_audience": True, "same_service_account": True,
               "different_pod": fresh_pod != running_pod})

    # Drop all raw token references from the case frame before returning.
    frozen = fresh_token = early_token = None
