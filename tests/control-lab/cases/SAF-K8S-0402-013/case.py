"""Exercise kubelet rotation of a synthetic projected service account token."""
import base64
import json
import subprocess
import time


NAMESPACE = "saf-test"
JOB = "saf-0402-013"
SERVICE_ACCOUNT = "saf-0402-013"
CONTAINER = "trainer"
TOKEN_PATH = "/var/run/saf-token/token"
AUDIENCE = "saf-0402-013.synthetic"
OTHER_AUDIENCE = "saf-0402-013.unrelated"
SERVER_VERSION = "v1.36.1"
EXPIRATION_SECONDS = 600
ROTATION_DEADLINE_SECONDS = 900
EXPIRY_LEEWAY_SECONDS = 60
EXPIRY_DEADLINE_SECONDS = 900
SAMPLE_INTERVAL_SECONDS = 5
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)

SCOPE = (
    "One disposable kind Job runs a synthetic non-root BusyBox workload for up to 30 minutes. "
    "Its ServiceAccount and Pod disable default automount; a separate projected "
    "serviceAccountToken requests audience saf-0402-013.synthetic for 600 seconds. "
    "The harness captures only this Pod's token file into subprocess memory, locally decodes "
    "exp/iat/aud, and sends tokens only in TokenReview request bodies. Raw token bytes never "
    "enter command arguments, logs, stdout, or evidence. Checks cover initial authentication, "
    "rejection for an unrelated audience, kubelet file refresh, stale-client expiry, a reopened "
    "file's valid token after old-token expiry, and continuity of Job/Pod/ServiceAccount identity. "
    "This does not test Vault, cloud SDKs, other training controllers, production outages, or "
    "application-specific reload implementations."
)


def _private_kubectl(lab, args, *, payload=None, timeout=45):
    """Run sensitive kubectl traffic without Lab.command's evidence logging."""
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        f"--request-timeout={max(1, timeout - 5)}s", *args,
    ]
    try:
        result = subprocess.run(
            command, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, env=lab.env, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("private Kubernetes operation failed or timed out") from error
    if result.returncode:
        raise RuntimeError("private Kubernetes operation returned a nonzero status")
    return result.stdout


def _read_token(lab, pod_name):
    raw = _private_kubectl(
        lab,
        ["--namespace", NAMESPACE, "exec", pod_name, "-c", CONTAINER, "--", "cat", TOKEN_PATH],
        timeout=30,
    )
    # Keep bytes local to this process. No error message contains the returned content.
    token = raw.decode("ascii", errors="strict").strip()
    if token.count(".") != 2 or len(token) < 100:
        raise RuntimeError("projected token did not have the expected opaque JWT shape")
    return token


def _claims(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        return {
            "iat": int(claims["iat"]),
            "exp": int(claims["exp"]),
            "aud": claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]],
        }
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("projected token claims were malformed") from error


def _review(lab, token, audience):
    # The bearer value exists only in this in-memory request body and response handling.
    body = json.dumps({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": {"token": token, "audiences": [audience]},
    }, separators=(",", ":")).encode("utf-8")
    raw = _private_kubectl(lab, ["create", "-f", "-", "-o", "json"], payload=body)
    try:
        result = json.loads(raw)
        status = result["status"]
        user = status.get("user", {})
        extra = user.get("extra", {})
        return {
            "authenticated": bool(status.get("authenticated", False)),
            "username": user.get("username", ""),
            "uid": user.get("uid", ""),
            "audiences": status.get("audiences", []),
            "pod_name": extra.get("authentication.kubernetes.io/pod-name", []),
            "pod_uid": extra.get("authentication.kubernetes.io/pod-uid", []),
        }
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("TokenReview returned an unexpected response") from error


def _one_object(lab, kind, name):
    return json.loads(lab.kubectl("get", kind, name, "-o", "json").stdout)


def _workload_pod(lab):
    data = json.loads(lab.kubectl(
        "get", "pods", "-l", f"job-name={JOB}", "-o", "json"
    ).stdout)
    items = data.get("items", [])
    if len(items) != 1:
        lab.block(f"Expected exactly one Job Pod; observed {len(items)}")
    return items[0]


def _identity(lab, pod):
    job = _one_object(lab, "job", JOB)
    sa = _one_object(lab, "serviceaccount", SERVICE_ACCOUNT)
    return {
        "job_uid": job["metadata"]["uid"],
        "pod_uid": pod["metadata"]["uid"],
        "service_account_uid": sa["metadata"]["uid"],
        "pod_name": pod["metadata"]["name"],
        "phase": pod.get("status", {}).get("phase", ""),
        "service_account": pod.get("spec", {}).get("serviceAccountName", ""),
        "automount": pod.get("spec", {}).get("automountServiceAccountToken", True),
    }


def _check_review_identity(review, identity):
    return (
        review["authenticated"]
        and review["username"] == f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
        and review["uid"] == identity["service_account_uid"]
        and review["pod_name"] == [identity["pod_name"]]
        and review["pod_uid"] == [identity["pod_uid"]]
    )


def _assert_same_running_identity(lab, expected):
    pod = _workload_pod(lab)
    current = _identity(lab, pod)
    if current != expected or current["phase"] != "Running":
        lab.block("Job/Pod/ServiceAccount identity or Running state changed during rotation")
    return current


def _job_manifest():
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": JOB},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 1800,
            "template": {
                "metadata": {"labels": {"app": JOB}},
                "spec": {
                    "serviceAccountName": SERVICE_ACCOUNT,
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "containers": [{
                        "name": CONTAINER,
                        "image": BUSYBOX_IMAGE,
                        "command": ["sh", "-ec", "while :; do sleep 5; done"],
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True,
                            "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                        "volumeMounts": [{"name": "workload-token", "mountPath": "/var/run/saf-token", "readOnly": True}],
                    }],
                    "volumes": [{
                        "name": "workload-token",
                        "projected": {"sources": [{"serviceAccountToken": {
                            "audience": AUDIENCE,
                            "expirationSeconds": EXPIRATION_SECONDS,
                            "path": "token",
                        }}]},
                    }],
                },
            },
        },
    }


def run(lab):
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server_version = version.get("serverVersion", {}).get("gitVersion", "")
    lab.check(
        "positive", "The tested API server is the pinned Kubernetes v1.36.1 target",
        server_version == SERVER_VERSION,
        {"server_git_version": server_version, "expected": SERVER_VERSION},
    )
    lab.create({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": SERVICE_ACCOUNT},
        "automountServiceAccountToken": False,
    })
    lab.create(_job_manifest())
    lab.kubectl("wait", "--for=create", "pod", "-l", f"job-name={JOB}",
                "--timeout=90s", timeout=100)
    pod_name = _workload_pod(lab)["metadata"]["name"]
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{pod_name}", "--timeout=120s", timeout=130)
    pod = _workload_pod(lab)
    identity = _identity(lab, pod)
    lab.check(
        "positive", "A continuing Job uses one explicit projected-token Pod with default automount disabled",
        identity["phase"] == "Running" and identity["service_account"] == SERVICE_ACCOUNT and not identity["automount"],
        {"phase": identity["phase"], "default_automount_disabled": not identity["automount"]},
    )

    original = _read_token(lab, pod_name)
    original_claims = _claims(original)
    if original_claims["aud"] != [AUDIENCE] or original_claims["exp"] - original_claims["iat"] != EXPIRATION_SECONDS:
        lab.block("Initial projected token did not contain the requested custom audience")
    initial_review = _review(lab, original, AUDIENCE)
    lab.check(
        "positive", "Initial short-lived token authenticates for its exact intended audience",
        _check_review_identity(initial_review, identity) and AUDIENCE in initial_review["audiences"],
        {"authenticated": initial_review["authenticated"], "username": initial_review["username"],
         "audience_match": initial_review["audiences"] == [AUDIENCE],
         "ttl_seconds": original_claims["exp"] - original_claims["iat"]},
    )
    wrong_audience = _review(lab, original, OTHER_AUDIENCE)
    lab.check(
        "positive", "The custom-audience token is not accepted for an unrelated audience",
        not wrong_audience["authenticated"],
        {"authenticated": wrong_audience["authenticated"], "audiences": wrong_audience["audiences"]},
    )

    deadline = time.monotonic() + ROTATION_DEADLINE_SECONDS
    refreshed = None
    while time.monotonic() < deadline:
        candidate = _read_token(lab, pod_name)
        if candidate != original:
            refreshed = candidate
            break
        time.sleep(SAMPLE_INTERVAL_SECONDS)
    if refreshed is None:
        lab.block("Kubelet did not replace the projected token before the 900-second rotation deadline")

    # Counterfactual application baseline: a process that cached the first read
    # continues to hold it even though a fresh open of the mounted path differs.
    stale_client_cache = original
    reopened = _read_token(lab, pod_name)
    fresh_claims = _claims(reopened)
    lab.check(
        "red", "A client that caches the original token does not follow the mounted-file replacement",
        stale_client_cache == original and stale_client_cache != reopened,
        {"cached_reader_unchanged": stale_client_cache == original, "reopened_file_changed": stale_client_cache != reopened,
         "reopened_exp_is_later": fresh_claims["exp"] > original_claims["exp"],
         "reopened_ttl_seconds": fresh_claims["exp"] - fresh_claims["iat"]},
    )
    if fresh_claims["exp"] <= original_claims["exp"] or fresh_claims["aud"] != [AUDIENCE]:
        lab.block("Reopened token did not have a later expiry and the requested custom audience")
    _assert_same_running_identity(lab, identity)
    rotated_review = _review(lab, reopened, AUDIENCE)
    reloaded_before_exp = time.time() < original_claims["exp"]
    lab.check(
        "green", "Reopening the projected path obtains a current token accepted for the same Pod identity",
        _check_review_identity(rotated_review, identity) and rotated_review["audiences"] == [AUDIENCE]
        and reloaded_before_exp,
        {"authenticated": rotated_review["authenticated"], "username": rotated_review["username"],
         "audience_match": rotated_review["audiences"] == [AUDIENCE],
         "reload_before_initial_exp": reloaded_before_exp,
         "ttl_seconds": fresh_claims["exp"] - fresh_claims["iat"]},
    )

    target = original_claims["exp"] + EXPIRY_LEEWAY_SECONDS + 1
    expiry_deadline = time.monotonic() + EXPIRY_DEADLINE_SECONDS
    while time.time() < target and time.monotonic() < expiry_deadline:
        time.sleep(min(SAMPLE_INTERVAL_SECONDS, max(1, target - time.time())))
    if time.time() < target:
        lab.block("Timed out waiting for the original token expiry plus 60-second leeway window")

    final_pod = _assert_same_running_identity(lab, identity)
    old_review = _review(lab, stale_client_cache, AUDIENCE)
    current = _read_token(lab, pod_name)
    current_claims = _claims(current)
    current_review = _review(lab, current, AUDIENCE)
    lab.check(
        "red", "A stale cached token is rejected after its JWT expiry plus 60 seconds",
        not old_review["authenticated"],
        {"authenticated": old_review["authenticated"], "checked_after_exp_and_leeway": True},
    )
    lab.check(
        "green", "A reopened current token remains valid after the original token expires",
        current != stale_client_cache and current_claims["exp"] > int(time.time())
        and _check_review_identity(current_review, identity)
        and AUDIENCE in current_review["audiences"],
        {"authenticated": current_review["authenticated"], "username": current_review["username"],
         "audience_match": current_review["audiences"] == [AUDIENCE],
         "pod_still_running": final_pod["phase"] == "Running", "same_job_uid": final_pod["job_uid"] == identity["job_uid"],
         "same_pod_uid": final_pod["pod_uid"] == identity["pod_uid"]},
    )

    (lab.evidence / "rotation-timing.json").write_text(json.dumps({
        "initial_issued_unix": original_claims["iat"], "initial_exp_unix": original_claims["exp"],
        "replacement_issued_unix": fresh_claims["iat"], "replacement_exp_unix": fresh_claims["exp"],
        "final_checked_unix": int(time.time()),
    }) + "\n")
