"""SAF-K8S-0402-014: Pod-bound token lifecycle in disposable Kind."""
import base64
import json
import subprocess
import time


IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
NAMESPACE = "saf-test"
AUDIENCE = "saf-0402-014.synthetic"
SCOPE = (
    "Pinned Kubernetes v1.36.1 Kind only. Synthetic TokenRequest credentials are "
    "bound to disposable Job Pods and reviewed with in-cluster TokenReview; one "
    "separate Pod identity is the positive control. No cloud, Vault, offline JWT, "
    "or production credential lifecycle is exercised."
)


def _run(lab, args, payload=None, timeout=45):
    """Capture API output in memory; never put request/response bodies in logs."""
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", "--namespace", NAMESPACE,
        f"--request-timeout={timeout - 5}s", *args,
    ]
    with (lab.evidence / "commands.log").open("a", encoding="utf-8") as log:
        log.write("$ kubectl " + " ".join(args) + " [bodies and output withheld]\n")
    try:
        result = subprocess.run(command, input=payload, text=True, capture_output=True,
                                env=lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("A scoped Kubernetes API operation could not complete")
    if result.returncode:
        # Errors can include server details; keep only an operation-level outcome.
        lab.block(f"kubectl operation failed: {args[0]}")
    return result.stdout


def _json(lab, *args, payload=None, timeout=45):
    try:
        return json.loads(_run(lab, list(args), payload, timeout))
    except json.JSONDecodeError:
        lab.block("Kubernetes returned a non-JSON response to a JSON request")


def _apply(lab, obj):
    _run(lab, ["apply", "-f", "-", "-o", "name"], json.dumps(obj))


def _pod(name, service_account):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "restartPolicy": "Never", "serviceAccountName": service_account,
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "idle", "image": IMAGE,
                "command": ["sh", "-c", "sleep 3600"],
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
            }],
        },
    }


def _job(name, service_account, ttl=None, *, failure=False):
    metadata = {"name": name, "namespace": NAMESPACE}
    if ttl is not None:
        metadata["labels"] = {"saf-k8s.example/ttl-probe": "true"}
    spec = {
        "backoffLimit": 0,
        "template": {
            "metadata": {"labels": {"saf-k8s.example/job": name}},
            "spec": {
                "restartPolicy": "Never", "serviceAccountName": service_account,
                "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "hold", "image": IMAGE,
                    "command": ["sh", "-ec",
                                "while [ ! -f /tmp/saf-finish ]; do sleep 1; done; "
                                + ("exit 17" if failure else "exit 0")],
                    "securityContext": {"allowPrivilegeEscalation": False,
                                        "capabilities": {"drop": ["ALL"]}},
                }],
            },
        },
    }
    if ttl is not None:
        spec["ttlSecondsAfterFinished"] = ttl
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": metadata, "spec": spec}


def _wait_pod(lab, selector, deadline_seconds=150):
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        result = _json(lab, "get", "pods", "-l", selector, "-o", "json")
        for pod in result.get("items", []):
            if pod.get("status", {}).get("phase") == "Running":
                return pod
        time.sleep(2)
    lab.block(f"Timed out waiting for Running Pod selected by {selector}")


def _token(lab, service_account, pod):
    """Token bytes stay in process memory; they are never printed or logged."""
    raw = _run(lab, [
        "create", "token", service_account, f"--audience={AUDIENCE}",
        "--duration=1h", "--bound-object-kind=Pod",
        f"--bound-object-name={pod['metadata']['name']}",
        f"--bound-object-uid={pod['metadata']['uid']}",
    ], timeout=45).strip()
    if not raw or raw.count(".") != 2:
        lab.block("TokenRequest did not return a JWT-shaped credential")
    try:
        payload = raw.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        expires = int(claims["exp"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        lab.block("Synthetic token did not contain a readable expiration claim")
    return raw, expires


def _review(lab, token):
    response = _json(lab, "create", "-f", "-", "-o", "json", payload=json.dumps({
        "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
        "spec": {"token": token, "audiences": [AUDIENCE]},
    }))
    status = response.get("status", {})
    return bool(status.get("authenticated")), status


def _finish(lab, pod_name, failure=False):
    _run(lab, ["exec", pod_name, "--", "touch", "/tmp/saf-finish"], timeout=30)
    expected = "Failed" if failure else "Complete"
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        job = _json(lab, "get", "job", pod_name.rsplit("-", 1)[0], "-o", "json")
        conditions = job.get("status", {}).get("conditions", [])
        if any(c.get("type") == expected and c.get("status") == "True" for c in conditions):
            pod = _json(lab, "get", "pod", pod_name, "-o", "json")
            (container,) = pod["status"]["containerStatuses"]
            if container["state"]["terminated"]["exitCode"] != (17 if failure else 0):
                lab.block("Job did not reach its controlled termination exit code")
            return job
        if expected == "Complete" and any(c.get("type") == "Failed" and c.get("status") == "True" for c in conditions):
            lab.block("Success probe Job failed instead of completing")
        if expected == "Failed" and any(c.get("type") == "Complete" and c.get("status") == "True" for c in conditions):
            lab.block("Failure probe Job completed instead of failing")
        time.sleep(1)
    lab.block(f"Job did not reach expected {expected} condition")


def _exists(lab, resource, name):
    result = subprocess.run([
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", NAMESPACE, "--request-timeout=10s", "get", resource, name,
        "-o", "name",
    ], text=True, capture_output=True, env=lab.env, timeout=15)
    if result.returncode == 0:
        return True
    if result.returncode == 1 and "NotFound" in result.stderr:
        return False
    lab.block(f"Could not determine whether {resource}/{name} exists")


def _wait_gone(lab, job_name, pod_name, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job_exists = _exists(lab, "job", job_name)
        pod_exists = _exists(lab, "pod", pod_name)
        if not job_exists and not pod_exists:
            return
        time.sleep(2)
    lab.block(f"TTL did not remove Job and dependent Pod {job_name} within {timeout}s")


def _matches(status, service_account, pod):
    user = status.get("user", {})
    return (status.get("authenticated") is True and status.get("audiences") == [AUDIENCE]
            and user.get("username") == f"system:serviceaccount:{NAMESPACE}:{service_account}"
            and user.get("extra", {}).get("authentication.kubernetes.io/pod-uid") == [pod["metadata"]["uid"]])


def _probe_job(lab, name, *, cleanup, failure):
    _apply(lab, _job(name, name, ttl=12 if cleanup else None, failure=failure))
    pod = _wait_pod(lab, f"saf-k8s.example/job={name}")
    pod_name = pod["metadata"]["name"]
    token, expiry = _token(lab, name, pod)
    _, status = _review(lab, token)
    initial_match = _matches(status, name, pod)
    lab.check("positive", f"{name}: the original bound credential authenticates",
              initial_match, {"expected_identity_and_audience": initial_match})
    finished = _finish(lab, pod_name, failure=failure)
    terminal = "Failed" if failure else "Complete"
    if cleanup:
        if finished["spec"].get("ttlSecondsAfterFinished") != 12:
            lab.block("Finished Job did not have the reviewed TTL")
        _wait_gone(lab, name, pod_name)

    job_present = _exists(lab, "job", name)
    pod_present = _exists(lab, "pod", pod_name)
    authenticated, status = _review(lab, token)
    still_unexpired = expiry - int(time.time()) > 300
    if cleanup:
        matched = not job_present and not pod_present and not authenticated
        goal = "cascading Job and Pod removal invalidates the original credential"
    else:
        matched = job_present and pod_present and _matches(status, name, pod)
        goal = "terminal Job with retained Pod still authenticates"
    lab.check("green" if cleanup else "red", f"{name}: {goal}", matched and still_unexpired,
              {"terminal": terminal, "job_present": job_present, "pod_present": pod_present,
               "authenticated": authenticated, "credential_exp_still_in_future": still_unexpired})


def run(lab):
    version = _json(lab, "version", "-o", "json")
    server = version.get("serverVersion", {}).get("gitVersion")
    nodes = _json(lab, "get", "nodes", "-o", "json")
    kubelets = sorted({n.get("status", {}).get("nodeInfo", {}).get("kubeletVersion")
                       for n in nodes.get("items", [])})
    lab.check("positive", "Disposable server and kubelet are v1.36.1",
              server == "v1.36.1" and kubelets == ["v1.36.1"],
              {"server": server, "kubelets": kubelets})

    names = ("train-baseline-success", "train-baseline-failure", "train-success",
             "train-failure", "independent")
    for account in names:
        _apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                     "metadata": {"name": account, "namespace": NAMESPACE}})

    _apply(lab, _pod("independent-pod", "independent"))
    _run(lab, ["wait", "--for=condition=Ready", "pod/independent-pod", "--timeout=120s"], timeout=130)
    independent_pod = _json(lab, "get", "pod", "independent-pod", "-o", "json")
    token, _ = _token(lab, "independent", independent_pod)
    _, status = _review(lab, token)
    valid = _matches(status, "independent", independent_pod)
    lab.check("positive", "Unrelated Pod-bound identity is valid before cleanup", valid,
              {"expected_identity_and_audience": valid})

    _probe_job(lab, "train-baseline-success", cleanup=False, failure=False)
    _probe_job(lab, "train-baseline-failure", cleanup=False, failure=True)
    _probe_job(lab, "train-success", cleanup=True, failure=False)
    _probe_job(lab, "train-failure", cleanup=True, failure=True)

    _, status = _review(lab, token)
    valid = _matches(status, "independent", independent_pod)
    lab.check("positive", "Unrelated permitted identity remains valid after Job cleanup", valid,
              {"expected_identity_and_audience": valid})
