"""Verify startup digest gating and read-only access with harmless synthetic bytes."""
import hashlib
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURE = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
CONTROL_ID = "SAF-K8S-0902-002"
NAMESPACE = "saf-0902-002"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
ARTIFACT_CONFIG = "synthetic-model-bytes"
WORKLOAD_CONFIG = "synthetic-mock-workload"
FAIL_POD = "digest-mismatch"
SERVE_POD = "verified-mock-serving"
OBSERVER_POD = "independent-readback"
WRONG_DIGEST = "f" * 64
SCOPE = (
    "One disposable Kind Kubernetes v1.36.1 cluster. A ConfigMap contains one public, inert "
    "synthetic marker, not a model. A digest-pinned BusyBox init container checks those exact "
    "bytes before a digest-pinned Python mock serving container may start. The failed case "
    "uses a fixed nonmatching digest and restartPolicy Never; the authorized case uses the "
    "fixture's fixed matching digest, reads and serves the marker, observes a read-only mount, "
    "and records a denied write. A separate Pod reads and hashes the mounted bytes afterward. "
    "No real artifacts, endpoints, registries, feeds, credentials, or secrets are used. This "
    "does not verify signatures, registry acquisition, model cache behavior, runtime replacement "
    "under concurrency, production inference behavior, or file integrity monitoring/alerting."
)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _labels():
    return {"saf-k8s.example/control": CONTROL_ID, "saf-k8s.example/fixture": "synthetic"}


def _configmaps():
    marker = FIXTURE["marker"].encode("utf-8")
    return [
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": ARTIFACT_CONFIG, "namespace": NAMESPACE, "labels": _labels()},
         "immutable": True, "data": {"marker.txt": FIXTURE["marker"]}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": WORKLOAD_CONFIG, "namespace": NAMESPACE, "labels": _labels()},
         "immutable": True, "data": {"workload.py": (HERE / "fixtures" / "workload.py").read_text(encoding="utf-8")}},
    ], _digest(marker)


def _pod(name, expected_digest, *, run_mock):
    containers = []
    if run_mock:
        containers = [{
            "name": "mock-serving", "image": PYTHON_IMAGE,
            "imagePullPolicy": "IfNotPresent",
            "command": ["python", "-B", "/case/workload.py", "serve"],
            "ports": [{"name": "http", "containerPort": 8080}],
            "readinessProbe": {"httpGet": {"path": "/ready", "port": "http"},
                               "periodSeconds": 2, "timeoutSeconds": 1},
            "securityContext": {"allowPrivilegeEscalation": False,
                                 "readOnlyRootFilesystem": True,
                                 "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                          "limits": {"cpu": "100m", "memory": "64Mi"}},
            "volumeMounts": [
                {"name": "artifact", "mountPath": "/model", "readOnly": True},
                {"name": "workload", "mountPath": "/case", "readOnly": True},
            ],
        }]
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "initContainers": [{
                "name": "verify-synthetic-digest", "image": BUSYBOX_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["sh", "-c", (
                    'actual="$(sha256sum /model/marker.txt | cut -d " " -f 1)"; '
                    'if [ "$actual" != "$EXPECTED_DIGEST" ]; then '
                    'echo "DIGEST_MISMATCH expected=sha256:$EXPECTED_DIGEST actual=sha256:$actual"; '
                    'exit 42; fi; '
                    'echo "DIGEST_VERIFIED digest=sha256:$actual"'
                )],
                "env": [{"name": "EXPECTED_DIGEST", "value": expected_digest}],
                "securityContext": {"allowPrivilegeEscalation": False,
                                     "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                              "limits": {"cpu": "50m", "memory": "32Mi"}},
                "volumeMounts": [{"name": "artifact", "mountPath": "/model", "readOnly": True}],
            }],
            "containers": containers,
            "volumes": [
                {"name": "artifact", "configMap": {"name": ARTIFACT_CONFIG}},
                {"name": "workload", "configMap": {"name": WORKLOAD_CONFIG}},
            ],
        },
    }


def _json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def _wait_terminal(lab, pod_name, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pod = _json(lab, "-n", NAMESPACE, "get", "pod", pod_name)
        statuses = pod.get("status", {}).get("initContainerStatuses", [])
        if (pod["status"].get("phase") == "Failed" and statuses
                and statuses[0].get("state", {}).get("terminated")):
            return pod
        time.sleep(1)
    lab.block(f"Init container for {pod_name} did not terminate within {timeout}s")


def _save(lab, filename, record):
    (lab.evidence / filename).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8")


def run(lab):
    if FIXTURE.get("control_id") != CONTROL_ID or FIXTURE.get("marker") != "SAF-SYNTHETIC-MODEL-MARKER-0902-002\n":
        lab.block("Unexpected synthetic marker fixture")
    resources, approved_digest = _configmaps()
    if approved_digest != FIXTURE.get("approved_sha256"):
        lab.block("Fixture marker and fixed approved digest do not match")
    lab.kubectl("create", "namespace", NAMESPACE)
    for resource in resources:
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(resource))
    config_readback = _json(lab, "-n", NAMESPACE, "get", "configmap", ARTIFACT_CONFIG)
    if (config_readback.get("immutable") is not True
            or config_readback.get("data", {}).get("marker.txt") != FIXTURE["marker"]):
        lab.block("Synthetic marker ConfigMap failed API readback")

    # Red: precise digest mismatch and init-gated absence of any serving-container start.
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                payload=json.dumps(_pod(FAIL_POD, WRONG_DIGEST, run_mock=True)))
    failed_pod = _wait_terminal(lab, FAIL_POD)
    failure_log = lab.kubectl("-n", NAMESPACE, "logs", FAIL_POD,
                              "-c", "verify-synthetic-digest").stdout.strip()
    init_status = failed_pod["status"]["initContainerStatuses"][0]
    init_term = init_status.get("state", {}).get("terminated", {})
    app_statuses = failed_pod.get("status", {}).get("containerStatuses", [])
    actual_digest = _digest(FIXTURE["marker"].encode("utf-8"))
    exact_failure = (
        failure_log == f"DIGEST_MISMATCH expected=sha256:{WRONG_DIGEST} actual=sha256:{actual_digest}"
        and init_term.get("exitCode") == 42
        and init_term.get("reason") == "Error"
        and failed_pod.get("status", {}).get("phase") == "Failed"
        and len(app_statuses) <= 1
        and all(app.get("state", {}).get("running") is None
                and app.get("state", {}).get("terminated") is None
                and app.get("restartCount") == 0
                and app.get("lastState", {}).get("terminated") is None
                and app.get("startedAt") is None
                for app in app_statuses)
    )
    lab.check("red", "A fixed nonmatching digest fails exactly before any mock serving container starts",
              exact_failure, {"init_exit_code": init_term.get("exitCode"), "init_reason": init_term.get("reason"),
                              "init_log": failure_log, "pod_phase": failed_pod.get("status", {}).get("phase"),
                              "serving_state": app_statuses[0].get("state") if app_statuses else None,
                              "serving_restart_count": app_statuses[0].get("restartCount") if app_statuses else None})

    # Green and positive: same bytes pass the fixed digest check and the mock starts.
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                payload=json.dumps(_pod(SERVE_POD, approved_digest, run_mock=True)))
    lab.kubectl("-n", NAMESPACE, "wait", f"pod/{SERVE_POD}", "--for=condition=Ready",
                "--timeout=90s", timeout=100)
    serving_pod = _json(lab, "-n", NAMESPACE, "get", "pod", SERVE_POD)
    init_log = lab.kubectl("-n", NAMESPACE, "logs", SERVE_POD,
                           "-c", "verify-synthetic-digest").stdout.strip()
    serving_log = lab.kubectl("-n", NAMESPACE, "logs", SERVE_POD,
                              "-c", "mock-serving").stdout.splitlines()
    try:
        startup = json.loads(serving_log[0])
    except (IndexError, json.JSONDecodeError):
        lab.block("Mock serving startup did not emit its structured synthetic marker receipt")
    serving_statuses = serving_pod.get("status", {}).get("containerStatuses", [])
    serving_running = (len(serving_statuses) == 1
                       and serving_statuses[0].get("state", {}).get("running") is not None)
    pod_ready = any(condition.get("type") == "Ready" and condition.get("status") == "True"
                    for condition in serving_pod.get("status", {}).get("conditions", []))
    app_status, = serving_pod["status"]["containerStatuses"]
    served = lab.kubectl(
        "-n", NAMESPACE, "exec", SERVE_POD, "-c", "mock-serving", "--", "python", "-c",
        "import urllib.request; receipt = urllib.request.urlopen('http://127.0.0.1:8080/marker', timeout=3); "
        "print(receipt.status); print(receipt.read().hex())",
    ).stdout.splitlines()
    served_expected_bytes = served == ["200", FIXTURE["marker"].encode().hex()]
    authorized = (served_expected_bytes and app_status["state"].get("running") is not None
                  and init_log == f"DIGEST_VERIFIED digest=sha256:{approved_digest}"
                  and startup.get("event") == "mock_startup"
                  and startup.get("marker") == FIXTURE["marker"].rstrip("\n")
                  and startup.get("digest") == f"sha256:{approved_digest}"
                  and serving_running and pod_ready)
    lab.check("green", "The authorized fixed digest starts the mock serving container, which reads the expected marker",
              authorized, {"init_log": init_log, "startup": startup,
                           "serving_started": serving_running, "pod_ready": pod_ready})

    mounts = {item["name"]: item for item in serving_pod["spec"]["containers"][0].get("volumeMounts", [])}
    readonly_spec = mounts.get("artifact", {}).get("readOnly") is True
    readonly_evidence = startup.get("mount_readonly") is True
    write_denied = startup.get("write_errno") == 30 and startup.get("write_denied") is True
    lab.check("positive", "The serving mount is read-only and the mock write fails with EROFS",
              readonly_spec and readonly_evidence and write_denied,
              {"api_mount_readOnly": readonly_spec, "runtime_mount_readonly": readonly_evidence,
               "write_denied": startup.get("write_denied"), "write_errno": startup.get("write_errno")})

    # Independent Pod with a separate container reads the same ConfigMap after the denied write.
    observer = _pod(OBSERVER_POD, approved_digest, run_mock=False)
    observer["spec"]["initContainers"][0]["command"] = ["sh", "-c", (
        'actual="$(sha256sum /model/marker.txt | cut -d " " -f 1)"; '
        'test "$actual" = "$EXPECTED_DIGEST"'
    )]
    observer["spec"]["initContainers"][0]["name"] = "verify-observer-bytes"
    observer["spec"]["containers"] = [{
        "name": "independent-reader", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-B", "/case/workload.py", "readback"],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                      "limits": {"cpu": "50m", "memory": "32Mi"}},
        "volumeMounts": [{"name": "artifact", "mountPath": "/model", "readOnly": True},
                         {"name": "workload", "mountPath": "/case", "readOnly": True}],
    }]
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(observer))
    lab.kubectl("-n", NAMESPACE, "wait", f"pod/{OBSERVER_POD}", "--for=jsonpath={.status.phase}=Succeeded",
                "--timeout=90s", timeout=100)
    observer_log = lab.kubectl("-n", NAMESPACE, "logs", OBSERVER_POD,
                               "-c", "independent-reader").stdout.splitlines()
    try:
        readback = json.loads(observer_log[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block("Independent reader did not emit a structured byte readback")
    readback_ok = (readback.get("event") == "independent_readback"
                   and readback.get("marker") == FIXTURE["marker"]
                   and readback.get("sha256") == approved_digest)
    lab.check("positive", "A separate Pod reads back unchanged marker bytes and the expected SHA-256",
              readback_ok, readback)

    _save(lab, "model-integrity.raw.json", {
        "control_id": CONTROL_ID, "scope": SCOPE, "secrets_included": False,
        "external_targets_contacted": False,
        "fixture": {"marker": FIXTURE["marker"], "sha256": approved_digest},
        "digest_mismatch": {"pod": FAIL_POD, "init_log": failure_log,
                             "init_termination": {"exit_code": init_term.get("exitCode"),
                                                  "reason": init_term.get("reason")},
                             "serving_container_started": False},
        "authorized_startup": {"pod": SERVE_POD, "init_log": init_log,
                                "startup": startup, "readiness": serving_pod.get("status", {}).get("conditions", [])},
        "independent_readback": {"pod": OBSERVER_POD, "record": readback},
        "checks": lab.checks,
        "monitoring_tested": False,
    })
