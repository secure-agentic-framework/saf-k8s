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
    "One disposable Kind v1.36.1 cluster. Startup compares a fixed inert marker with approved "
    "and incorrect digests. An independent Pod verifies the read-only consumer's mounted bytes. "
    "A separate case-owned PVC comparison observes an already-running read-only monitor detect "
    "the exact fixture marker change made by a scoped writer. Deployed signer, cache, storage "
    "and response guarantees have separate verification."
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
    _run_fim_monitor(lab)


# Additive scratch file-integrity monitoring exercise, separate from original ConfigMap tests.
FIM_PVC = "fim-synthetic-model"
FIM_WRITER_SA = "fim-fixture-writer"
FIM_SEED_POD = "fim-seed-writer"
FIM_CHANGE_POD = "fim-change-writer"
FIM_MONITOR_POD = "fim-readonly-consumer"
FIM_CONFIG = "fim-integrity-monitor"
FIM_BASELINE = b"SAF-0902-002-FIM-BASELINE\n"
FIM_CHANGED = b"SAF-0902-002-FIM-UPDATED\n"
FIM_MONITOR = 'import errno, hashlib, json, pathlib, time, os\npath = pathlib.Path("/model/marker.txt")\nexpected = os.environ["EXPECTED_SHA256"]\nactual = hashlib.sha256(path.read_bytes()).hexdigest()\ntry:\n    with path.open("ab"):\n        pass\n    write_errno = None\nexcept OSError as err:\n    write_errno = err.errno\nprint(json.dumps({"event": "monitor_baseline", "expected_sha256": expected, "observed_sha256": actual,\n                  "write_denied": write_errno == errno.EROFS, "write_errno": write_errno}), flush=True)\nif actual != expected:\n    raise SystemExit(2)\ndeadline = time.monotonic() + 90\nwhile time.monotonic() < deadline:\n    observed = hashlib.sha256(path.read_bytes()).hexdigest()\n    if observed != expected:\n        print(json.dumps({"event": "integrity_discrepancy", "expected_sha256": expected,\n                          "observed_sha256": observed}), flush=True)\n        break\n    time.sleep(0.2)\nelse:\n    raise SystemExit(3)\n'
FIM_WRITE = 'import hashlib, json, os, pathlib\npayload = os.environ["FIXTURE_MARKER"].encode("ascii")\npath = pathlib.Path("/model/marker.txt")\npending = path.with_name(".marker-next")\npending.write_bytes(payload)\npending.replace(path)\nprint(json.dumps({"event": "fixture_write", "sha256": hashlib.sha256(payload).hexdigest()}))\n'


def _fim_pod(name, *, writer=False, marker=None):
    if writer:
        container = {"name": "fixture-writer", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                     "command": ["python", "-c", FIM_WRITE],
                     "env": [{"name": "FIXTURE_MARKER", "value": marker.decode("ascii")}],
                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                         "capabilities": {"drop": ["ALL"]}},
                     "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                                   "limits": {"cpu": "50m", "memory": "32Mi"}},
                     "volumeMounts": [{"name": "model", "mountPath": "/model", "readOnly": False}]}
    else:
        container = {"name": "integrity-monitor", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                     "command": ["python", "-B", "/monitor/monitor.py"],
                     "env": [{"name": "EXPECTED_SHA256", "value": _digest(FIM_BASELINE)}],
                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                         "capabilities": {"drop": ["ALL"]}},
                     "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                                   "limits": {"cpu": "50m", "memory": "32Mi"}},
                     "volumeMounts": [{"name": "model", "mountPath": "/model", "readOnly": True},
                                      {"name": "monitor", "mountPath": "/monitor", "readOnly": True}]}
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
            "spec": {"restartPolicy": "Never", "serviceAccountName": FIM_WRITER_SA if writer else "default",
                     "automountServiceAccountToken": False, "terminationGracePeriodSeconds": 1,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [container],
                     "volumes": [{"name": "model", "persistentVolumeClaim": {"claimName": FIM_PVC}}] +
                                ([] if writer else [{"name": "monitor", "configMap": {"name": FIM_CONFIG, "defaultMode": 292}}])}}


def _fim_wait_logs(lab, pod_name, match, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = lab.kubectl("-n", NAMESPACE, "logs", pod_name, allow_failure=True)
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event") == match:
                return result.stdout, record
        time.sleep(1)
    lab.block(f"The owned fixture did not emit {match}")


def _fim_wait_succeeded(lab, name, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = lab.kubectl("-n", NAMESPACE, "get", "pod", name,
                             "-o", "jsonpath={.status.phase}", allow_failure=True)
        if result.stdout.strip() == "Succeeded":
            return
        time.sleep(1)
    lab.block(f"Fixture writer Pod {name} did not complete")


def _fim_write_pod(lab, name, marker):
    pod = _fim_pod(name, writer=True, marker=marker)
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(pod))
    _fim_wait_succeeded(lab, name)
    record = json.loads(lab.kubectl("-n", NAMESPACE, "logs", name).stdout.strip())
    actual = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", name, "-o", "json").stdout)
    return actual, record


def _run_fim_monitor(lab):
    def create(resource):
        return lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(resource))

    provisioner = lab.kubectl("get", "storageclass", "standard", "-o", "jsonpath={.provisioner}").stdout.strip()
    if provisioner != "rancher.io/local-path":
        lab.block("The integrity monitor supplement requires the owned Kind local-path provisioner")
    create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": FIM_WRITER_SA, "namespace": NAMESPACE},
                "automountServiceAccountToken": False})
    create({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": FIM_PVC, "namespace": NAMESPACE,
                "labels": _labels()}, "spec": {"storageClassName": "standard", "accessModes": ["ReadWriteOnce"],
                "resources": {"requests": {"storage": "16Mi"}}}})
    seed = _fim_pod(FIM_SEED_POD, writer=True, marker=FIM_BASELINE)
    seed["spec"]["containers"][0]["command"] = ["python", "-c", "import time; time.sleep(90)"]
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(seed))
    deadline = time.monotonic() + 80
    claim = None
    while time.monotonic() < deadline:
        result = lab.kubectl("-n", NAMESPACE, "get", "pvc", FIM_PVC, "-o", "json", allow_failure=True)
        if result.returncode == 0:
            claim = json.loads(result.stdout)
            if claim.get("status", {}).get("phase") == "Bound":
                break
        time.sleep(1)
    if not claim or claim.get("status", {}).get("phase") != "Bound":
        lab.block("The owned local-path PVC did not bind")
    pv_name = claim["spec"]["volumeName"]
    pv = json.loads(lab.kubectl("get", "pv", pv_name, "-o", "json").stdout)
    claim_ref = pv["spec"].get("claimRef", {})
    expected_path = f"/var/local-path-provisioner/{pv_name}_{NAMESPACE}_{FIM_PVC}"
    if (claim_ref.get("uid") != claim["metadata"]["uid"]
            or claim_ref.get("namespace") != NAMESPACE or claim_ref.get("name") != FIM_PVC
            or pv["spec"].get("hostPath", {}).get("path") != expected_path):
        lab.block("The bound local volume does not identify the exact owned fixture claim and path")
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{FIM_SEED_POD}",
                "--timeout=40s", timeout=50)
    seed_actual = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", FIM_SEED_POD, "-o", "json").stdout)
    if seed_actual["spec"]["nodeName"] != f"{lab.cluster}-control-plane":
        lab.block("The seed fixture was not placed on the exact owned Kind node")
    seed_receipt = json.loads(lab.kubectl("-n", NAMESPACE, "exec", FIM_SEED_POD, "-c",
                                         "fixture-writer", "--", "python", "-c", FIM_WRITE).stdout)
    lab.kubectl("-n", NAMESPACE, "delete", "pod", FIM_SEED_POD, "--wait=true",
                "--timeout=20s", timeout=25)
    baseline_digest = _digest(FIM_BASELINE)
    if seed_receipt.get("sha256") != baseline_digest:
        lab.block("Seed writer did not record the fixed baseline digest")
    create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": FIM_CONFIG, "namespace": NAMESPACE,
                "labels": _labels()}, "immutable": True, "data": {"monitor.py": FIM_MONITOR}})
    monitor_pod = _fim_pod(FIM_MONITOR_POD)
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(monitor_pod))
    _, baseline_record = _fim_wait_logs(lab, FIM_MONITOR_POD, "monitor_baseline")
    monitor_pod = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", FIM_MONITOR_POD, "-o", "json").stdout)
    baseline_match = (baseline_record.get("expected_sha256") == baseline_digest
                      and baseline_record.get("observed_sha256") == baseline_digest
                      and baseline_record.get("write_denied") is True
                      and baseline_record.get("write_errno") == 30
                      and monitor_pod["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] is True
                      and monitor_pod["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] is True)
    lab.check("positive", "The hardened read-only consumer records the fixed PVC baseline digest",
              baseline_match, {"pvc_bound": True, "provisioner": provisioner, "read_only_mount": True,
                               "read_only_rootfs": True, "baseline_digest_match": baseline_match})
    changed_digest = _digest(FIM_CHANGED)
    change_pod, change_receipt = _fim_write_pod(lab, FIM_CHANGE_POD, FIM_CHANGED)
    monitor_logs, discrepancy = _fim_wait_logs(lab, FIM_MONITOR_POD, "integrity_discrepancy")
    actual_change = (change_receipt.get("sha256") == changed_digest
                     and discrepancy.get("expected_sha256") == baseline_digest
                     and discrepancy.get("observed_sha256") == changed_digest
                     and change_pod["spec"]["serviceAccountName"] == FIM_WRITER_SA
                     and change_pod["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] == FIM_PVC
                     and change_pod["spec"]["containers"][0]["volumeMounts"][0]["mountPath"] == "/model"
                     and change_pod["spec"]["containers"][0]["volumeMounts"][0].get("readOnly", False) is False
                     and FIM_BASELINE.decode("ascii") not in monitor_logs
                     and FIM_CHANGED.decode("ascii") not in monitor_logs)
    lab.check("green", "An approved fixture writer changes only its owned marker and the monitor emits a digest-only discrepancy",
              actual_change, {"writer_service_account": FIM_WRITER_SA, "pvc": FIM_PVC,
                             "baseline_sha256": baseline_digest, "observed_sha256": changed_digest,
                             "discrepancy_detected": actual_change, "record_contains_marker_bytes": False})
    state = {"scope": "synthetic local-path PVC and two fixed inert marker values only",
             "provisioner": provisioner, "pvc_bound": True, "writer_service_account": FIM_WRITER_SA,
             "pvc": FIM_PVC, "baseline_sha256": baseline_digest, "changed_sha256": changed_digest,
             "read_only_consumer_mount": True, "read_only_consumer_rootfs": True,
             "monitor_records_only_hashes": True, "discrepancy": discrepancy}
    _save(lab, "model-integrity-monitor.raw.json", state)
