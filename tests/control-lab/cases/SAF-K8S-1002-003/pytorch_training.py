"""One pinned PyTorch CPU training run, observed through Prometheus."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import time
import urllib.parse

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
POD_NAME = "saf-pytorch-training"
MONITOR_NAME = "saf-pytorch-training"
PROMETHEUS = "http://saf-prometheus:9090"
VERSION = "2.15.0+cpu"
PORT = 8080
GLOO_COMPANIONS = {
    "gloo_runtime.py": "5217b3db2bbaa1637db010772d2d461f3a3446059fdf70b7b8708eec49a64ceb",
    "Dockerfile.gloo": "5ba6be415a184d107fe7f74aeb89a6d585eeaaa1232b591b387d5e0139378b82",
    "wheel-lock-amd64.json": "31192ece7525234993934f621d48a1aa81098842a0a7862f5abde2b81c78addd",
    "wheel-lock-arm64.json": "72857111feac7ef4ad7cef97a3ea955f98bcca4248d35d6e1cdb39a3fd37154a",
}


def _load_runtime(case_dir):
    cases_root = Path(case_dir).resolve().parent
    companion = cases_root / "SAF-K8S-0901-002"
    if not companion.is_dir():
        import os
        configured = os.environ.get("SAF_CONTROL_CASES_ROOT")
        companion = Path(configured).resolve() / "SAF-K8S-0901-002" if configured else companion
    if not companion.is_dir():
        raise RuntimeError("the published SAF-K8S-0901-002 pinned PyTorch builder companion is unavailable")
    for name, expected in GLOO_COMPANIONS.items():
        data = (companion / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"published PyTorch builder companion {name} hash differs")
    path = companion / "gloo_runtime.py"
    spec = importlib.util.spec_from_file_location("saf_1002_003_pytorch_build", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _query(lab, expression):
    url = PROMETHEUS + "/api/v1/query?" + urllib.parse.urlencode({"query": expression})
    script = "import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1],timeout=8).read().decode())"
    raw = lab.kubectl("exec", "pod/saf-query", "--", "python", "-c", script,
                      url, timeout=20).stdout
    payload = json.loads(raw)
    if payload.get("status") != "success":
        lab.block("Prometheus API returned an unsuccessful PyTorch training metric query")
    return payload["data"]["result"]


def _series_sample(lab, rows, metric_name):
    if not rows:
        return None
    if len(rows) != 1:
        lab.block(f"Expected one {metric_name} series for the exact training Pod")
    row = rows[0]
    labels = row.get("metric", {})
    expected = {"__name__": metric_name, "pod": POD_NAME, "namespace": NAMESPACE,
                "container": "trainer", "endpoint": "metrics",
                "framework": "pytorch", "device": "cpu", "workload": POD_NAME}
    if any(labels.get(key) != value for key, value in expected.items()):
        lab.block(f"{metric_name} series labels do not identify the reviewed training workload")
    values = row.get("values")
    if not isinstance(values, list) or not values:
        lab.block(f"{metric_name} query returned no actual scrape samples")
    timestamp, raw_value = values[-1]
    try:
        timestamp = float(timestamp)
        value = float(raw_value)
    except (TypeError, ValueError):
        lab.block(f"{metric_name} sample did not contain numeric scrape values")
    if not math.isfinite(timestamp) or not math.isfinite(value):
        lab.block(f"{metric_name} sample did not contain finite values")
    return timestamp, value, labels


def _same_target_identity(left, right):
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    return ({key: value for key, value in left.items() if key != "__name__"}
            == {key: value for key, value in right.items() if key != "__name__"})


def _pod_request(lab, pod_ip, path, method):
    url = f"http://{pod_ip}:{PORT}{path}"
    script = (
        "import sys,urllib.request; req=urllib.request.Request(sys.argv[1],data=b'',method=sys.argv[2]); "
        "print(urllib.request.urlopen(req,timeout=20).read().decode())")
    result = lab.kubectl("exec", "pod/saf-query", "--", "python", "-c", script,
                         url, method, timeout=30, allow_failure=True)
    if result.returncode:
        logs = lab.kubectl("logs", "pod/" + POD_NAME, "-c", "trainer",
                           "--tail=60", timeout=20, allow_failure=True)
        diagnostics = {"method": method, "path": path,
                       "request_exit_code": result.returncode,
                       "trainer_log_exit_code": logs.returncode,
                       "trainer_log_tail": (logs.stdout + logs.stderr)[-6000:]}
        (lab.evidence / "pytorch-training-request-failure.raw.json").write_text(
            json.dumps(diagnostics, indent=2, sort_keys=True) + "\n")
        lab.block(f"Fixed PyTorch workload request failed for {method} {path}")
    return json.loads(result.stdout)


def _pod_manifest(image):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": POD_NAME,
                     "labels": {"app": POD_NAME, "fixture": "1002-003",
                                "saf.synthetic": "true"}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Always",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "code", "configMap": {"name": POD_NAME + "-code"}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}],
            "containers": [{
                "name": "trainer", "image": image, "imagePullPolicy": "Never",
                "command": ["python3", "-B", "/case/training_metrics.py"],
                "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                        {"name": "HOME", "value": "/tmp"},
                        {"name": "TMPDIR", "value": "/tmp"},
                        {"name": "OMP_NUM_THREADS", "value": "1"},
                        {"name": "MKL_NUM_THREADS", "value": "1"},
                        {"name": "OPENBLAS_NUM_THREADS", "value": "1"}],
                "ports": [{"name": "metrics", "containerPort": PORT}],
                "readinessProbe": {"httpGet": {"path": "/metrics", "port": "metrics"},
                                   "periodSeconds": 2, "timeoutSeconds": 2},
                "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                              "limits": {"cpu": "1000m", "memory": "1536Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "code", "mountPath": "/case", "readOnly": True},
                                  {"name": "tmp", "mountPath": "/tmp"}],
            }],
        },
    }


def run(lab, case_dir):
    case_dir = Path(case_dir)
    try:
        runtime = _load_runtime(case_dir)
    except (OSError, RuntimeError) as error:
        lab.block(f"The pinned PyTorch builder companion could not be verified: {error}")
    image, provenance = runtime.build_and_import(lab)
    script_bytes = (case_dir / "training_metrics.py").read_bytes()
    provenance.update({"torch_expected_version": VERSION,
                       "training_source_sha256": hashlib.sha256(script_bytes).hexdigest(),
                       "gpu_used": False})

    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": POD_NAME + "-code"}, "immutable": True,
                "data": {"training_metrics.py": script_bytes.decode("utf-8")}})
    lab.create(_pod_manifest(image))
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + POD_NAME,
                "--timeout=180s", timeout=190)
    pod = json.loads(lab.kubectl("get", "pod", POD_NAME, "-o", "json", timeout=20).stdout)
    pod_uid = pod.get("metadata", {}).get("uid")
    pod_ip = pod.get("status", {}).get("podIP")
    statuses = pod.get("status", {}).get("containerStatuses", [])
    status = next((item for item in statuses if item.get("name") == "trainer"), {})
    image_id = status.get("imageID")
    if (not pod_uid or not pod_ip or not image_id or status.get("restartCount") != 0
            or pod.get("spec", {}).get("automountServiceAccountToken") is not False):
        lab.block("The native PyTorch training Pod lacks its reviewed identity or runtime state")
    provenance.update({"training_pod_uid": pod_uid, "training_pod_ip": pod_ip,
                       "training_image_id": image_id, "restart_count": status["restartCount"],
                       "service_account_token_mounted": False})

    lab.create({"apiVersion": "monitoring.coreos.com/v1", "kind": "PodMonitor",
                "metadata": {"name": MONITOR_NAME, "labels": {"saf.synthetic": "true"}},
                "spec": {"selector": {"matchLabels": {"app": POD_NAME,
                                                           "saf.synthetic": "true"}},
                         "namespaceSelector": {"matchNames": [NAMESPACE]},
                         "podMetricsEndpoints": [{"port": "metrics", "path": "/metrics",
                                                  "interval": "4s"}]}})

    target_expression = f'up{{pod="{POD_NAME}",namespace="{NAMESPACE}"}}'
    target = []
    # The pinned config reloader checks its input on a three-minute interval.
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        target = _query(lab, target_expression)
        if (len(target) == 1 and target[0].get("value", [None, None])[1] == "1"
                and target[0].get("metric", {}).get("pod") == POD_NAME):
            break
        time.sleep(2)
    if len(target) != 1 or target[0].get("value", [None, None])[1] != "1":
        lab.block("Prometheus did not discover the exact ready CPU PyTorch training Pod")

    steps_metric = f'saf_torch_optimizer_steps_total{{pod="{POD_NAME}",namespace="{NAMESPACE}"}}[30s]'
    initial_rows = _query(lab, steps_metric)
    initial = _series_sample(lab, initial_rows, "saf_torch_optimizer_steps_total")
    initial_zero = initial is not None and initial[1] == 0
    (lab.evidence / "pytorch-training-baseline.raw.json").write_text(
        json.dumps({"provenance": provenance, "target_up": target,
                    "steps_metric_before_training": initial_rows,
                    "observed_zero_baseline": initial}, indent=2, sort_keys=True) + "\n")
    lab.check("red", "The real PyTorch workload exposes a zero optimizer-step baseline before training",
              initial_zero,
              {"target_up": True, "metric": "saf_torch_optimizer_steps_total",
               "exact_zero_baseline": initial_zero, "framework": "pytorch",
               "device": "cpu", "pod_uid_bound": bool(pod_uid)})

    receipt = _pod_request(lab, pod_ip, "/train", "POST")
    independent_receipt = _pod_request(lab, pod_ip, "/receipt", "GET")
    if receipt != independent_receipt:
        lab.block("Independent training receipt readback differs from the completed training request")
    if (receipt.get("framework") != "pytorch" or receipt.get("torch_version") != VERSION
            or receipt.get("device") != "cpu" or receipt.get("optimizer_steps") != 3
            or not isinstance(receipt.get("initial_loss"), (int, float))
            or not isinstance(receipt.get("epoch_losses"), list)
            or len(receipt["epoch_losses"]) != 3
            or any(not isinstance(value, (int, float)) or not math.isfinite(value)
                   for value in receipt["epoch_losses"])
            or receipt["final_loss"] != receipt["epoch_losses"][-1]
            or not receipt["final_loss"] < receipt["initial_loss"]):
        lab.block("The CPU framework receipt does not show the exact bounded measured training run")

    deadline = time.monotonic() + 90
    steps_rows = []
    steps_sample = None
    while time.monotonic() < deadline:
        steps_rows = _query(lab, steps_metric)
        steps_sample = _series_sample(lab, steps_rows, "saf_torch_optimizer_steps_total")
        if (steps_sample is not None and initial is not None
                and steps_sample[0] > initial[0] and steps_sample[1] == 3):
            break
        time.sleep(2)

    loss_metric = f'saf_torch_training_loss{{pod="{POD_NAME}",namespace="{NAMESPACE}"}}[30s]'
    loss_rows = _query(lab, loss_metric)
    loss_sample = _series_sample(lab, loss_rows, "saf_torch_training_loss")
    same_series = (steps_sample is not None and initial is not None
                   and steps_sample[2] == initial[2])
    measured_loss_matches = (loss_sample is not None
                             and math.isclose(loss_sample[1], receipt["final_loss"],
                                              rel_tol=1e-6, abs_tol=1e-8))
    complete = (steps_sample is not None and steps_sample[1] == receipt["optimizer_steps"]
                and initial is not None and steps_sample[0] > initial[0] and same_series
                and measured_loss_matches
                and _same_target_identity(steps_sample[2], loss_sample[2]))
    evidence = {"provenance": provenance, "target_up": target,
                "training_request_receipt": receipt,
                "independent_receipt_readback": independent_receipt,
                "steps_baseline": initial_rows, "steps_after": steps_rows,
                "loss_after": loss_rows,
                "steps_baseline_sample": initial, "steps_observed_sample": steps_sample,
                "loss_observed_sample": loss_sample,
                "measured_loss_matches_framework_receipt": measured_loss_matches,
                "same_steps_series": same_series, "generated_or_training_data_retained": False}
    (lab.evidence / "pytorch-training-prometheus.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Prometheus scrapes step count and measured loss from a real pinned PyTorch CPU training run",
              complete,
              {"target_up": True, "torch_version": receipt.get("torch_version"),
               "device": receipt.get("device"), "optimizer_steps": steps_sample[1]
               if steps_sample else None,
               "steps_scraped_after_training": steps_sample is not None and initial is not None
               and steps_sample[0] > initial[0],
               "same_series": same_series, "loss_matches_framework_measurement": measured_loss_matches,
               "loss_decreased": receipt["final_loss"] < receipt["initial_loss"],
               "pod_uid_bound": bool(pod_uid), "gpu_used": False})
