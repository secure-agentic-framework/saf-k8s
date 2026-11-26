"""Supplement 1002-003 with a SHA-bound native CPU serving metrics witness."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import tempfile
import time
import urllib.parse

HERE = Path(__file__).resolve().parent
SIBLING = "SAF-K8S-0903-004"
COMPANIONS = {
    "llama_runtime.py": "eb5431938939d15363a21f7c6dbb8126def4b99ec790e92a2be2e0bd40b513d8",
    "Dockerfile.llama": "9e9d4d3a6db46fac9fafca6fdc2b3ed2b703c24c5c49c87f7556aecd71057650",
    "llama_client.py": "1a5da8194ad25415aaa7e3b8cc50ecc5d86257dedd7e115ad76db5f1f8d5986d",
}
NAMESPACE = "saf-test"
PROMETHEUS = "http://saf-prometheus:9090"
METRIC = 'llamacpp:tokens_predicted_total{pod="saf-llama-real",namespace="saf-test"}'


def _companion_bytes(lab):
    cases_root = HERE.parent
    sibling = cases_root / SIBLING
    # Approval-run scratch copies contain only their own case directory. The explicit
    # override lets the runner provide the same published sibling without copying it.
    if not sibling.is_dir():
        configured = os.environ.get("SAF_CONTROL_CASES_ROOT")
        sibling = Path(configured).resolve() / SIBLING if configured else sibling
    if not sibling.is_dir():
        lab.block("The published SAF-K8S-0903-004 companion directory is unavailable; set SAF_CONTROL_CASES_ROOT for a scratch-loaded case")
    contents = {}
    for name, expected in COMPANIONS.items():
        path = sibling / name
        try:
            data = path.read_bytes()
        except OSError as error:
            lab.block(f"Pinned llama companion {name} is unavailable: {error}")
        observed = hashlib.sha256(data).hexdigest()
        if observed != expected:
            lab.block(f"Pinned llama companion {name} SHA-256 differs from the reviewed source")
        contents[name] = data
    return sibling, contents


def _query(lab, expression):
    url = PROMETHEUS + "/api/v1/query?" + urllib.parse.urlencode({"query": expression})
    script = "import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1],timeout=8).read().decode())"
    raw = lab.kubectl("exec", "pod/saf-query", "--", "python", "-c", script, url,
                      timeout=20).stdout
    payload = json.loads(raw)
    if payload.get("status") != "success":
        lab.block("Prometheus API returned an unsuccessful native serving metric query")
    return payload["data"]["result"]


def _wait_for_target(lab):
    expression = 'up{pod="saf-llama-real",namespace="saf-test"}'
    deadline = time.monotonic() + 200
    last_rows = []
    while time.monotonic() < deadline:
        last_rows = _query(lab, expression)
        if (len(last_rows) == 1 and last_rows[0]["value"][1] == "1"
                and last_rows[0]["metric"].get("pod") == "saf-llama-real"
                and last_rows[0]["metric"].get("namespace") == NAMESPACE):
            return last_rows[0]
        time.sleep(2)
    lab.block(f"The pinned Prometheus operator did not expose one up llama target: {last_rows}")


def _latest_counter_sample(rows):
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError("expected one native llama metric series for the case-owned Pod")
    series = rows[0]
    labels = series["metric"]
    if (labels.get("__name__") != "llamacpp:tokens_predicted_total"
            or labels.get("pod") != "saf-llama-real"
            or labels.get("namespace") != NAMESPACE
            or labels.get("service") != "saf-llama-real"
            or labels.get("endpoint") != "metrics"):
        raise ValueError("native llama metric series does not identify the dedicated target")
    timestamp, raw_value = series["values"][-1]
    value = float(raw_value)
    if not math.isfinite(timestamp) or not math.isfinite(value) or value < 0:
        raise ValueError("expected a finite timestamp and nonnegative native counter")
    return timestamp, value, labels


def run(lab):
    sibling, contents = _companion_bytes(lab)
    runtime_spec = importlib.util.spec_from_file_location(
        "saf_1002_003_pinned_llama_runtime", sibling / "llama_runtime.py")
    runtime = importlib.util.module_from_spec(runtime_spec)
    exec(compile(contents["llama_runtime.py"], str(sibling / "llama_runtime.py"), "exec"),
         runtime.__dict__)

    # The existing builder reads Dockerfile.llama from runtime.HERE. Point it to an
    # ephemeral context containing exactly the already-hash-checked companion bytes.
    with tempfile.TemporaryDirectory(prefix="saf-1002-003-pinned-companion-") as dependency:
        dependency = Path(dependency)
        (dependency / "Dockerfile.llama").write_bytes(contents["Dockerfile.llama"])
        runtime.HERE = dependency
        image, provenance = runtime._build_and_load(lab)

    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": runtime.CLIENT_CONFIG}, "immutable": True,
                "data": {"llama_client.py": contents["llama_client.py"].decode("utf-8")}})
    pod = runtime._server_pod(image)
    pod["metadata"]["labels"].update({"app": runtime.SERVER, "saf.synthetic": "true"})
    pod["spec"]["containers"][0]["args"].append("--metrics")
    lab.create(pod)
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + runtime.SERVER,
                "--timeout=190s", timeout=200)
    server = json.loads(lab.kubectl("get", "pod", runtime.SERVER, "-o", "json").stdout)
    pod_ip = server["status"].get("podIP")
    if not pod_ip:
        lab.block("The llama server has no observed Pod IP")

    labels = {"app": runtime.SERVER, "saf.synthetic": "true"}
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": runtime.SERVER, "labels": labels},
                "spec": {"selector": labels,
                         "ports": [{"name": "metrics", "port": 8080, "targetPort": "http"}]}})
    lab.create({"apiVersion": "monitoring.coreos.com/v1", "kind": "ServiceMonitor",
                "metadata": {"name": runtime.SERVER, "labels": {"saf.synthetic": "true"}},
                "spec": {"selector": {"matchLabels": {"app": runtime.SERVER,
                                                          "saf.synthetic": "true"}},
                         "namespaceSelector": {"matchNames": [NAMESPACE]},
                         "endpoints": [{"port": "metrics", "path": "/metrics",
                                        "interval": "4s"}]}})

    target = _wait_for_target(lab)
    lab.create(runtime._client_pod())
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + runtime.CLIENT,
                "--timeout=60s", timeout=70)
    # A range selector supplies actual scrape timestamps rather than query timestamps.
    metric_expression = METRIC + "[30s]"
    baseline_rows = []
    baseline_sample = None
    baseline_deadline = time.monotonic() + 30
    while time.monotonic() < baseline_deadline and baseline_sample is None:
        baseline_rows = _query(lab, metric_expression)
        baseline_sample = _latest_counter_sample(baseline_rows)
        if baseline_sample is None:
            time.sleep(2)
    (lab.evidence / "llama-metrics-baseline.raw.json").write_text(
        json.dumps(baseline_rows, indent=2, sort_keys=True) + "\n")
    if baseline_sample is None:
        lab.block("The dedicated target never exposed a finite native baseline sample")
    baseline_timestamp, baseline, baseline_labels = baseline_sample
    if baseline != 0:
        lab.block(f"The fresh serving process reported an unexpected initial counter: {baseline}")
    result = lab.kubectl("exec", "pod/" + runtime.CLIENT, "--", "python", "-B",
                         "/fixture/llama_client.py", pod_ip, timeout=75,
                         allow_failure=True)
    (lab.evidence / "llama-metrics-client.raw.log").write_text(result.stdout + result.stderr)
    try:
        request = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"Native llama client response was not valid JSON: {error}")

    deadline = time.monotonic() + 90
    observed_rows = []
    observed_timestamp = observed_value = None
    observed_labels = None
    while time.monotonic() < deadline:
        observed_rows = _query(lab, metric_expression)
        sample = _latest_counter_sample(observed_rows)
        if sample is not None:
            observed_timestamp, observed_value, observed_labels = sample
            if observed_timestamp > baseline_timestamp and observed_value > baseline:
                break
        time.sleep(2)
    delta = None if observed_value is None else observed_value - baseline
    same_series = observed_labels == baseline_labels
    later_scrape = observed_timestamp is not None and observed_timestamp > baseline_timestamp
    valid = (result.returncode == 0 and target["metric"].get("pod") == runtime.SERVER
             and target["metric"].get("namespace") == NAMESPACE
             and request.get("completion_tokens") == 4 and same_series and later_scrape
             and delta == request.get("completion_tokens"))
    provenance.update({"model_sha256": runtime.MODEL_SHA256, "llama_release": "b9519",
                       "metrics_enabled": True, "prometheus_target_pod":
                       target["metric"].get("pod"), "service_monitor": runtime.SERVER,
                       "native_metric": "llamacpp:tokens_predicted_total",
                       "companion_sha256": COMPANIONS})
    evidence = {"provenance": provenance, "baseline": baseline_rows,
                "target_up": target, "client": request, "after": observed_rows,
                "baseline_value": baseline, "observed_value": observed_value,
                "baseline_sample_timestamp": baseline_timestamp,
                "observed_sample_timestamp": observed_timestamp, "observed_delta": delta,
                "metric_expected_description":
                "number of generation tokens processed, per pinned b9519 server documentation"}
    (lab.evidence / "llama-native-prometheus.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Prometheus observes the bounded native llama.cpp generation counter increase",
              valid, {"target_up": target["value"][1] == "1",
                      "metric": "llamacpp:tokens_predicted_total",
                      "exact_zero_baseline": baseline == 0, "same_series": same_series,
                      "later_scrape": later_scrape, "counter_increase": delta,
                      "completion_tokens": request.get("completion_tokens"),
                      "llama_release": "b9519", "gpu_layers": 0})
