"""Verify bounded training Pod admission and synthetic service-priority health."""
import json
import importlib.util
from pathlib import Path
import re
import subprocess
import time
from datetime import datetime, timezone


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CONTROL_ID = "SAF-K8S-1007-007"
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
QUOTA = "saf-1007-007-training-budget"
HEALTH_POD = "saf-1007-007-shared-health"
HEALTH_SERVICE = "saf-1007-007-health"
SHARED_CLASS = "saf-1007-007-shared-service"
TRAINING_CLASS = "saf-1007-007-training"
CASE_LABEL = "saf-lab.example/control"
FIXTURE_LABEL = "saf-lab.example/fixture"
SCOPE = (
    "One disposable Kind v1.36.1 cluster. A small server-side dry-run Pod request is compared "
    "before and after a namespace CPU/memory ResourceQuota; a second request at the remaining "
    "declared budget is admitted. Two case-owned PriorityClasses are read back and resolved "
    "onto dry-run Pods, with preemption disabled. One tokenless, low-resource HTTP fixture Pod "
    "is observed Ready and read through the Kubernetes API Service proxy before and after quota "
    "checks, and looks up the exact in-cluster Kubernetes Service via CoreDNS. A pinned Metrics Server "
    "provides fresh native PodMetrics samples around those probes, and read-only container logs are "
    "checked for additional fixed health requests. A further 5m CPU / 8Mi memory Pod shares the namespace "
    "within quota, serves through an independent case Service, and has fresh observed PodMetrics during coexistence. "
    "This does not create pressure or simulate training. It does not demonstrate actual "
    "scheduler ordering under contention, protection of built-in control-plane components, "
        "CoreDNS resolution latency, production metrics or log pipelines, log forwarding lag, node/network "
    "capacity, or production service availability."
)

_METRICS_PATH = HERE / "metrics_server_supplement.py"
_METRICS_SPEC = importlib.util.spec_from_file_location("saf_1007_007_metrics", _METRICS_PATH)
_METRICS = importlib.util.module_from_spec(_METRICS_SPEC)
_METRICS_SPEC.loader.exec_module(_METRICS)


def prepare_kind(lab, temporary):
    """Generate the one-node profile needed for verified Metrics Server kubelet TLS."""
    config = temporary / "kind.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  kubeadmConfigPatches:
""")
    return _METRICS.configure_metrics_server_kind(lab, temporary, config)


def _metrics_snapshot(lab, pod_name=HEALTH_POD, expected_uid=None, *, retain_usage=False):
    """Read one exact PodMetrics object; retain values only for the additive coexistence sample."""
    identity_before = json.loads(lab.kubectl("get", "pod", pod_name, "-o", "json").stdout)
    uid_before = identity_before.get("metadata", {}).get("uid")
    path = f"/apis/metrics.k8s.io/v1beta1/namespaces/{NAMESPACE}/pods/{pod_name}"
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "get", "--raw", path], env=lab.env, text=True, capture_output=True, timeout=20,
    )
    metrics = {}
    if result.returncode == 0:
        try:
            metrics = json.loads(result.stdout)
        except json.JSONDecodeError:
            metrics = {}
    identity_after = json.loads(lab.kubectl("get", "pod", pod_name, "-o", "json").stdout)
    uid_after = identity_after.get("metadata", {}).get("uid")
    meta = metrics.get("metadata", {})
    exact = (metrics.get("apiVersion") == "metrics.k8s.io/v1beta1"
             and metrics.get("kind") == "PodMetrics"
             and meta.get("name") == pod_name and meta.get("namespace") == NAMESPACE)
    containers = metrics.get("containers", [])
    observed = next((item for item in containers
                     if item.get("name") == "mock-workload"
                     and all(key in item.get("usage", {}) for key in ("cpu", "memory"))), None)
    usage_present = observed is not None
    fresh = False
    try:
        sampled = datetime.fromisoformat(metrics.get("timestamp", "").replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - sampled).total_seconds()
        fresh = -5 <= age <= 90
    except (TypeError, ValueError):
        pass
    uid_match_key = ("uid_matches_original_fixture" if pod_name == HEALTH_POD
                     else "uid_matches_expected_companion_uid")
    normalized = {
        "api_read_succeeded": result.returncode == 0,
        "exact_podmetrics_identity": exact,
        "cpu_memory_usage_present": usage_present,
        "sample_fresh_within_90s": fresh,
        "same_pod_uid_around_sample": bool(uid_before) and uid_before == uid_after,
        uid_match_key: bool(uid_before) and uid_before == (expected_uid or lab.health_fixture_uid),
    }
    if retain_usage:
        return {**normalized, "usage": observed.get("usage", {}) if observed else {},
                "timestamp": metrics.get("timestamp"), "window": metrics.get("window")}
    return normalized



def _wait_metrics(lab, label, pod_name=HEALTH_POD, expected_uid=None, *, retain_usage=False, newer_than=None):
    deadline = time.monotonic() + 100
    latest = None
    while time.monotonic() < deadline:
        latest = _metrics_snapshot(lab, pod_name, expected_uid, retain_usage=retain_usage)
        uid_match_key = ("uid_matches_original_fixture" if pod_name == HEALTH_POD
                         else "uid_matches_expected_companion_uid")
        valid = all(latest.get(key) is True for key in (
            "api_read_succeeded", "exact_podmetrics_identity", "cpu_memory_usage_present",
            "sample_fresh_within_90s", "same_pod_uid_around_sample", uid_match_key))
        if valid and newer_than is not None:
            observed_at = datetime.fromisoformat(latest["timestamp"].replace("Z", "+00:00"))
            valid = observed_at > newer_than
        if valid and (not retain_usage or all(latest.get("usage", {}).get(k) for k in ("cpu", "memory"))):
            return latest
        time.sleep(3)
    lab.block(f"{label} exact PodMetrics sample did not become current and ready")


def _health_log_readback(lab):
    """Read only the fixture container's last bounded log lines and retain no text."""
    before = json.loads(lab.kubectl("get", "pod", HEALTH_POD, "-o", "json").stdout)
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--namespace", NAMESPACE, "logs", f"pod/{HEALTH_POD}", "-c", "mock-workload", "--tail=100"],
        env=lab.env, text=True, capture_output=True, timeout=15,
    )
    if result.returncode:
        after = json.loads(lab.kubectl("get", "pod", HEALTH_POD, "-o", "json").stdout)
        return {"read_succeeded": False, "health_probe_line_count": 0,
                "same_pod_uid_around_log_read": before.get("metadata", {}).get("uid") == after.get("metadata", {}).get("uid"),
                "uid_matches_original_fixture": before.get("metadata", {}).get("uid") == lab.health_fixture_uid}
    lines = re.findall(r'GET /healthz HTTP/[0-9.]+" 200\b', result.stdout)
    after = json.loads(lab.kubectl("get", "pod", HEALTH_POD, "-o", "json").stdout)
    before_uid = before.get("metadata", {}).get("uid")
    after_uid = after.get("metadata", {}).get("uid")
    return {"read_succeeded": True, "health_probe_line_count": len(lines),
            "same_pod_uid_around_log_read": bool(before_uid) and before_uid == after_uid,
            "uid_matches_original_fixture": bool(before_uid) and before_uid == lab.health_fixture_uid}


def _labels():
    return {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "synthetic"}


def _priority_class(name, value, description):
    return {
        "apiVersion": "scheduling.k8s.io/v1",
        "kind": "PriorityClass",
        "metadata": {"name": name, "labels": _labels()},
        "value": value,
        "globalDefault": False,
        "preemptionPolicy": "Never",
        "description": description,
    }


def _pod(name, cpu, memory, priority_class):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {
            "priorityClassName": priority_class,
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "mock-workload",
                "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-m", "http.server", "8080", "--bind", "0.0.0.0",
                            "--directory", "/fixture"],
                "securityContext": {
                    "readOnlyRootFilesystem": True,
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {
                    "requests": {"cpu": cpu, "memory": memory},
                    "limits": {"cpu": "50m", "memory": "64Mi"},
                },
                "readinessProbe": {
                    "httpGet": {"path": "/healthz", "port": 8080},
                    "periodSeconds": 2,
                    "timeoutSeconds": 1,
                    "failureThreshold": 3,
                },
                "volumeMounts": [{"name": "health-fixture", "mountPath": "/fixture", "readOnly": True}],
            }],
            "volumes": [{"name": "health-fixture", "configMap": {"name": HEALTH_POD}}],
        },
    }


def _fixture_objects():
    health_marker = (FIXTURES / "healthz.txt").read_text(encoding="utf-8")
    if health_marker != "SYNTH-1007-007-HEALTH-OK\n":
        raise ValueError("Unexpected case-owned health fixture")
    health = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": HEALTH_POD, "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True,
        "data": {"healthz": health_marker},
    }
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": HEALTH_SERVICE, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {
            "selector": _labels(),
            "ports": [{"name": "http", "port": 80, "targetPort": 8080}],
        },
    }
    return health, service


def _quota():
    return {
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": {"name": QUOTA, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {"hard": {"requests.cpu": "20m", "requests.memory": "32Mi"}},
    }


def _check_health(lab, phase):
    pod = json.loads(lab.kubectl("get", "pod", HEALTH_POD, "-o", "json").stdout)
    ready = pod.get("status", {}).get("phase") == "Running" and any(
        status.get("name") == "mock-workload" and status.get("ready") is True
        for status in pod.get("status", {}).get("containerStatuses", [])
    )
    proxy_path = f"/api/v1/namespaces/{NAMESPACE}/services/{HEALTH_SERVICE}:http/proxy/healthz"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        endpoint = lab.kubectl("get", "--raw", proxy_path, allow_failure=True)
        if endpoint.returncode == 0:
            marker = endpoint.stdout
            break
        if "(ServiceUnavailable)" not in endpoint.stderr or "no endpoints available" not in endpoint.stderr:
            lab.block("Fixture service proxy did not return the expected health response")
        time.sleep(0.3)
    else:
        lab.block("Fixture Service endpoints did not converge after Pod readiness")
    kube_service = json.loads(lab.kubectl("get", "service", "kubernetes", "-n", "default", "-o", "json").stdout)
    lookup = "import json,socket; print(json.dumps(sorted(set(socket.gethostbyname_ex('kubernetes.default.svc.cluster.local')[2]))))"
    resolved = json.loads(lab.kubectl("exec", f"pod/{HEALTH_POD}", "--", "python", "-c", lookup).stdout)
    service_address_verified = resolved == [kube_service["spec"]["clusterIP"]]
    lab.check(
        "positive",
        f"{phase}: the steady fixture serves its marker and resolves the exact in-cluster Service",
        ready and marker == "SYNTH-1007-007-HEALTH-OK\n" and service_address_verified,
        {"pod_ready": ready, "http_marker_matches": marker == "SYNTH-1007-007-HEALTH-OK\n",
         "pod_uid_present": bool(pod.get("metadata", {}).get("uid")),
         "cluster_dns_matches_service_address": service_address_verified},
    )
    return {"pod_uid": pod["metadata"]["uid"], "ready": ready, "dns_matches": service_address_verified,
            "marker": marker}


def _wait_ready(lab):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{HEALTH_POD}", "--timeout=90s", timeout=100)


def _assert_priority_readback(lab):
    shared = json.loads(lab.kubectl("get", "priorityclass", SHARED_CLASS, "-o", "json").stdout)
    training = json.loads(lab.kubectl("get", "priorityclass", TRAINING_CLASS, "-o", "json").stdout)
    observed = {
        "shared_value": shared.get("value"),
        "training_value": training.get("value"),
        "both_nonpreempting": shared.get("preemptionPolicy") == "Never"
        and training.get("preemptionPolicy") == "Never",
        "neither_global_default": shared.get("globalDefault", False) is False
        and training.get("globalDefault", False) is False,
    }
    lab.check(
        "positive", "Case-owned priority metadata declares shared service above training, without preemption",
        observed["shared_value"] == 1000 and observed["training_value"] == 10
        and observed["both_nonpreempting"] and observed["neither_global_default"], observed,
    )


def run(lab):
    _METRICS._install_metrics_server(lab, lab.kubeconfig.parent)
    lab.create(_priority_class(SHARED_CLASS, 1000, "Synthetic shared health fixture only"))
    lab.create(_priority_class(TRAINING_CLASS, 10, "Synthetic training probe only"))
    _assert_priority_readback(lab)

    baseline = lab.create(
        _pod("saf-1007-007-training-baseline", "16m", "24Mi", TRAINING_CLASS),
        dry_run=True, allow_failure=True,
    )
    lab.check(
        "red", "Without a namespace quota, the small synthetic training request reaches admission",
        baseline.returncode == 0,
        {"server_side_dry_run_admitted": baseline.returncode == 0},
    )

    health_config, health_service = _fixture_objects()
    lab.create(health_config)
    lab.create(_pod(HEALTH_POD, "5m", "8Mi", SHARED_CLASS))
    lab.create(health_service)
    _wait_ready(lab)
    health_before = _check_health(lab, "before quota enforcement")
    lab.health_fixture_uid = health_before["pod_uid"]
    metrics_before = _wait_metrics(lab, "pre-admission")
    logs_before = _health_log_readback(lab)

    lab.create(_quota())
    quota = json.loads(lab.kubectl("get", "resourcequota", QUOTA, "-o", "json").stdout)
    hard = quota.get("spec", {}).get("hard", {})
    quota_readback = hard.get("requests.cpu") == "20m" and hard.get("requests.memory") == "32Mi"
    lab.check("positive", "The namespace quota readback matches the fixed small budget",
              quota_readback, {"cpu": hard.get("requests.cpu"), "memory": hard.get("requests.memory")})
    usage_ready = False
    for _ in range(30):
        quota = json.loads(lab.kubectl("get", "resourcequota", QUOTA, "-o", "json").stdout)
        used = quota.get("status", {}).get("used", {})
        if used.get("requests.cpu") == "5m" and used.get("requests.memory") == "8Mi":
            usage_ready = True
            break
        time.sleep(1)
    lab.check("positive", "Quota usage readback accounts for only the steady fixture before probes",
              usage_ready, {"used_cpu": used.get("requests.cpu"), "used_memory": used.get("requests.memory")})

    over_budget = lab.create(
        _pod("saf-1007-007-training-over-budget", "16m", "24Mi", TRAINING_CLASS),
        dry_run=True, allow_failure=True,
    )
    denied_by_quota = (
        over_budget.returncode != 0
        and "exceeded quota" in over_budget.stderr.lower()
        and QUOTA in over_budget.stderr
        and "requests.cpu" in over_budget.stderr
    )
    lab.check(
        "green", "ResourceQuota refuses a request that exceeds the declared CPU budget",
        denied_by_quota,
        {"server_side_dry_run_denied_by_named_quota": denied_by_quota,
         "detail_is_quota_refusal": "exceeded quota" in over_budget.stderr.lower()},
    )

    over_memory = lab.create(
        _pod("saf-1007-007-training-over-memory", "15m", "25Mi", TRAINING_CLASS),
        dry_run=True, allow_failure=True,
    )
    memory_denied = (over_memory.returncode != 0 and "exceeded quota" in over_memory.stderr.lower()
                     and QUOTA in over_memory.stderr and "requests.memory" in over_memory.stderr)
    lab.check("green", "The named quota separately refuses an over-budget memory request",
              memory_denied, {"rejected_by_named_memory_quota": memory_denied})

    at_budget = lab.create(
        _pod("saf-1007-007-training-at-budget", "15m", "24Mi", TRAINING_CLASS),
        dry_run=True, allow_failure=True,
    )
    try:
        admitted = json.loads(at_budget.stdout) if at_budget.returncode == 0 else {}
    except json.JSONDecodeError:
        admitted = {}
    spec = admitted.get("spec", {})
    exact_budget_and_priority = (
        at_budget.returncode == 0
        and spec.get("priorityClassName") == TRAINING_CLASS
        and spec.get("priority") == 10
        and spec.get("preemptionPolicy") == "Never"
        and spec.get("containers", [{}])[0].get("resources", {}).get("requests")
        == {"cpu": "15m", "memory": "24Mi"}
    )
    lab.check(
        "positive", "The request at the remaining declared budget is admitted with resolved low non-preempting priority",
        exact_budget_and_priority,
        {"server_side_dry_run_admitted_at_budget": at_budget.returncode == 0,
         "resolved_priority_matches": spec.get("priority") == 10,
         "training_class_matches": spec.get("priorityClassName") == TRAINING_CLASS,
         "preemption_disabled": spec.get("preemptionPolicy") == "Never"},
    )

    health_after = _check_health(lab, "after quota refusal and bounded admission probes")
    pod_inventory = json.loads(lab.kubectl("get", "pods", "-o", "json").stdout)
    only_steady_fixture = [item["metadata"]["uid"] for item in pod_inventory["items"]] == [health_before["pod_uid"]]
    same_steady_fixture = health_before["pod_uid"] == health_after["pod_uid"]
    lab.check("positive", "The same healthy Pod remains and the dry-run requests created no training Pods",
              same_steady_fixture and only_steady_fixture,
              {"same_steady_fixture": same_steady_fixture, "training_pods_created": not only_steady_fixture})
    shared_pod = json.loads(lab.kubectl("get", "pod", HEALTH_POD, "-o", "json").stdout)
    shared_spec = shared_pod.get("spec", {})
    lab.check(
        "positive", "The steady fixture resolves to the higher declared shared-service priority",
        shared_spec.get("priorityClassName") == SHARED_CLASS and shared_spec.get("priority") == 1000,
        {"priority_class_matches": shared_spec.get("priorityClassName") == SHARED_CLASS,
         "resolved_priority_matches": shared_spec.get("priority") == 1000,
         "pod_uid_present": bool(shared_pod.get("metadata", {}).get("uid"))},
    )

    metrics_after = _wait_metrics(lab, "post-admission")
    logs_after = _health_log_readback(lab)
    metrics_both = all(metrics_before.values()) and all(metrics_after.values())
    lab.check(
        "positive", "The exact steady fixture has fresh native CPU and memory PodMetrics before and after quota probes",
        metrics_both,
        {"before": metrics_before, "after": metrics_after,
         "same_fixture_uid_across_samples": health_before["pod_uid"] == health_after["pod_uid"]},
    )
    logs_observed = {
        "before_read_succeeded": logs_before["read_succeeded"],
        "after_read_succeeded": logs_after["read_succeeded"],
        "health_probe_present_before": logs_before["health_probe_line_count"] > 0,
        "health_probe_present_after": logs_after["health_probe_line_count"] > 0,
        "additional_health_probe_after_quota_probes": logs_after["health_probe_line_count"] > logs_before["health_probe_line_count"],
        "same_original_pod_uid_around_both_log_reads": (
            logs_before["same_pod_uid_around_log_read"] and logs_after["same_pod_uid_around_log_read"]
            and logs_before["uid_matches_original_fixture"] and logs_after["uid_matches_original_fixture"]
        ),
        "raw_log_text_retained": False,
    }
    logs_both = all(value for key, value in logs_observed.items() if key != "raw_log_text_retained")
    lab.check(
        "positive", "Read-only native container logs show additional harmless health probes after quota checks",
        logs_both, logs_observed,
    )

    (lab.evidence / "quota-health-observations.raw.json").write_text(json.dumps({
        "quota": quota, "health_before": health_before, "health_after": health_after,
        "all_dry_run_probes_left_inventory_unchanged": only_steady_fixture,
        "metrics_before": metrics_before, "metrics_after": metrics_after,
        "health_log_observations": logs_observed,
        "checks": lab.checks,
    }, indent=2, sort_keys=True) + "\n")

    _observe_bounded_coexistence(lab)


COEXIST_POD = "saf-1007-007-bounded-coexistence"
COEXIST_SERVICE = "saf-1007-007-coexistence-health"
COEXIST_CONFIG = "saf-1007-007-coexistence-marker"
COEXIST_MARKER = "SYNTH-1007-007-COEXIST-OK\n"
COEXIST_LABELS = {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "bounded-coexistence"}


def _pod_service_probe(lab, pod_name, service_name, expected_marker):
    before = json.loads(lab.kubectl("get", "pod", pod_name, "-o", "json").stdout)
    before_status = next((item for item in before.get("status", {}).get("containerStatuses", [])
                          if item.get("name") == "mock-workload"), {})
    ready = before.get("status", {}).get("phase") == "Running" and before_status.get("ready") is True
    endpoints = json.loads(lab.kubectl("get", "endpoints", service_name, "-o", "json").stdout)
    pod_ip = before.get("status", {}).get("podIP")
    endpoint_matches = any(address.get("ip") == pod_ip
                           for subset in endpoints.get("subsets", [])
                           for address in subset.get("addresses", []))
    path = f"/api/v1/namespaces/{NAMESPACE}/services/{service_name}:http/proxy/healthz"
    deadline = time.monotonic() + 20
    response_ok = False
    while time.monotonic() < deadline:
        response = lab.kubectl("get", "--raw", path, allow_failure=True)
        if response.returncode == 0:
            response_ok = response.stdout == expected_marker
            break
        if "no endpoints available" not in response.stderr and "ServiceUnavailable" not in response.stderr:
            lab.block("Owned service proxy returned an unexpected response during coexistence")
        time.sleep(0.3)
    after = json.loads(lab.kubectl("get", "pod", pod_name, "-o", "json").stdout)
    after_status = next((item for item in after.get("status", {}).get("containerStatuses", [])
                         if item.get("name") == "mock-workload"), {})
    return {"pod_uid": before.get("metadata", {}).get("uid"),
            "same_uid_after_request": before.get("metadata", {}).get("uid") == after.get("metadata", {}).get("uid"),
            "pod_ready": ready and after.get("status", {}).get("phase") == "Running" and after_status.get("ready") is True,
            "service_endpoint_matches_pod": bool(pod_ip) and endpoint_matches,
            "independent_service_response_matches": response_ok}


def _observe_bounded_coexistence(lab):
    config = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": COEXIST_CONFIG, "namespace": NAMESPACE, "labels": _labels()},
              "immutable": True, "data": {"healthz": COEXIST_MARKER}}
    workload = _pod(COEXIST_POD, "5m", "8Mi", TRAINING_CLASS)
    workload["metadata"]["labels"] = COEXIST_LABELS
    workload["spec"]["volumes"] = [{"name": "health-fixture", "configMap": {"name": COEXIST_CONFIG}}]
    service = {"apiVersion": "v1", "kind": "Service",
               "metadata": {"name": COEXIST_SERVICE, "namespace": NAMESPACE, "labels": _labels()},
               "spec": {"selector": COEXIST_LABELS,
                        "ports": [{"name": "http", "port": 80, "targetPort": 8080}]}}
    lab.create(config)
    lab.create(workload)
    lab.create(service)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{COEXIST_POD}", "--timeout=90s", timeout=100)
    companion = json.loads(lab.kubectl("get", "pod", COEXIST_POD, "-o", "json").stdout)
    companion_uid = companion["metadata"]["uid"]
    coexist_quota_ready = False
    for _ in range(25):
        quota = json.loads(lab.kubectl("get", "resourcequota", QUOTA, "-o", "json").stdout)
        used = quota.get("status", {}).get("used", {})
        if used.get("requests.cpu") == "10m" and used.get("requests.memory") == "16Mi":
            coexist_quota_ready = True
            break
        time.sleep(1)
    if not coexist_quota_ready:
        lab.block("The bounded coexistence Pod did not remain within the declared namespace quota")

    health_before = json.loads(lab.kubectl("get", "pod", HEALTH_POD, "-o", "json").stdout)
    coexist_before = _wait_metrics(lab, "bounded coexistence Pod", COEXIST_POD,
                                   companion_uid, retain_usage=True)
    health_during_metrics = json.loads(lab.kubectl("get", "pod", HEALTH_POD, "-o", "json").stdout)
    before_sample_time = datetime.fromisoformat(coexist_before["timestamp"].replace("Z", "+00:00"))
    coexist_after = _wait_metrics(lab, "bounded coexistence Pod after service probes", COEXIST_POD,
                                  companion_uid, retain_usage=True, newer_than=before_sample_time)
    health_after_metrics = json.loads(lab.kubectl("get", "pod", HEALTH_POD, "-o", "json").stdout)
    original_service = _pod_service_probe(lab, HEALTH_POD, HEALTH_SERVICE, "SYNTH-1007-007-HEALTH-OK\n")
    companion_service = _pod_service_probe(lab, COEXIST_POD, COEXIST_SERVICE, COEXIST_MARKER)
    original_uid = getattr(lab, "health_fixture_uid", None)
    both_services_and_pods = (
        health_before.get("metadata", {}).get("uid") == original_uid ==
        health_during_metrics.get("metadata", {}).get("uid") ==
        health_after_metrics.get("metadata", {}).get("uid")
        and health_before.get("status", {}).get("phase") == "Running"
        and health_after_metrics.get("status", {}).get("phase") == "Running"
        and all(original_service.values()) and all(companion_service.values())
    )
    metrics_observed = (all(coexist_before.get(key) is True for key in (
        "api_read_succeeded", "exact_podmetrics_identity", "cpu_memory_usage_present",
        "sample_fresh_within_90s", "same_pod_uid_around_sample", "uid_matches_expected_companion_uid"))
        and all(coexist_after.get(key) is True for key in (
        "api_read_succeeded", "exact_podmetrics_identity", "cpu_memory_usage_present",
        "sample_fresh_within_90s", "same_pod_uid_around_sample", "uid_matches_expected_companion_uid"))
        and bool(coexist_before.get("usage", {}).get("cpu"))
        and bool(coexist_before.get("usage", {}).get("memory"))
        and bool(coexist_after.get("usage", {}).get("cpu"))
        and bool(coexist_after.get("usage", {}).get("memory")))
    lab.kubectl("delete", "pod", COEXIST_POD, "--wait=true", "--timeout=50s")
    lab.kubectl("delete", "service", COEXIST_SERVICE, "--wait=true")
    lab.kubectl("delete", "configmap", COEXIST_CONFIG, "--wait=true")
    for _ in range(25):
        quota = json.loads(lab.kubectl("get", "resourcequota", QUOTA, "-o", "json").stdout)
        used = quota.get("status", {}).get("used", {})
        if used.get("requests.cpu") == "5m" and used.get("requests.memory") == "8Mi":
            break
        time.sleep(1)
    quota_returned = (used.get("requests.cpu") == "5m" and used.get("requests.memory") == "8Mi")
    lab.check("positive", "A second bounded CPU-only workload coexists with independently ready services and fresh measured metrics",
              coexist_quota_ready and both_services_and_pods and metrics_observed and quota_returned,
              {"coexist_quota_requests": {"cpu": "10m", "memory": "16Mi"},
               "quota_returned_to_original_fixture": quota_returned,
               "original_service": {key: value for key, value in original_service.items() if key != "pod_uid"},
               "companion_service": {key: value for key, value in companion_service.items() if key != "pod_uid"},
               "new_companion_metrics_sample_observed": metrics_observed,
               "both_original_and_companion_pods_remained_ready": both_services_and_pods})
    (lab.evidence / "bounded-coexistence-observations.json").write_text(json.dumps({
        "control": CONTROL_ID,
        "scope": "one case-owned 5m CPU / 8Mi memory HTTP Pod alongside the original case-owned service Pod; no stress load",
        "pods": {"original_uid": original_uid,
                 "coexistence_uid": companion_uid},
        "metrics": {"coexistence_sample_before_service_probes": coexist_before,
                    "coexistence_sample_after_service_probes": coexist_after},
        "services": {"original": original_service, "companion": companion_service},
        "quota": {"coexistence_requests": {"cpu": "10m", "memory": "16Mi"},
                  "returned_to_original": quota_returned},
        "normalized": {"both_services_ready_and_responding": both_services_and_pods,
                       "measured_cpu_memory_present": metrics_observed,
                       "coexistence_quota_accounted": coexist_quota_ready,
                       "cleanup_restored_original_quota": quota_returned},
    }, sort_keys=True, indent=2) + "\n")
