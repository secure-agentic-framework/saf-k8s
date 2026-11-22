"""Exercise native HPA bounds with a local deterministic external-metric fixture."""
import base64
import json
from pathlib import Path
import tempfile
import time


HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "metrics_provider.py"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-0903-007"
CONTROL_ID = "SAF-K8S-0903-007"
METRIC = "saf_fixture_demand"
METRIC_LABELS = {"fixture": CONTROL_ID}
WORKLOAD = "synthetic-inference"
PROVIDER = "synthetic-metrics"
SCOPE = (
    "One disposable Kind cluster (the harness-pinned Kubernetes v1.36.1 node image), one case-owned "
    "namespace, one inert Python Deployment capped at four Pods during the intentionally unsafe baseline, "
    "and one case-owned HTTPS external-metrics API fixture. The native autoscaling/v2 HPA controller reads "
    "a deterministic synthetic external metric and scales only that Deployment. The case observes an unsafe "
    "baseline reaching its configured ceiling, then verifies a guarded maximum of three replicas, a one-Pod "
    "per-30-second scale-up policy, and a 30-second scale-down stabilization window. No GPU, GPU metric "
    "provider, KEDA, inference server, real workload, demand source, external traffic, co-host, or production "
    "cluster is involved. The fixture creates only a short-lived local API serving certificate."
)


def _kubectl(lab, *args, timeout=45, allow_failure=False, **kwargs):
    return lab.kubectl("-n", NAMESPACE, *args, timeout=timeout,
                       allow_failure=allow_failure, **kwargs)


def _apply(lab, obj):
    return json.loads(_kubectl(lab, "apply", "-f", "-", "-o", "json",
                               payload=json.dumps(obj)).stdout)


def _get(lab, kind, name):
    return json.loads(_kubectl(lab, "get", kind, name, "-o", "json").stdout)


def _create_provider(lab, temp):
    service_dns = f"{PROVIDER}.{NAMESPACE}.svc"
    cert, key = temp / "serving.crt", temp / "serving.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", f"/CN={service_dns}", "-addext", f"subjectAltName=DNS:{service_dns}",
                "-keyout", str(key), "-out", str(cert), timeout=30)
    _kubectl(lab, "create", "secret", "tls", "synthetic-metrics-tls",
             f"--cert={cert}", f"--key={key}")
    _apply(lab, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "synthetic-metrics-fixture"},
        "immutable": True, "data": {"metrics_provider.py": FIXTURE.read_text(encoding="utf-8")},
    })
    _apply(lab, {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": PROVIDER, "labels": {"app": PROVIDER,
                                                       "saf.example/control": CONTROL_ID}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": PROVIDER}},
                 "template": {"metadata": {"labels": {"app": PROVIDER}}, "spec": {
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "provider", "image": IMAGE,
                         "imagePullPolicy": "IfNotPresent",
                         "command": ["python", "/case/metrics_provider.py"],
                         "env": [{"name": "INITIAL_DEMAND", "value": "1"}],
                         "ports": [{"name": "https", "containerPort": 6443}],
                         "readinessProbe": {"httpGet": {"path": "/-/ready", "port": "https",
                                                           "scheme": "HTTPS"},
                                            "periodSeconds": 2, "failureThreshold": 30},
                         "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                       "limits": {"cpu": "100m", "memory": "64Mi"}},
                         "securityContext": {"allowPrivilegeEscalation": False,
                             "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
                         "volumeMounts": [{"name": "fixture", "mountPath": "/case", "readOnly": True},
                                          {"name": "tls", "mountPath": "/tls", "readOnly": True},
                                          {"name": "tmp", "mountPath": "/tmp"}]}],
                     "volumes": [{"name": "fixture", "configMap": {"name": "synthetic-metrics-fixture"}},
                                 {"name": "tls", "secret": {"secretName": "synthetic-metrics-tls",
                                                               "defaultMode": 292}},
                                 {"name": "tmp", "emptyDir": {}}]}}},
    })
    _apply(lab, {"apiVersion": "v1", "kind": "Service",
                 "metadata": {"name": PROVIDER},
                 "spec": {"selector": {"app": PROVIDER},
                          "ports": [{"name": "https", "port": 443, "targetPort": 6443}]}})
    _apply(lab, {"apiVersion": "apiregistration.k8s.io/v1", "kind": "APIService",
                 "metadata": {"name": "v1beta1.external.metrics.k8s.io"},
                 "spec": {"group": "external.metrics.k8s.io", "version": "v1beta1",
                          "groupPriorityMinimum": 100, "versionPriority": 100,
                          "caBundle": base64.b64encode(cert.read_bytes()).decode("ascii"),
                          "service": {"namespace": NAMESPACE, "name": PROVIDER, "port": 443}}})
    _kubectl(lab, "rollout", "status", f"deployment/{PROVIDER}", "--timeout=120s", timeout=130)
    _kubectl(lab, "wait", "--for=condition=Available",
             "apiservice/v1beta1.external.metrics.k8s.io", "--timeout=120s", timeout=130)


def _create_workload(lab):
    _apply(lab, {"apiVersion": "apps/v1", "kind": "Deployment",
                 "metadata": {"name": WORKLOAD, "labels": {"saf.example/control": CONTROL_ID}},
                 "spec": {"replicas": 1, "selector": {"matchLabels": {"app": WORKLOAD}},
                          "template": {"metadata": {"labels": {"app": WORKLOAD,
                                                                   "saf.example/control": CONTROL_ID}},
                                       "spec": {"automountServiceAccountToken": False,
                                           "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                                               "seccompProfile": {"type": "RuntimeDefault"}},
                                           "containers": [{"name": "inert", "image": IMAGE,
                                               "imagePullPolicy": "IfNotPresent",
                                               "command": ["python", "-c",
                                                           "import time; time.sleep(86400)"],
                                               "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                             "limits": {"cpu": "100m", "memory": "64Mi"}},
                                               "securityContext": {"allowPrivilegeEscalation": False,
                                                   "readOnlyRootFilesystem": True,
                                                   "capabilities": {"drop": ["ALL"]}}}]}}}})
    _kubectl(lab, "rollout", "status", f"deployment/{WORKLOAD}", "--timeout=120s", timeout=130)


def _hpa(name, max_replicas, scaleup_pods, scaleup_period, down_stabilization, down_pods):
    return {"apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": name},
            "spec": {"scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment",
                                         "name": WORKLOAD},
                     "minReplicas": 1, "maxReplicas": max_replicas,
                     "metrics": [{"type": "External", "external": {
                         "metric": {"name": METRIC, "selector": {"matchLabels": METRIC_LABELS}},
                         "target": {"type": "AverageValue", "averageValue": "1"}}}],
                     "behavior": {
                         "scaleUp": {"stabilizationWindowSeconds": 0, "selectPolicy": "Max",
                                     "policies": [{"type": "Pods", "value": scaleup_pods,
                                                   "periodSeconds": scaleup_period}]},
                         "scaleDown": {"stabilizationWindowSeconds": down_stabilization,
                                       "policies": [{"type": "Pods", "value": down_pods,
                                                     "periodSeconds": 15}]}}}}


def _fixture_demand(lab, value):
    command = ("from pathlib import Path; p=Path('/tmp/demand.next'); "
               f"p.write_text('{int(value)}'); p.replace('/tmp/demand.json')")
    _kubectl(lab, "exec", f"deployment/{PROVIDER}", "--", "python", "-c", command)
    deadline = time.monotonic() + 90
    last = None
    while time.monotonic() < deadline:
        state = _kubectl(lab, "exec", f"deployment/{PROVIDER}", "--", "cat", "/tmp/demand.json").stdout.strip()
        try:
            response = json.loads(_kubectl(lab, "get", "--raw",
                f"/apis/external.metrics.k8s.io/v1beta1/namespaces/{NAMESPACE}/{METRIC}"
            ).stdout)
        except Exception as error:
            lab.block(f"The case-owned external-metrics fixture returned an invalid API response: {error}")
        values = [item.get("value") for item in response.get("items", [])
                  if item.get("metricName") == METRIC and item.get("metricLabels") == METRIC_LABELS]
        last = {"fixture_file_value": state, "api_values": values}
        if state == str(value) and values == [str(value)]:
            return last
        time.sleep(2)
    lab.block(f"The deterministic fixture did not expose requested demand {value}: {last}")


def _state(lab, hpa_name):
    try:
        deployment = _get(lab, "deployment", WORKLOAD)
        hpa = _get(lab, "hpa", hpa_name)
    except Exception as error:
        lab.block(f"Could not read the case-owned HPA or Deployment state: {error}")
    return {"deployment_spec_replicas": deployment.get("spec", {}).get("replicas"),
            "deployment_status_replicas": deployment.get("status", {}).get("replicas", 0),
            "deployment_ready_replicas": deployment.get("status", {}).get("readyReplicas", 0),
            "hpa_desired_replicas": hpa.get("status", {}).get("desiredReplicas"),
            "hpa_current_replicas": hpa.get("status", {}).get("currentReplicas"),
            "hpa_max_replicas": hpa.get("spec", {}).get("maxReplicas"),
            "hpa_behavior": hpa.get("spec", {}).get("behavior"),
            "hpa_metrics": hpa.get("status", {}).get("currentMetrics", []),
            "hpa_reasons": {c["type"]: c["reason"] for c in hpa.get("status", {}).get("conditions", [])}}


def _wait_replicas(lab, hpa_name, expected, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _state(lab, hpa_name)
        if (last["deployment_spec_replicas"] == expected
                and last["deployment_ready_replicas"] == expected
                and last["hpa_desired_replicas"] == expected):
            return last
        time.sleep(3)
    lab.block(f"Case-owned workload did not reach {expected} ready replicas: {last}")


def _verify_owned_state(lab):
    provider = _get(lab, "deployment", PROVIDER)
    workload = _get(lab, "deployment", WORKLOAD)
    config = json.loads(_kubectl(lab, "get", "configmap", "synthetic-metrics-fixture", "-o", "json").stdout)
    api_service = json.loads(lab.kubectl(
        "get", "apiservice", "v1beta1.external.metrics.k8s.io", "-o", "json").stdout)
    provider_pod = provider["spec"]["template"]["spec"]
    workload_pod = workload["spec"]["template"]["spec"]
    provider_container = provider_pod["containers"][0]
    workload_container = workload_pod["containers"][0]
    valid = (
        config.get("data", {}).get("metrics_provider.py") == FIXTURE.read_text(encoding="utf-8")
        and provider.get("metadata", {}).get("labels", {}).get("app") == PROVIDER
        and workload.get("metadata", {}).get("labels", {}).get("saf.example/control") == CONTROL_ID
        and provider_pod.get("automountServiceAccountToken") is False
        and workload_pod.get("automountServiceAccountToken") is False
        and provider_container.get("image") == IMAGE
        and workload_container.get("image") == IMAGE
        and workload_container.get("command") == ["python", "-c", "import time; time.sleep(86400)"]
        and not api_service["spec"].get("insecureSkipTLSVerify", False)
        and bool(api_service["spec"].get("caBundle"))
        and api_service.get("spec", {}).get("service", {}).get("namespace") == NAMESPACE
    )
    return valid, {"provider_image": provider_container.get("image"),
                   "workload_image": workload_container.get("image"),
                   "workload_command": workload_container.get("command"),
                   "workload_control_label": workload.get("metadata", {}).get("labels", {}).get("saf.example/control"),
                   "provider_token_mounted": provider_pod.get("automountServiceAccountToken"),
                   "workload_token_mounted": workload_pod.get("automountServiceAccountToken"),
                   "fixture_configmap_matches_source": config.get("data", {}).get("metrics_provider.py") == FIXTURE.read_text(encoding="utf-8"),
                   "api_service_namespace": api_service.get("spec", {}).get("service", {}).get("namespace"),
                   "api_service_skips_backend_certificate_verification": api_service["spec"].get("insecureSkipTLSVerify", False)}


def _sample(lab, hpa, duration):
    start = time.monotonic()
    states = []
    while time.monotonic() - start < duration:
        state = _state(lab, hpa)
        states.append({"elapsed": round(time.monotonic() - start, 2), **state})
        time.sleep(2)
    return states


def _replicas(state):
    return {"requested": state["deployment_spec_replicas"],
            "ready": state["deployment_ready_replicas"],
            "desired": state["hpa_desired_replicas"], "maximum": state["hpa_max_replicas"]}


def run(lab):
    _kubectl(lab, "create", "namespace", NAMESPACE)
    facts = {}
    with tempfile.TemporaryDirectory(prefix="saf-0903-007-") as directory:
        _create_provider(lab, Path(directory))
        _create_workload(lab)
        owned_ok, owned_observation = _verify_owned_state(lab)
        lab.check("positive", "The metric fixture and inert target match the case-owned pinned manifests",
                  owned_ok, owned_observation)
        initial = _fixture_demand(lab, 1)
        lab.check("positive", "The aggregated API exposes the exact fixed synthetic demand",
                  initial == {"fixture_file_value": "1", "api_values": ["1"]}, initial)

        baseline = "hpa-baseline"
        _apply(lab, _hpa(baseline, max_replicas=4, scaleup_pods=8,
                         scaleup_period=15, down_stabilization=0, down_pods=8))
        facts["baseline_demand"] = _fixture_demand(lab, 40)
        facts["baseline_window"] = _sample(lab, baseline, 24)
        observed = any(item["deployment_spec_replicas"] == 4 for item in facts["baseline_window"])
        before = _replicas(_wait_replicas(lab, baseline, 4, timeout=40))
        lab.check("red", "The broader baseline permits four requested replicas in the initial high-demand period",
                  observed and before == {"requested": 4, "ready": 4, "desired": 4, "maximum": 4},
                  {**before, "four_requested_in_window": observed})

        _fixture_demand(lab, 1)
        _wait_replicas(lab, baseline, 1, timeout=60)
        _kubectl(lab, "delete", "hpa", baseline, "--wait=true", timeout=30)
        guarded = "hpa-guarded"
        _apply(lab, _hpa(guarded, max_replicas=3, scaleup_pods=1,
                         scaleup_period=30, down_stabilization=30, down_pods=6))
        _wait_replicas(lab, guarded, 1, timeout=45)
        facts["guarded_demand"] = _fixture_demand(lab, 40)
        rate = _sample(lab, guarded, 24)
        facts["guarded_rate_window"] = rate
        counts = {item["deployment_spec_replicas"] for item in rate}
        policy = rate[-1]["hpa_behavior"]["scaleUp"]["policies"]
        first_only = counts <= {1, 2} and 2 in counts
        lab.check("green", "The active HPA requests only one additional replica during the comparable high-demand window",
                  first_only and policy == [{"type": "Pods", "value": 1, "periodSeconds": 30}],
                  {"only_one_additional_replica": first_only, "policy": policy})

        max_state = _wait_replicas(lab, guarded, 3, timeout=95)
        facts["maximum_state"] = max_state
        max_replicas = _replicas(max_state)
        capped = max_state["hpa_reasons"].get("ScalingLimited") == "TooManyReplicas"
        lab.check("green", "Sustained demand reaches three Ready Pods and the native controller reports its ceiling",
                  capped and max_replicas == {"requested": 3, "ready": 3, "desired": 3, "maximum": 3},
                  {**max_replicas, "ceiling_reported": capped})

        facts["low_demand"] = _fixture_demand(lab, 1)
        low = _sample(lab, guarded, 20)
        facts["stabilization_window"] = low
        maintained = all(item["deployment_spec_replicas"] == 3 for item in low)
        reported = any(item["hpa_reasons"].get("AbleToScale") == "ScaleDownStabilized" for item in low)
        window = low[-1]["hpa_behavior"]["scaleDown"]["stabilizationWindowSeconds"]
        lab.check("green", "The controller retains three replicas and reports downscale stabilization after demand falls",
                  maintained and reported and window == 30,
                  {"window_seconds": window, "held_replicas": maintained, "stabilization_reported": reported})
        after = _replicas(_wait_replicas(lab, guarded, 1, timeout=65))
        lab.check("positive", "After stabilization expires the inert workload returns to one Ready Pod",
                  after == {"requested": 1, "ready": 1, "desired": 1, "maximum": 3}, after)
    (lab.evidence / "hpa-observations.raw.json").write_text(json.dumps(facts, indent=2) + "\n")
