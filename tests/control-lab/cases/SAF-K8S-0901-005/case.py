"""Observe participant namespace isolation and approved local health access."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE_A = "saf-0901-005-participant-a"
NAMESPACE_B = "saf-0901-005-participant-b"
AGGREGATION_NS = "saf-0901-005-aggregation"
PARTICIPANTS = {
    "participant-a": {"namespace": NAMESPACE_A, "marker": "SAF-0901-005-PARTICIPANT-A-HEALTH-7f21"},
    "participant-b": {"namespace": NAMESPACE_B, "marker": "SAF-0901-005-PARTICIPANT-B-HEALTH-9c34"},
}
AGGREGATION_MARKER = "SAF-0901-005-APPROVED-AGGREGATION-HEALTH-2a68"
ROLE_LABEL = "saf-k8s.example/0901-005-role"
APP_LABEL = "saf-k8s.example/0901-005-app"
AGGREGATION_SERVICE = "approved-aggregation"
PORT = 8080
SCOPE = (
    "One disposable Kind cluster on Kubernetes v1.36.1 with two synthetic participant namespaces "
    "and one case-owned local aggregation namespace. Two participant mock HTTP responders first "
    "exchange only fixed /healthz markers before NetworkPolicy, then the same ordinary health path "
    "is checked after namespace policies isolate participants and permit the approved aggregation "
    "Service. Both participants independently contact the identical aggregation ClusterIP and port. "
    "No model, training, gradient, adversarial input, real service, feed, or external target is used."
)


def kubectl(lab, *args, timeout=35, allow_failure=False, **kwargs):
    return lab.kubectl(*args, timeout=timeout, allow_failure=allow_failure, **kwargs)


def apply_json(lab, resource):
    namespace = resource["metadata"].get("namespace")
    args = ["-n", namespace] if namespace else []
    kubectl(lab, *args, "apply", "-f", "-", payload=json.dumps(resource))


def verify_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected pinned kind v0.32.0, got {kind_version!r}")
    server_version = json.loads(kubectl(lab, "version", "-o", "json").stdout).get("serverVersion", {})
    if server_version.get("gitVersion") != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server_version.get('gitVersion')!r}")

    kubectl(lab, "-n", "kube-system", "rollout", "status", "daemonset/kindnet",
            "--timeout=30s", timeout=40)
    kindnet = json.loads(kubectl(
        lab, "-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    desired = kindnet.get("status", {}).get("desiredNumberScheduled", 0)
    ready = kindnet.get("status", {}).get("numberReady", 0)
    images = [container.get("image", "") for container in
              kindnet.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])]
    kindnet_ready = desired >= 2 and ready >= 2 and any("kindnetd" in image for image in images)
    lab.check("positive", "Pinned Kubernetes and bundled kindnet are ready on both nodes",
              kindnet_ready,
              {"kind_version": kind_version, "kubernetes_version": server_version.get("gitVersion"),
               "kindnet_images": images, "ready_nodes": ready, "desired_nodes": desired})


def create_namespace(lab, namespace, kind):
    apply_json(lab, {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": namespace, "labels": {"saf-k8s.example/0901-005-namespace": kind}},
    })


def create_fixture_pod(lab, namespace, pod_name, fixture_name, marker, mode):
    kubectl(lab, "-n", namespace, "create", "configmap", f"{pod_name}-fixture",
            f"--from-file=health_server.py={HERE / 'fixtures' / 'health_server.py'}",
            f"--from-file=health_probe.py={HERE / 'fixtures' / 'health_probe.py'}", "-o", "name")
    labels = {ROLE_LABEL: mode, APP_LABEL: fixture_name}
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace, "labels": labels},
        "spec": {
            "restartPolicy": "Always", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "health-fixture", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "/case/health_server.py"],
                "env": [{"name": "SAF_FIXTURE_NAME", "value": fixture_name},
                        {"name": "SAF_HEALTH_MARKER", "value": marker}],
                "ports": [{"name": "health", "containerPort": PORT}],
                "readinessProbe": {"tcpSocket": {"port": PORT}, "periodSeconds": 1},
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "fixture", "mountPath": "/case", "readOnly": True}],
            }],
            "volumes": [{"name": "fixture", "configMap": {"name": f"{pod_name}-fixture"}}],
        },
    }
    apply_json(lab, pod)
    kubectl(lab, "-n", namespace, "wait", "--for=condition=Ready", f"pod/{pod_name}",
            "--timeout=90s", timeout=100)
    current = json.loads(kubectl(lab, "-n", namespace, "get", "pod", pod_name,
                                  "-o", "json").stdout)
    pod_ip = current.get("status", {}).get("podIP")
    if not pod_ip:
        lab.block(f"Case-owned fixture {namespace}/{pod_name} has no Pod IP")
    return pod_ip


def create_aggregation_service(lab):
    apply_json(lab, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": AGGREGATION_SERVICE, "namespace": AGGREGATION_NS},
        "spec": {"type": "ClusterIP", "selector": {APP_LABEL: "aggregation"},
                 "ports": [{"name": "health", "protocol": "TCP", "port": PORT,
                            "targetPort": PORT}]},
    })
    service = json.loads(kubectl(lab, "-n", AGGREGATION_NS, "get", "service",
                                  AGGREGATION_SERVICE, "-o", "json").stdout)
    address = service.get("spec", {}).get("clusterIP")
    if not address or address == "None":
        lab.block("Case-owned aggregation Service has no ClusterIP")
    ready_addresses = []
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and len(ready_addresses) != 1:
        slices = json.loads(kubectl(
            lab, "-n", AGGREGATION_NS, "get", "endpointslices",
            "-l", f"kubernetes.io/service-name={AGGREGATION_SERVICE}", "-o", "json").stdout)
        ready_addresses = [address for item in slices.get("items", [])
                           for endpoint in item.get("endpoints", [])
                           if endpoint.get("conditions", {}).get("ready")
                           for address in endpoint.get("addresses", [])]
        if len(ready_addresses) != 1:
            time.sleep(0.5)
    if len(ready_addresses) != 1:
        lab.block("Approved aggregation Service does not have exactly one ready mock endpoint")
    return address, ready_addresses[0]


def request_health(lab, evidence_file, phase, source, destination_ip, marker):
    namespace = source["namespace"]
    pod_name = source["pod"]
    result = kubectl(
        lab, "-n", namespace, "exec", f"pod/{pod_name}", "--", "python",
        "/case/health_probe.py", f"http://{destination_ip}:{PORT}/healthz",
        allow_failure=True, timeout=12,
    )
    try:
        observed = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block(f"Health fixture {source['id']} returned no bounded JSON observation")
    record = {"phase": phase, "source_namespace": namespace, "source_pod": pod_name,
              "source_id": source["id"], "destination_ip": destination_ip,
              "destination_port": PORT, "request_path": "/healthz",
              "expected_marker": marker, "exit_code": result.returncode,
              "observation": observed}
    with evidence_file.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    if observed.get("path") != "/healthz":
        lab.block("Health fixture emitted evidence for an unexpected path")
    return observed


def observe_expected(lab, evidence_file, phase, source, destination_ip, marker, reachable):
    deadline = time.monotonic() + 30
    consecutive = 0
    observations = []
    while time.monotonic() < deadline and consecutive < 2:
        observed = request_health(lab, evidence_file, phase, source, destination_ip, marker)
        observations.append(observed)
        matches = (observed.get("result") == "response" and observed.get("status") == 200
                   and observed.get("body") == marker)
        if not reachable:
            matches = (observed.get("result") == "no-response"
                       and observed.get("failure_class") == "TimeoutError")
        consecutive = consecutive + 1 if matches else 0
        if consecutive < 2:
            time.sleep(0.5)
    return consecutive == 2, observations


def capture_server_logs(lab, evidence_file, namespace, pod_name):
    logs = kubectl(lab, "-n", namespace, "logs", f"pod/{pod_name}").stdout
    evidence_file.write_text(logs, encoding="utf-8")


def run(lab):
    verify_platform(lab)
    for namespace, kind in ((NAMESPACE_A, "participant"), (NAMESPACE_B, "participant"),
                            (AGGREGATION_NS, "aggregation")):
        create_namespace(lab, namespace, kind)

    sources = {}
    for participant_id, item in PARTICIPANTS.items():
        pod_name = participant_id
        pod_ip = create_fixture_pod(lab, item["namespace"], pod_name, participant_id,
                                    item["marker"], "participant")
        sources[participant_id] = {"id": participant_id, "namespace": item["namespace"],
                                   "pod": pod_name, "pod_ip": pod_ip,
                                   "marker": item["marker"]}
    aggregation_pod_ip = create_fixture_pod(
        lab, AGGREGATION_NS, "aggregation-mock", "aggregation", AGGREGATION_MARKER, "aggregation")
    aggregation_ip, endpoint_ip = create_aggregation_service(lab)
    if endpoint_ip != aggregation_pod_ip:
        lab.block("Approved aggregation Service endpoint differs from its case-owned Pod")

    workload_receipts = {}
    for namespace, pod_name in ((NAMESPACE_A, "participant-a"),
                                (NAMESPACE_B, "participant-b"),
                                (AGGREGATION_NS, "aggregation-mock")):
        pod = json.loads(kubectl(
            lab, "-n", namespace, "get", "pod", pod_name, "-o", "json").stdout)
        containers = pod.get("spec", {}).get("containers", [])
        statuses = pod.get("status", {}).get("containerStatuses", [])
        ready = (pod.get("status", {}).get("phase") == "Running" and len(statuses) == 1
                 and statuses[0].get("ready") is True)
        if len(containers) != 1 or containers[0].get("image") != IMAGE or not ready:
            lab.block(f"Case-owned pod {namespace}/{pod_name} is not ready on the pinned image")
        workload_receipts[f"{namespace}/{pod_name}"] = pod
    service_receipt = json.loads(kubectl(
        lab, "-n", AGGREGATION_NS, "get", "service", AGGREGATION_SERVICE, "-o", "json").stdout)
    (lab.evidence / "workloads.raw.json").write_text(json.dumps({
        "pods": workload_receipts, "aggregation_service": service_receipt,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    (lab.evidence / "case-scope.json").write_text(json.dumps({
        "control": "SAF-K8S-0901-005", "scope": SCOPE,
        "kind_node_image": "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
        "worker_image": IMAGE,
        "participants": {key: {"namespace": value["namespace"], "pod": value["pod"],
                               "pod_ip": value["pod_ip"], "fixed_health_marker": value["marker"]}
                         for key, value in sources.items()},
        "aggregation": {"namespace": AGGREGATION_NS, "service": AGGREGATION_SERVICE,
                        "cluster_ip": aggregation_ip, "pod_ip": aggregation_pod_ip,
                        "fixed_health_marker": AGGREGATION_MARKER},
        "direct_ip_health_checks_only": True, "dns_scope_tested": False,
        "real_targets_or_feeds_accessed": False, "secrets_collected": False,
        "model_or_gradient_data_used": False,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    raw_observations = lab.evidence / "health-observations.raw.jsonl"
    for source_id, target_id in (("participant-a", "participant-b"),
                                 ("participant-b", "participant-a")):
        source = sources[source_id]
        target = sources[target_id]
        passed, observations = observe_expected(
            lab, raw_observations, "red", source, target["pod_ip"], target["marker"], True)
        lab.check("red", f"{source_id} reaches the other synthetic participant before isolation",
                  passed, {"source_namespace": source["namespace"],
                           "destination_namespace": target["namespace"],
                           "request_path": "/healthz", "expected_fixed_marker": target["marker"],
                           "two_matching_health_replies": passed})

    case_dir = Path(__file__).resolve().parent
    for manifest in ("participant-isolation.yaml", "aggregation-ingress.yaml"):
        lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                    f"kind-{lab.cluster}", "apply", "-f", str(case_dir / manifest))
    policies = {namespace: json.loads(kubectl(
        lab, "-n", namespace, "get", "networkpolicies", "-o", "json").stdout)
                for namespace in (NAMESPACE_A, NAMESPACE_B, AGGREGATION_NS)}
    (lab.evidence / "networkpolicies.raw.json").write_text(
        json.dumps(policies, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for source_id, target_id in (("participant-a", "participant-b"),
                                 ("participant-b", "participant-a")):
        source = sources[source_id]
        target = sources[target_id]
        passed, observations = observe_expected(
            lab, raw_observations, "green", source, target["pod_ip"], target["marker"], False)
        target_health, _ = observe_expected(lab, raw_observations, "positive-listener", target,
                                            "127.0.0.1", target["marker"], True)
        lab.check("green", f"{source_id} cannot reach the other synthetic participant after isolation",
                  passed and target_health, {"source_namespace": source["namespace"],
                                             "destination_namespace": target["namespace"],
                                             "request_path": "/healthz", "two_matching_timeouts": passed,
                                             "same_target_listener_remained_available": target_health})

    same_destination_results = {}
    for source_id in ("participant-a", "participant-b"):
        source = sources[source_id]
        passed, observations = observe_expected(
            lab, raw_observations, "positive", source, aggregation_ip,
            AGGREGATION_MARKER, True)
        same_destination_results[source_id] = passed
        lab.check("positive", f"{source_id} reaches the approved aggregation health Service",
                  passed, {"source_namespace": source["namespace"],
                           "destination_namespace": AGGREGATION_NS,
                           "destination_service": AGGREGATION_SERVICE,
                           "destination_port": PORT, "request_path": "/healthz",
                           "expected_fixed_marker": AGGREGATION_MARKER,
                           "two_matching_health_replies": passed})
    lab.check("positive", "Both participants independently use the identical approved destination",
              same_destination_results == {"participant-a": True, "participant-b": True},
              {"participants": sorted(same_destination_results),
               "identical_service_destination": bool(aggregation_ip), "port": PORT,
               "protocol": "TCP", "path": "/healthz"})

    capture_server_logs(lab, lab.evidence / "participant-a.raw.jsonl", NAMESPACE_A, "participant-a")
    capture_server_logs(lab, lab.evidence / "participant-b.raw.jsonl", NAMESPACE_B, "participant-b")
    capture_server_logs(lab, lab.evidence / "aggregation.raw.jsonl", AGGREGATION_NS,
                        "aggregation-mock")
