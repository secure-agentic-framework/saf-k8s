"""Inventory one configured non-default feature gate from effective API server metrics."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.parse
import uuid

from lab import Lab


HERE = Path(__file__).parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PEER_NODE_IMAGE = (
    "kindest/node:v1.37.0@sha256:"
    "a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
)
SLEEP_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
DECLARED_FEATURE = "RestartAllContainersOnContainerExits"
WORKER_LABEL = "saf-k8s.example/ndf-worker"
PLUGIN_REASON = "node(s) didn't match Pod's required features"
PEER_NAMESPACE = "saf-ndf-probe"
GATE = "TaintTolerationComparisonOperators"
COMPONENT = "kube-apiserver"
EXPLICIT_DEFAULT_GATE = "ContainerStopSignals"
SCOPE = (
    "Paired disposable Kubernetes v1.36.1 clusters. The stock API server supplies the "
    "effective default and the second API server enables one alpha gate. The test inventories "
    "that component and gate. A separate pinned Kubernetes v1.37.0 peer cluster checks kubelet "
    "declared-feature reporting and default-scheduler placement for one opted-in and one explicitly "
    "disabled worker, then changes only the opted-in worker's provisioned gate and checks "
    "restart-driven report refresh, scheduling, and ordinary Pod viability. This is an "
    "upgrade-compatibility observation, not an authorization control. Full production component "
    "inventory and declared-feature expiration governance need separate evidence."
)

_spec = importlib.util.spec_from_file_location(
    "saf_k8s_0104_022_evaluator", HERE / "evaluator.py")
evaluator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evaluator)


def prepare_kind(lab, temporary: Path) -> Path:
    """Generate kubeadm config that enables exactly the case gate on kube-apiserver."""
    config = temporary / "kind.yaml"
    config.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n"
        "- role: control-plane\n"
        "kubeadmConfigPatches:\n"
        "- |\n"
        "  apiVersion: kubeadm.k8s.io/v1beta4\n"
        "  kind: ClusterConfiguration\n"
        "  apiServer:\n"
        "    extraArgs:\n"
        "      - name: feature-gates\n"
        f"        value: {GATE}=true,{EXPLICIT_DEFAULT_GATE}=false\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    return config


def _metric_observation(metrics, gate):
    pattern = re.compile(
        r'^kubernetes_feature_enabled\{(?P<labels>[^}]*)\}\s+(?P<value>[01](?:\.0+)?)$')
    matches = []
    for line in metrics.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        labels = dict(re.findall(r'([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"', match["labels"]))
        if labels.get("name") == gate:
            matches.append({"component": COMPONENT, "feature": gate,
                            "enabled": float(match["value"]) == 1.0,
                            "stage": labels.get("stage")})
    if len(matches) != 1:
        raise ValueError(f"expected one API server metric for {gate}; found {len(matches)}")
    return matches[0]


def _component_arguments(pod):
    containers = pod.get("spec", {}).get("containers", [])
    component = next((item for item in containers if item.get("name") == COMPONENT), None)
    if component is None:
        raise ValueError("API server static pod has no kube-apiserver container")
    return component.get("command", []) + component.get("args", [])


def configured_flags(arguments):
    flags = [arg.partition("=")[2] for arg in arguments if arg.startswith("--feature-gates=")]
    return {setting for flag in flags for setting in flag.split(",")}


def observe(lab, gate=GATE):
    response = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--request-timeout=20s", "get", "--raw", "/metrics"],
        capture_output=True, text=True, env=lab.env, timeout=25,
    )
    if response.returncode:
        lab.block("The owned kube-apiserver metrics were unavailable")
    return _metric_observation(response.stdout, gate)


def observe_stock(lab):
    stock = Lab(lab.evidence, lab.context, lab.kubeconfig.parent / "stock-kubeconfig")
    if stock.cluster in stock.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Generated stock cluster name is already in use")
    try:
        stock.command("kind", "create", "cluster", "--name", stock.cluster, "--image", NODE_IMAGE,
                      "--kubeconfig", str(stock.kubeconfig), "--wait", "90s", timeout=480)
        data = observe(stock)
        default_gate = observe(stock, EXPLICIT_DEFAULT_GATE)
        pod_name = f"kube-apiserver-{stock.cluster}-control-plane"
        pod = json.loads(stock.kubectl("get", "pod", "-n", "kube-system", pod_name, "-o", "json").stdout)
        explicit = f"{EXPLICIT_DEFAULT_GATE}=false" in configured_flags(_component_arguments(pod))
        version = json.loads(stock.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    finally:
        stock.command("kind", "delete", "cluster", "--name", stock.cluster,
                      "--kubeconfig", str(stock.kubeconfig), timeout=90)
    deleted = stock.cluster not in stock.command("kind", "get", "clusters").stdout.splitlines()
    return data, version, deleted, default_gate, explicit


def peer_kubectl(lab, kubeconfig, cluster, *args, payload=None, timeout=45, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        "--namespace", PEER_NAMESPACE,
        f"--request-timeout={timeout - 5}s", *args, payload=payload, timeout=timeout,
        allow_failure=allow_failure,
    )


def peer_node_config(temporary):
    """Build one fresh loopback-only cluster with per-worker kubeadm Join patches."""
    cluster = f"saf-lab-ndf-{uuid.uuid4().hex[:8]}"
    config = temporary / "declared-features-kind.yaml"
    config.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        f"name: {cluster}\n"
        "networking:\n"
        "  apiServerAddress: 127.0.0.1\n"
        "nodes:\n"
        "- role: control-plane\n"
        "- role: worker\n"
        "  labels:\n"
        f"    {WORKER_LABEL}: disabled\n"
        "  kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: JoinConfiguration\n"
        "    nodeRegistration:\n"
        "      kubeletExtraArgs:\n"
        "      - name: feature-gates\n"
        f"        value: {DECLARED_FEATURE}=false\n"
        "- role: worker\n"
        "  labels:\n"
        f"    {WORKER_LABEL}: enabled\n"
        "  kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: JoinConfiguration\n"
        "    nodeRegistration:\n"
        "      kubeletExtraArgs:\n"
        "      - name: feature-gates\n"
        f"        value: {DECLARED_FEATURE}=true\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    return cluster, config


def assert_local_peer_endpoint(lab, kubeconfig, cluster):
    context = f"kind-{cluster}"
    server = peer_kubectl(
        lab, kubeconfig, cluster, "config", "view", "--minify", "-o",
        "jsonpath={.clusters[0].cluster.server}",
    ).stdout.strip()
    parsed = urllib.parse.urlsplit("")
    try:
        parsed = urllib.parse.urlsplit(server)
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except (ValueError, TypeError):
        loopback = False
    lab.check(
        "positive", "The peer kubeconfig uses its exact HTTPS host-loopback endpoint",
        parsed.scheme == "https" and loopback and bool(parsed.port)
        and context == f"kind-{cluster}",
        {"expected_context_selected": context == f"kind-{cluster}",
         "https": parsed.scheme == "https", "loopback": loopback,
         "port_present": bool(parsed.port)},
    )


def docker_peer_nodes(lab, cluster):
    """Enumerate only nodes carrying this case's exact Kind cluster label."""
    found = lab.command(
        "docker", "--context", lab.context, "ps", "-aq",
        "--filter", f"label=io.x-k8s.kind.cluster={cluster}",
    ).stdout.splitlines()
    inspected = []
    for container_id in found:
        fields = lab.command(
            "docker", "--context", lab.context, "inspect", "--format",
            '{{.Name}} {{index .Config.Labels "io.x-k8s.kind.cluster"}} '
            '{{index .Config.Labels "io.x-k8s.kind.role"}}', container_id,
        ).stdout.split()
        if len(fields) != 3:
            lab.block("Peer Docker node is missing expected Kind labels")
        name, cluster_label, role = fields
        inspected.append({"name": name.lstrip("/"), "cluster_label": cluster_label, "role": role})
    return inspected


def peer_nodes_ready(lab, kubeconfig, cluster, node_names):
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        response = json.loads(peer_kubectl(
            lab, kubeconfig, cluster, "get", "nodes", "-o", "json", timeout=30,
        ).stdout)
        by_name = {node["metadata"]["name"]: node for node in response.get("items", [])}
        if all(name in by_name and any(
            condition["type"] == "Ready" and condition["status"] == "True"
            for condition in by_name[name].get("status", {}).get("conditions", [])
        ) for name in node_names):
            workers = {
                node["metadata"]["labels"].get(WORKER_LABEL): node
                for node in by_name.values()
                if node["metadata"]["labels"].get(WORKER_LABEL) in ("enabled", "disabled")
            }
            features = {
                value: sorted(workers[value].get("status", {}).get("declaredFeatures", []))
                for value in ("disabled", "enabled") if value in workers
            }
            if (len(workers) == 2
                    and DECLARED_FEATURE not in features.get("disabled", [])
                    and DECLARED_FEATURE in features.get("enabled", [])):
                return workers, features
        time.sleep(2)
    lab.block("Peer workers did not become Ready with the expected kubelet feature reports")


def peer_cri_readiness(lab, docker_nodes):
    results = {}
    for node in docker_nodes:
        info = json.loads(lab.command(
            "docker", "--context", lab.context, "exec", node["name"],
            "crictl", "info", "-o", "json", timeout=30,
        ).stdout)
        conditions = info.get("status", {}).get("conditions", [])
        ready = any(condition.get("type") == "RuntimeReady"
                    and condition.get("status") is True for condition in conditions)
        results[node["name"]] = ready
    return results


def test_pod(name, selector, *, feature_required):
    container = {
        "name": "sleep",
        "image": SLEEP_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": ["sh", "-c", "sleep 3600"],
        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}},
    }
    if feature_required:
        container.update({
            "restartPolicy": "Never",
            "restartPolicyRules": [{
                "action": "RestartAllContainers",
                "exitCodes": {"operator": "In", "values": [42]},
            }],
        })
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": PEER_NAMESPACE},
        "spec": {
            "restartPolicy": "Never",
            "nodeSelector": {WORKER_LABEL: selector},
            "containers": [container],
        },
    }


def wait_pod_ready(lab, kubeconfig, cluster, name):
    peer_kubectl(lab, kubeconfig, cluster, "wait", "--for=condition=Ready",
                 f"pod/{name}", "--timeout=120s", timeout=130)
    return json.loads(peer_kubectl(
        lab, kubeconfig, cluster, "get", "pod", name, "-o", "json",
    ).stdout)


def pending_feature_event(lab, kubeconfig, cluster, name):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        pod = json.loads(peer_kubectl(
            lab, kubeconfig, cluster, "get", "pod", name, "-o", "json",
        ).stdout)
        events = json.loads(peer_kubectl(
            lab, kubeconfig, cluster, "get", "events",
            f"--field-selector=involvedObject.name={name}", "-o", "json",
        ).stdout).get("items", [])
        failures = [event for event in events if event.get("reason") == "FailedScheduling"]
        if pod.get("status", {}).get("phase") == "Pending" and not pod.get("spec", {}).get("nodeName") and failures:
            last = sorted(failures, key=lambda event: event.get("message", ""))[0]
            if PLUGIN_REASON in last.get("message", ""):
                return pod, last["message"]
        time.sleep(2)
    lab.block("Feature workload lacked the expected scheduler declared-feature filter event")


def kubelet_ready_snapshot(lab, kubeconfig, cluster, node_name):
    """Return only stable, non-identifying fields used to prove a kubelet refresh."""
    node = json.loads(peer_kubectl(
        lab, kubeconfig, cluster, "get", "node", node_name, "-o", "json",
    ).stdout)
    ready = next((condition for condition in node.get("status", {}).get("conditions", [])
                  if condition.get("type") == "Ready"), {})
    return {
        "resource_version": node.get("metadata", {}).get("resourceVersion", ""),
        "ready": ready.get("status") == "True",
        "ready_heartbeat": ready.get("lastHeartbeatTime", ""),
        "declares_feature": DECLARED_FEATURE in node.get("status", {}).get(
            "declaredFeatures", []),
    }


def disable_provisioned_worker_gate(lab, worker):
    """Change only the kubeadm-managed feature gate token in the exact worker node."""
    script = (
        "set -eu; f=/var/lib/kubelet/kubeadm-flags.env; "
        f"old='--feature-gates={DECLARED_FEATURE}=true'; "
        f"new='--feature-gates={DECLARED_FEATURE}=false'; "
        "test -f \"$f\"; "
        "test \"$(grep -oF -- \"$old\" \"$f\" | wc -l | tr -d ' ')\" = 1; "
        "sed -i \"s/${old}/${new}/\" \"$f\"; "
        "test \"$(grep -oF -- \"$old\" \"$f\" | wc -l | tr -d ' ')\" = 0; "
        "test \"$(grep -oF -- \"$new\" \"$f\" | wc -l | tr -d ' ')\" = 1; "
        "printf '%s\\n' '{\"old_gate_once\":true,\"new_gate_once\":true}'"
    )
    result = lab.command(
        "docker", "--context", lab.context, "exec", worker, "sh", "-ec", script,
        timeout=30,
    )
    return json.loads(result.stdout) == {"old_gate_once": True, "new_gate_once": True}


def run_kubelet_refresh_followup(lab, kubeconfig, cluster, docker_nodes,
                                  worker_names, reporting_worker, ordinary_probe, feature_on):
    """Run saf-lab-0104-022.2 on the same disposable peer after the paired probes."""
    # Remove the only running feature-dependent probe before changing its worker.
    peer_kubectl(lab, kubeconfig, cluster, "delete", "pod", feature_on["metadata"]["name"],
                 "--wait=true", "--timeout=60s", timeout=70)
    remaining_probes = []
    for probe in (ordinary_probe, feature_on):
        result = peer_kubectl(
            lab, kubeconfig, cluster, "get", "pod", probe["metadata"]["name"],
            "-o", "json", allow_failure=True,
        )
        if result.returncode == 0:
            remaining_probes.append(probe["metadata"]["name"])
    lab.check(
        "positive", "Original synthetic probes are removed before the gate change",
        not remaining_probes,
        {"original_probes_absent": not remaining_probes},
    )

    worker_name = reporting_worker["metadata"]["name"]
    exact_worker = f"{cluster}-worker2"
    node_entries = {item["name"]: item for item in docker_nodes}
    worker_entry = node_entries.get(exact_worker, {})
    exact_owned_worker = (
        worker_name == exact_worker
        and exact_worker in worker_names
        and worker_entry.get("cluster_label") == cluster
        and worker_entry.get("role") == "worker"
    )
    lab.check(
        "positive", "The published worker maps to its exact cluster-labeled Kind node",
        exact_owned_worker,
        {"one_exact_worker_selected": exact_owned_worker,
         "exact_label_and_role_match": exact_owned_worker},
    )
    if not exact_owned_worker:
        lab.block("Published worker did not map to the exact owned Kind worker")

    before = kubelet_ready_snapshot(lab, kubeconfig, cluster, worker_name)
    lab.check(
        "positive", "Pre-change snapshot is Ready and reports the enabled feature",
        before["ready"] and before["declares_feature"] and bool(before["resource_version"])
        and bool(before["ready_heartbeat"]),
        {"ready": before["ready"], "feature_reported": before["declares_feature"],
         "version_present": bool(before["resource_version"]),
         "heartbeat_present": bool(before["ready_heartbeat"])},
    )

    changed = disable_provisioned_worker_gate(lab, exact_worker)
    lab.check(
        "positive", "Only the kubeadm-managed worker gate value changes true to false",
        changed,
        {"single_old_gate_replaced": changed, "single_new_gate_present": changed},
    )
    worker_command = ("docker", "--context", lab.context, "exec", exact_worker, "systemctl")
    process_query = (*worker_command, "show", "kubelet", "--property=MainPID", "--value")
    old_pid = int(lab.command(*process_query, timeout=15).stdout.strip())
    lab.command(*worker_command, "restart", "kubelet", timeout=45)
    new_pid = int(lab.command(*process_query, timeout=15).stdout.strip())
    restarted = old_pid > 0 and new_pid > 0 and old_pid != new_pid
    lab.check("positive", "The exact owned worker started a new kubelet process",
              restarted, {"old_and_new_pid_present_and_distinct": restarted})

    deadline = time.monotonic() + 150
    after = None
    while time.monotonic() < deadline:
        snapshot = kubelet_ready_snapshot(lab, kubeconfig, cluster, worker_name)
        if (snapshot["ready"] and not snapshot["declares_feature"]
                and snapshot["resource_version"] != before["resource_version"]
                and snapshot["ready_heartbeat"] > before["ready_heartbeat"]):
            after = snapshot
            break
        time.sleep(2)
    refreshed = after is not None
    lab.check(
        "green", "Restarted kubelet refreshes Node status and removes its declaration",
        refreshed,
        {"ready": bool(after and after["ready"]),
         "feature_removed": bool(after and not after["declares_feature"]),
         "resource_version_advanced": bool(after and after["resource_version"]
                                            != before["resource_version"]),
         "ready_heartbeat_advanced": bool(after and after["ready_heartbeat"]
                                          > before["ready_heartbeat"])},
    )
    if not refreshed:
        lab.block("Restarted worker did not publish a fresh Ready Node status without the feature")

    ordinary = test_pod("ordinary-after-refresh", "enabled", feature_required=False)
    peer_kubectl(lab, kubeconfig, cluster, "create", "-f", "-",
                 payload=json.dumps(ordinary))
    ordinary_observed = wait_pod_ready(lab, kubeconfig, cluster, ordinary["metadata"]["name"])
    ordinary_node = ordinary_observed.get("spec", {}).get("nodeName")
    ordinary_ok = (
        ordinary_observed.get("status", {}).get("phase") == "Running"
        and ordinary_node == worker_name
    )
    lab.check(
        "positive", "An ordinary supported Pod remains viable on the refreshed worker",
        ordinary_ok,
        {"running_on_refreshed_worker": ordinary_ok,
         "phase_is_running": ordinary_observed.get("status", {}).get("phase") == "Running"},
    )

    feature = test_pod("feature-after-refresh", "enabled", feature_required=True)
    peer_kubectl(lab, kubeconfig, cluster, "create", "-f", "-",
                 payload=json.dumps(feature))
    pending, message = pending_feature_event(lab, kubeconfig, cluster,
                                              feature["metadata"]["name"])
    blocked = (
        pending.get("status", {}).get("phase") == "Pending"
        and not pending.get("spec", {}).get("nodeName")
        and PLUGIN_REASON in message
    )
    lab.check(
        "red", "A new matching feature Pod stays Pending for the exact scheduler reason",
        blocked,
        {"pending_without_node": blocked,
         "exact_scheduler_reason_present": PLUGIN_REASON in message,
         "reason_value": PLUGIN_REASON},
    )


def run_declared_feature_peer(lab):
    """Observe v1.37 kubelet publication and default-scheduler filtering on a fresh peer."""
    env_docker_endpoint = lab.command(
        "docker", "--context", lab.context, "context", "inspect", lab.context,
        "--format", "{{.Endpoints.docker.Host}}",
    ).stdout.strip()
    if not env_docker_endpoint.startswith("unix://"):
        lab.block("The peer must use the selected local Docker Unix-socket context")

    with tempfile.TemporaryDirectory(prefix="saf-0104-022-peer-") as directory:
        temporary = Path(directory)
        cluster, config = peer_node_config(temporary)
        kubeconfig = temporary / "peer-kubeconfig"
        before = lab.command("kind", "get", "clusters").stdout.splitlines()
        if cluster in before:
            lab.block("Generated declared-feature peer name already exists")
        owned = False
        try:
            owned = True
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", PEER_NODE_IMAGE,
                "--config", str(config), "--kubeconfig", str(kubeconfig), "--wait", "120s",
                timeout=600,
            )
            docker_nodes = docker_peer_nodes(lab, cluster)
            expected_node_names = [f"{cluster}-control-plane", f"{cluster}-worker",
                                   f"{cluster}-worker2"]
            exact_owned_nodes = (
                len(docker_nodes) == 3
                and sorted(node["name"] for node in docker_nodes) == sorted(expected_node_names)
                and all(node["cluster_label"] == cluster for node in docker_nodes)
            )
            lab.check(
                "positive", "Fresh peer is named and its Docker nodes are exact-label scoped",
                exact_owned_nodes,
                {"expected_node_count": len(docker_nodes),
                 "expected_node_names_present": exact_owned_nodes,
                 "all_nodes_carry_exact_cluster_label": all(
                     node["cluster_label"] == cluster for node in docker_nodes)},
            )
            if not exact_owned_nodes:
                lab.block("Peer Docker node ownership did not match the exact generated cluster")

            assert_local_peer_endpoint(lab, kubeconfig, cluster)
            server = json.loads(peer_kubectl(
                lab, kubeconfig, cluster, "version", "-o", "json",
            ).stdout)["serverVersion"]["gitVersion"]
            lab.check(
                "positive", "Peer API server matches the digest-pinned Kubernetes v1.37.0 node image",
                server == "v1.37.0" and PEER_NODE_IMAGE.endswith(
                    "a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"),
                {"server_version": server, "node_image": PEER_NODE_IMAGE},
            )
            cri = peer_cri_readiness(lab, docker_nodes)
            lab.check("positive", "CRI RuntimeReady is true on every owned peer node",
                      len(cri) == 3 and all(cri.values()),
                      {"runtime_ready_count": sum(cri.values()), "node_count": len(cri)})

            workers, features = peer_nodes_ready(
                lab, kubeconfig, cluster, expected_node_names,
            )
            report = {
                value: {
                    "node": workers[value]["metadata"]["name"],
                    "ready": any(condition["type"] == "Ready" and condition["status"] == "True"
                                 for condition in workers[value]["status"].get("conditions", [])),
                    "kubelet_version": workers[value]["status"]["nodeInfo"]["kubeletVersion"],
                    "declared_features": features[value],
                    "feature_reported": DECLARED_FEATURE in features[value],
                }
                for value in ("disabled", "enabled")
            }
            correct_reports = (
                all(item["ready"] and item["kubelet_version"] == "v1.37.0"
                    for item in report.values())
                and not report["disabled"]["feature_reported"]
                and report["enabled"]["feature_reported"]
            )
            lab.check(
                "green", "Ready v1.37 kubelets publish the configured per-worker feature state",
                correct_reports,
                {name: {key: item[key] for key in ("ready", "kubelet_version", "feature_reported")}
                 for name, item in report.items()},
            )
            classifications = {}
            for label, state in report.items():
                # The peer nodes were verified against this fixture's exact Docker labels.
                gate_tokens = lab.command(
                    "docker", "--context", lab.context, "exec", state["node"],
                    "grep", "-oE", f"{DECLARED_FEATURE}=(true|false)",
                    "/var/lib/kubelet/kubeadm-flags.env",
                ).stdout.splitlines()
                configured = len(gate_tokens) == 1 and gate_tokens[0].endswith(
                    "=true" if state["feature_reported"] else "=false")
                classification = ("explicit-equal-default" if state["feature_reported"]
                                  else "explicit-non-default") if configured else "unknown"
                classifications[label] = {"effective": state["feature_reported"],
                                          "documented_default": True,
                                          "flag_corroborates": configured,
                                          "classification": classification}
            peer_inventory = {
                "disabled": {"effective": False, "documented_default": True, "flag_corroborates": True,
                             "classification": "explicit-non-default"},
                "enabled": {"effective": True, "documented_default": True, "flag_corroborates": True,
                            "classification": "explicit-equal-default"},
            }
            lab.check("green", "The peer inventory preserves explicit equal-default and overridden kubelet settings",
                      classifications == peer_inventory, classifications)
            (lab.evidence / "worker-feature-inventory.raw.json").write_text(
                json.dumps(classifications, indent=2, sort_keys=True) + "\n")
            peer_kubectl(lab, kubeconfig, cluster, "create", "namespace", PEER_NAMESPACE)

            ordinary = test_pod("ordinary-on-disabled", "disabled", feature_required=False)
            peer_kubectl(lab, kubeconfig, cluster, "create", "-f", "-",
                         payload=json.dumps(ordinary))
            ordinary_observed = wait_pod_ready(
                lab, kubeconfig, cluster, ordinary["metadata"]["name"],
            )
            ordinary_node = ordinary_observed.get("spec", {}).get("nodeName")
            lab.check(
                "positive", "Ordinary matching control workload runs on the explicitly disabled worker",
                ordinary_observed.get("status", {}).get("phase") == "Running"
                and ordinary_node == report["disabled"]["node"],
                {"phase": ordinary_observed.get("status", {}).get("phase"),
                 "on_expected_disabled_worker": ordinary_node == report["disabled"]["node"],
                 "image": SLEEP_IMAGE},
            )
            peer_kubectl(lab, kubeconfig, cluster, "delete", "pod", ordinary["metadata"]["name"],
                         "--wait=true", "--timeout=60s", timeout=70)

            feature_off = test_pod("feature-on-disabled", "disabled", feature_required=True)
            peer_kubectl(lab, kubeconfig, cluster, "create", "-f", "-",
                         payload=json.dumps(feature_off))
            off_observed, event_message = pending_feature_event(
                lab, kubeconfig, cluster, feature_off["metadata"]["name"],
            )
            lab.check(
                "red", "Identical declared-feature workload stays Pending on the off worker for the exact plugin reason",
                off_observed.get("status", {}).get("phase") == "Pending"
                and not off_observed.get("spec", {}).get("nodeName")
                and PLUGIN_REASON in event_message,
                {"phase": off_observed.get("status", {}).get("phase"),
                 "node_assigned": bool(off_observed.get("spec", {}).get("nodeName")),
                 "scheduler_plugin_reason": PLUGIN_REASON,
                 "exact_reason_present": PLUGIN_REASON in event_message},
            )

            feature_on = test_pod("feature-on-enabled", "enabled", feature_required=True)
            same_feature_spec = (
                {key: value for key, value in feature_off["spec"].items() if key != "nodeSelector"}
                == {key: value for key, value in feature_on["spec"].items() if key != "nodeSelector"}
            )
            peer_kubectl(lab, kubeconfig, cluster, "create", "-f", "-",
                         payload=json.dumps(feature_on))
            on_observed = wait_pod_ready(lab, kubeconfig, cluster, feature_on["metadata"]["name"])
            on_node = on_observed.get("spec", {}).get("nodeName")
            lab.check(
                "green", "The same declared-feature workload binds Ready to the reporting worker",
                same_feature_spec and on_observed.get("status", {}).get("phase") == "Running"
                and on_node == report["enabled"]["node"],
                {"same_feature_spec_except_node_selector": same_feature_spec,
                 "phase": on_observed.get("status", {}).get("phase"),
                 "on_expected_reporting_worker": on_node == report["enabled"]["node"],
                 "image": SLEEP_IMAGE,
                 "exit_42_policy_configured_but_not_exercised": True},
            )

            run_kubelet_refresh_followup(
                lab, kubeconfig, cluster, docker_nodes, expected_node_names,
                workers["enabled"], ordinary, feature_on,
            )
        finally:
            if owned:
                # Delete exactly the named peer; do not infer ownership from context alone.
                deleted = False
                delete_succeeded = False
                for _attempt in range(3):
                    deletion = lab.command(
                        "kind", "delete", "cluster", "--name", cluster,
                        "--kubeconfig", str(kubeconfig), timeout=120, allow_failure=True,
                    )
                    delete_succeeded = delete_succeeded or deletion.returncode == 0
                    remaining = docker_peer_nodes(lab, cluster)
                    after = lab.command("kind", "get", "clusters").stdout.splitlines()
                    deleted = cluster not in after and not remaining
                    if deleted:
                        break
                lab.check(
                    "positive", "The owned declared-feature peer cluster was deleted",
                    deleted,
                    {"owned_peer_absent_from_kind": cluster not in after,
                     "exact_label_scoped_containers_remaining": len(remaining),
                     "delete_command_succeeded": delete_succeeded},
                )


def run(lab):
    baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
    expected = json.loads((HERE / "expected-effective.json").read_text(encoding="utf-8"))

    stock, stock_version, stock_deleted, stock_default_gate, stock_was_explicit = observe_stock(lab)
    default_inventory = evaluator.evaluate(baseline, [stock])
    lab.check("red", "The stock API server reports the versioned default and no override",
              stock["enabled"] == baseline["default"] and default_inventory == []
              and stock_version == f"v{baseline['kubernetes_version']}" and stock_deleted,
              {"stock_metric": stock, "classified_inventory": default_inventory,
               "stock_version": stock_version, "stock_cleanup": stock_deleted})

    pod_name = f"kube-apiserver-{lab.cluster}-control-plane"
    pod = json.loads(lab.kubectl("get", "pod", "-n", "kube-system", pod_name,
                                  "-o", "json").stdout)
    args = _component_arguments(pod)
    explicit_flags = configured_flags(args)
    configured = f"{GATE}=true" in explicit_flags
    effective = observe(lab)
    inventory = evaluator.evaluate(baseline, [effective])
    expected_inventory = expected["expected_inventory"]
    lab.check("green", "Effective read-only API server state is statically classified",
              inventory == expected_inventory and effective["enabled"],
              {"effective_metric": effective, "classified_inventory": inventory,
               "expected_inventory": expected_inventory})
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    lab.check("positive", "Generated configuration and effective metric agree",
              configured and effective["enabled"] is True and version == stock_version,
              {"api_server_feature_gate_argument_present": configured,
               "effective_metric_enabled": effective["enabled"],
               "metric_source": "kube-apiserver /metrics via read-only Kubernetes API GET"})
    explicit_default = observe(lab, EXPLICIT_DEFAULT_GATE)
    selected = {
        "gate": EXPLICIT_DEFAULT_GATE, "stock_effective": stock_default_gate["enabled"],
        "stock_explicit": stock_was_explicit, "configured_effective": explicit_default["enabled"],
        "configured_explicit": f"{EXPLICIT_DEFAULT_GATE}=false" in explicit_flags,
        "observed_alpha_stage": explicit_default["stage"] == stock_default_gate["stage"] == "ALPHA",
    }
    lab.check("positive", "An explicit API server setting equal to the default remains visible",
              not selected["stock_effective"] and not selected["stock_explicit"]
              and not selected["configured_effective"] and selected["configured_explicit"]
              and selected["observed_alpha_stage"], selected)
    run_declared_feature_peer(lab)
