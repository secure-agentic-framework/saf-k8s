"""Exercise a pinned Cilium Helm release and a reversible failed upgrade.

The harness owns the fresh Kind cluster. This case owns only its Helm release,
the marker namespace workloads, and bounded in-cluster HTTP requests.
"""
import hashlib
import json
from pathlib import Path
import time


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
KIND_VERSION = "kind v0.32.0"
KUBERNETES_VERSION = "v1.36.1"
CILIUM_VERSION = "1.20.5"
CHART_SOURCE = "oci://quay.io/cilium/charts/cilium"
CHART_SHA256 = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
AGENT_IMAGE = (
    "quay.io/cilium/cilium:v1.20.5@sha256:"
    "aa72499f075ad729947ea91b026218aceba24f1a8e4534bf36b8368c7c561526"
)
OPERATOR_IMAGE = (
    "quay.io/cilium/operator-generic:v1.20.5@sha256:"
    "c6e7de6665aa9701db86c4fe46828a75a0d167afe084a9ffb5bce34b2c4fa8c4"
)
PREVIOUS_CILIUM_VERSION = "1.20.4"
PREVIOUS_CHART_SHA256 = "505abff8385811df1a949776fc42e9f10697989a332acc86d6e8933efcb855ed"
PREVIOUS_AGENT_IMAGE = (
    "quay.io/cilium/cilium:v1.20.4@sha256:"
    "20fe92e4c86641233a450098c158d2d29085f3419931ab6bf681d2485dedf16e"
)
PREVIOUS_OPERATOR_IMAGE = (
    "quay.io/cilium/operator-generic:v1.20.4@sha256:"
    "7a7a3489dc66ad67e420d285c8a8d2e169b0957ad15e120f593d27081bf38d82"
)
RELEASE = "cilium"
NAMESPACE = "saf-test"
SERVER = "marker-server"
CLIENT = "marker-client"
SERVICE = "marker"
PORT = 18080
MARKER = "saf-0502-004-baseline-marker"
CNP_NAME = "saf-0502-004-approved-marker-flow"
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
COMPONENT_FAILURE_REASONS = {
    "ContainerCannotRun", "CreateContainerError", "CrashLoopBackOff", "Error",
    "RunContainerError", "StartError",
}
INSTALLS_CNI = True
SCOPE = (
    "One fresh harness-owned Kind v0.32.0 / Kubernetes v1.36.1 cluster, with "
    "Kind's default CNI disabled. The case installs Cilium 1.20.4 and upgrades "
    "to 1.20.5 from checked OCI chart archives. Both pre- and post-upgrade "
    "agent/operator Pods are Ready on the expected pins. The same owned policy "
    "and server Pod UIDs are observed with the policy realized on both versions. "
    "One TCP marker request follows the approved path between two case-owned "
    "pods in the cluster. A deliberately invalid readiness-probe threshold is "
    "submitted through Helm with and without --atomic. The case requires API "
    "rejection for both attempts, a deployed rollback revision for the atomic trial, restored user "
    "values, and the same marker request afterward. An additive lifecycle branch "
    "rolls Cilium agents after a valid monitor-aggregation setting change, then "
    "observes a failed operator workload image rollout and explicit Helm rollback "
    "while keeping the agent datapath pinned. A case-owned namespaced "
    "CiliumNetworkPolicy permits only ordinary marker-client ingress to the "
    "marker-server TCP port, remains realized through the tested Helm lifecycle, "
    "and is removed afterward. A schema-valid, case-local option is rejected by "
    "the pinned agent, then explicit rollback restores the Ready, pinned agent "
    "and re-verifies the same realized policy and marker. Scope excludes "
    "production baseline, CVE status "
    "or patch timeliness, provider SLAs, RBAC "
    "process, PSA configuration, or production-scale availability."
)


def prepare_kind(_lab, temporary):
    profile = temporary / "kind.yaml"
    profile.write_bytes(Path(__file__).with_name("kind-profile.yaml").read_bytes())
    return profile


def _kubectl(lab, *args, timeout=60, allow_failure=False, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args,
        payload=payload, timeout=timeout, allow_failure=allow_failure,
    )


def _helm(lab, *args, timeout=90, allow_failure=False):
    return lab.command(
        "helm", *args, "--kubeconfig", str(lab.kubeconfig),
        "--kube-context", f"kind-{lab.cluster}", timeout=timeout,
        allow_failure=allow_failure,
    )


def _json(result):
    return json.loads(result.stdout)


def _create(lab, resource):
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(resource))


def _container(name, command):
    return {
        "name": name,
        "image": "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec",
        "command": command,
        "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                      "limits": {"cpu": "75m", "memory": "24Mi"}},
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def _pod(name, command, labels):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": labels},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "containers": [_container(name, command)],
        },
    }


def _prepare_workloads(lab):
    _create(lab, _pod(
        SERVER,
        ["sh", "-ec", f"mkdir -p /tmp/www; printf %s {MARKER} >/tmp/www/index.html; exec httpd -f -p {PORT} -h /tmp/www"],
        {"app": SERVER},
    ))
    _create(lab, _pod(CLIENT, ["sh", "-ec", "exec sleep 1800"], {"app": CLIENT}))
    _create(lab, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": NAMESPACE},
        "spec": {"selector": {"app": SERVER},
                 "ports": [{"name": "http", "port": PORT, "targetPort": PORT}]},
    })
    for name in (SERVER, CLIENT):
        _kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready",
                 f"pod/{name}", "--timeout=90s", timeout=100)


def _approved_marker_policy():
    """A single ordinary client-to-server TCP flow, restricted to this fixture."""
    return {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {"name": CNP_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-lab.example/control": "SAF-K8S-0502-004",
                                "saf-lab.example/fixture": "synthetic"}},
        "spec": {
            "description": "Allow only the case-owned marker client to its marker server TCP port.",
            "endpointSelector": {"matchLabels": {"app": SERVER}},
            "ingress": [{
                "fromEndpoints": [{"matchLabels": {"app": CLIENT}}],
                "toPorts": [{"ports": [{"port": str(PORT), "protocol": "TCP"}]}],
            }],
        },
    }


def _endpoint_observation(lab):
    endpoint = _json(_kubectl(lab, "-n", NAMESPACE, "get", "ciliumendpoint", SERVER, "-o", "json"))
    status = endpoint.get("status", {})
    return {"endpoint_name": endpoint.get("metadata", {}).get("name"),
            "endpoint_identity": status.get("identity", {}).get("id"),
            "endpoint_state": status.get("state"),
            "policy_status_present": "policy" in status}


def _wait_endpoint_ready(lab, timeout=45):
    deadline = time.monotonic() + timeout
    latest = {}
    while time.monotonic() < deadline:
        latest = _endpoint_observation(lab)
        if latest.get("endpoint_name") == SERVER and latest.get("endpoint_identity", 0) > 1 \
                and latest.get("endpoint_state") == "ready":
            return latest
        time.sleep(0.5)
    lab.block("The exact marker server CiliumEndpoint did not report ready with an assigned identity")


def _effective_agent_policy_state(lab, expected_agent_image=AGENT_IMAGE):
    """Read only this owned endpoint from its pinned local Cilium agent."""
    pod = _json(_kubectl(lab, "-n", NAMESPACE, "get", "pod", SERVER, "-o", "json"))
    endpoint = _json(_kubectl(lab, "-n", NAMESPACE, "get", "ciliumendpoint", SERVER, "-o", "json"))
    pod_uid = pod.get("metadata", {}).get("uid")
    owner_refs = endpoint.get("metadata", {}).get("ownerReferences", [])
    if not pod_uid or not any(ref.get("kind") == "Pod" and ref.get("uid") == pod_uid
                              for ref in owner_refs):
        lab.block("The marker-server CiliumEndpoint is not owned by the exact marker-server Pod")

    endpoint_id = endpoint.get("status", {}).get("id")
    if not isinstance(endpoint_id, int) or endpoint_id < 1:
        lab.block("The owned marker-server CiliumEndpoint has no valid local Cilium endpoint ID")
    node_name = pod.get("spec", {}).get("nodeName")
    agents = _json(_kubectl(lab, "-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium", "-o", "json"))
    local_agents = []
    for candidate in agents.get("items", []):
        if candidate.get("spec", {}).get("nodeName") != node_name:
            continue
        containers = candidate.get("spec", {}).get("containers", [])
        agent_images = [c.get("image") for c in containers if c.get("name") == "cilium-agent"]
        conditions = candidate.get("status", {}).get("conditions", [])
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
        if agent_images == [expected_agent_image] and ready:
            local_agents.append(candidate)
    if len(local_agents) != 1:
        lab.block("Could not identify exactly one ready, digest-pinned Cilium agent on the marker-server node")

    agent_name = local_agents[0].get("metadata", {}).get("name")
    raw = _kubectl(lab, "-n", "kube-system", "exec", f"pod/{agent_name}", "-c", "cilium-agent",
                   "--", "cilium-dbg", "endpoint", "get", str(endpoint_id), "-o", "json")
    models = json.loads(raw.stdout)
    if not isinstance(models, list) or len(models) != 1 or not isinstance(models[0], dict):
        lab.block("cilium-dbg endpoint get did not return exactly one endpoint model")
    model = models[0]
    status = model.get("status", {})
    external = status.get("external-identifiers", {})
    policy = status.get("policy", {})
    realized = policy.get("realized", {})
    ingress = realized.get("l4", {}).get("ingress", [])
    owned_cnp = _json(_kubectl(lab, "-n", NAMESPACE, "get", "ciliumnetworkpolicy", CNP_NAME, "-o", "json"))
    owned_cnp_uid = owned_cnp.get("metadata", {}).get("uid")
    if not owned_cnp_uid:
        lab.block("The case-owned Cilium policy has no API UID")
    expected_labels = {
        "k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
        f"k8s:io.cilium.k8s.policy.name={CNP_NAME}",
        f"k8s:io.cilium.k8s.policy.namespace={NAMESPACE}",
        f"k8s:io.cilium.k8s.policy.uid={owned_cnp_uid}",
    }
    owned_ingress_rule_count = 0
    for rule in ingress if isinstance(ingress, list) else []:
        for source_labels in rule.get("derived-from-rules", []):
            if expected_labels.issubset(set(source_labels)):
                specification = json.loads(rule["rule"])
                if specification.get("port") == PORT and specification.get("protocol") == "TCP":
                    owned_ingress_rule_count += 1
                    break
    observed = {
        "agent_pod": agent_name,
        "agent_image_pinned": True,
        "endpoint_id": model.get("id"),
        "endpoint_id_matches_ciliumendpoint": model.get("id") == endpoint_id,
        "ciliumendpoint_pod_uid_binding_observed": True,
        "captured_pod_uid": pod_uid,
        "captured_policy_uid": owned_cnp_uid,
        "endpoint_attachment_matches": bool(external.get("cni-attachment-id")) and
            external.get("cni-attachment-id") == endpoint["status"].get("external-identifiers", {}).get("cni-attachment-id"),
        "endpoint_pod_address_matches": bool(pod.get("status", {}).get("podIP")) and
            any(pod["status"]["podIP"] in (address.get("ipv4"), address.get("ipv6"))
                for address in status.get("networking", {}).get("addressing", [])),
        "policy_enabled": realized.get("policy-enabled"),
        "realized_ingress_rule_count": len(ingress) if isinstance(ingress, list) else 0,
        "owned_policy_ingress_rule_count": owned_ingress_rule_count,
    }
    if not (observed["endpoint_id_matches_ciliumendpoint"]
            and observed["endpoint_attachment_matches"]
            and observed["endpoint_pod_address_matches"]
            and observed["policy_enabled"] in {"ingress", "both"}
            and observed["owned_policy_ingress_rule_count"] > 0):
        lab.block("Pinned local Cilium agent did not report the owned CNP in the endpoint's realized ingress policy")
    return observed


def marker_observation(returncode, stdout, marker=MARKER):
    """Pure evaluator shared by the executable case and deterministic checks."""
    return returncode == 0 and stdout.strip() == marker


def rollback_observation(upgrade_returncode, history, current_values, baseline_values):
    """Require Helm failure, a failed revision, a later deployed rollback, and values."""
    rows = sorted(history, key=lambda row: int(row["revision"]))
    failed_revisions = [int(row["revision"]) for row in rows if row["status"] == "failed"]
    deployed_revisions = [int(row["revision"]) for row in rows if row["status"] == "deployed"]
    rollback_follows_failure = bool(failed_revisions and deployed_revisions
                                    and max(deployed_revisions) > max(failed_revisions))
    return (upgrade_returncode != 0 and rollback_follows_failure
            and current_values == baseline_values)


def _marker_request(lab):
    result = _kubectl(
        lab, "-n", NAMESPACE, "exec", f"pod/{CLIENT}", "--", "wget", "-q",
        "-T", "3", "-O", "-", f"http://{SERVICE}:{PORT}/", timeout=15,
        allow_failure=True,
    )
    return marker_observation(result.returncode, result.stdout), {
        "returncode": result.returncode,
        "marker_received": result.stdout.strip() == MARKER,
    }


def _wait_for_marker(lab):
    deadline = time.monotonic() + 30
    while True:
        reachable, result = _marker_request(lab)
        if reachable or time.monotonic() >= deadline:
            return reachable, result
        time.sleep(1)


def _assert_images(lab):
    ds = _json(_kubectl(lab, "-n", "kube-system", "get", "daemonset/cilium", "-o", "json"))
    agent_images = [c["image"] for c in ds["spec"]["template"]["spec"]["containers"]
                    if c["name"] == "cilium-agent"]
    operator = _json(_kubectl(lab, "-n", "kube-system", "get", "deployment/cilium-operator", "-o", "json"))
    operator_images = [c["image"] for c in operator["spec"]["template"]["spec"]["containers"]]
    return agent_images == [AGENT_IMAGE] and OPERATOR_IMAGE in operator_images, {
        "agent_images": agent_images,
        "operator_images": operator_images,
    }


def _agent_rollout_state(lab):
    ds = _json(_kubectl(lab, "-n", "kube-system", "get", "daemonset/cilium", "-o", "json"))
    images = [c["image"] for c in ds["spec"]["template"]["spec"]["containers"]
              if c["name"] == "cilium-agent"]
    status = ds.get("status", {})
    desired = status.get("desiredNumberScheduled", 0)
    ready = (desired > 0
             and status.get("updatedNumberScheduled", 0) == desired
             and status.get("numberReady", 0) == desired
             and status.get("numberAvailable", 0) == desired)
    annotations = ds["spec"]["template"].get("metadata", {}).get("annotations", {})
    config = _json(_kubectl(
        lab, "-n", "kube-system", "get", "configmap/cilium-config", "-o", "json"))
    return {
        "images_pinned": images == [AGENT_IMAGE],
        "agent_images": images,
        "desired_agents": desired,
        "all_desired_agents_updated_and_ready": ready,
        "rollout_checksum_present": bool(annotations.get("cilium.io/cilium-configmap-checksum")),
        "monitor_aggregation_low": config.get("data", {}).get("monitor-aggregation") == "low",
    }


def _operator_rollout_state(lab):
    deployment = _json(_kubectl(
        lab, "-n", "kube-system", "get", "deployment/cilium-operator", "-o", "json"))
    status = deployment.get("status", {})
    desired = deployment.get("spec", {}).get("replicas", 0)
    strategy = deployment.get("spec", {}).get("strategy", {})
    rolling = strategy.get("rollingUpdate", {})
    images = [c["image"] for c in deployment["spec"]["template"]["spec"]["containers"]
              if c["name"] == "cilium-operator"]
    pods = _json(_kubectl(
        lab, "-n", "kube-system", "get", "pods",
        "-l", "io.cilium/app=operator,name=cilium-operator", "-o", "json"))
    candidate_pods = []
    for pod in pods.get("items", []):
        for container in pod.get("status", {}).get("containerStatuses", []):
            if container.get("name") != "cilium-operator":
                continue
            waiting = container.get("state", {}).get("waiting", {})
            terminated = container.get("state", {}).get("terminated", {})
            last_termination = container.get("lastState", {}).get("terminated", {})
            reasons = {waiting.get("reason"), terminated.get("reason"), last_termination.get("reason")}
            image_digest = BUSYBOX_IMAGE.split("@", 1)[1]
            candidate_pods.append({
                "candidate_image": container.get("imageID", "").endswith("@" + image_digest),
                "not_ready": not container.get("ready", False),
                "recognized_start_failure": bool(reasons & COMPONENT_FAILURE_REASONS),
                "restart_seen": container.get("restartCount", 0) > 0,
            })
    updated = status.get("updatedReplicas", 0)
    not_ready = status.get("readyReplicas", 0) == 0 and status.get("availableReplicas", 0) == 0
    return {
        "candidate_template_image": images == [BUSYBOX_IMAGE],
        "candidate_pod_observed": any(
            pod["candidate_image"] and pod["not_ready"]
            and (pod["recognized_start_failure"] or pod["restart_seen"])
            for pod in candidate_pods),
        "updated_replica_attempted": desired > 0 and updated == desired,
        "updated_replicas_available": status.get("availableReplicas", 0),
        "updated_replicas_ready": status.get("readyReplicas", 0),
        "failed_rollout_shape": not_ready,
        "no_surge_rollout_strategy": (
            strategy.get("type") == "RollingUpdate"
            and rolling.get("maxSurge") == 0
            and rolling.get("maxUnavailable") in {"100%", 100}),
    }


def _operator_restored(lab):
    deployment = _json(_kubectl(
        lab, "-n", "kube-system", "get", "deployment/cilium-operator", "-o", "json"))
    status = deployment.get("status", {})
    desired = deployment.get("spec", {}).get("replicas", 0)
    images = [c["image"] for c in deployment["spec"]["template"]["spec"]["containers"]
              if c["name"] == "cilium-operator"]
    return {
        "pinned_operator_image_restored": OPERATOR_IMAGE in images,
        "operator_ready": desired > 0 and status.get("readyReplicas", 0) == desired
        and status.get("availableReplicas", 0) == desired,
        "operator_images": images,
        "desired_replicas": desired,
    }


def _config_hash(lab):
    ds = _json(_kubectl(lab, "-n", "kube-system", "get", "daemonset/cilium", "-o", "json"))
    return ds["spec"]["template"].get("metadata", {}).get("annotations", {}).get(
        "cilium.io/cilium-configmap-checksum")


def _lifecycle_upgrade(lab, chart):
    return _helm(
        lab, "upgrade", RELEASE, str(chart), "--namespace", "kube-system",
        "--reuse-values", "--set", "bpf.monitorAggregation=low",
        "--set", "rollOutCiliumPods=true", "--wait",
        "--timeout", "150s", timeout=170, allow_failure=True,
    )


def _stage_operator_comparison(lab, chart):
    return _helm(
        lab, "upgrade", RELEASE, str(chart), "--namespace", "kube-system",
        "--reuse-values", "--set-string", f"operator.image.override={BUSYBOX_IMAGE}",
        "--set-string", "operator.image.pullPolicy=IfNotPresent",
        "--set", "operator.updateStrategy.rollingUpdate.maxSurge=0",
        timeout=55, allow_failure=True,
    )


def _run_rollout_recovery(lab, chart):
    baseline_history, _ = _revision_and_values(lab)
    before_revision = max(int(row["revision"]) for row in baseline_history)
    before_hash = _config_hash(lab)

    lifecycle = _lifecycle_upgrade(lab, chart)
    agent_rollout = _kubectl(
        lab, "-n", "kube-system", "rollout", "status", "daemonset/cilium",
        "--timeout=120s", timeout=130, allow_failure=True)
    lifecycle_history, lifecycle_values = _revision_and_values(lab)
    lifecycle_statuses = _new_revision_statuses(lifecycle_history, before_revision)
    lifecycle_state = _agent_rollout_state(lab)
    after_hash = _config_hash(lab)
    lifecycle_ok = (
        lifecycle.returncode == 0
        and agent_rollout.returncode == 0
        and lifecycle_statuses == ["deployed"]
        and lifecycle_values.get("bpf", {}).get("monitorAggregation") == "low"
        and lifecycle_values.get("rollOutCiliumPods") is True
        and lifecycle_state["images_pinned"]
        and lifecycle_state["all_desired_agents_updated_and_ready"]
        and lifecycle_state["rollout_checksum_present"]
        and lifecycle_state["monitor_aggregation_low"]
        and after_hash is not None and after_hash != before_hash
    )
    lab.check(
        "positive", "Valid Cilium agent configuration upgrade rolls out and becomes Ready",
        lifecycle_ok,
        {"upgrade_succeeded": lifecycle.returncode == 0,
         "agent_rollout_wait_succeeded": agent_rollout.returncode == 0,
         "new_revision_deployed": lifecycle_statuses == ["deployed"],
         "effective_values_match": (
             lifecycle_values.get("bpf", {}).get("monitorAggregation") == "low"
             and lifecycle_values.get("rollOutCiliumPods") is True),
         "agent_images_pinned": lifecycle_state["images_pinned"],
         "desired_agents_updated_and_ready": lifecycle_state["all_desired_agents_updated_and_ready"],
         "config_checksum_rollout_observed": (
             lifecycle_state["rollout_checksum_present"]
             and after_hash is not None and after_hash != before_hash),
         "configmap_value_applied": lifecycle_state["monitor_aggregation_low"]})
    if not lifecycle_ok:
        lab.block("Valid Cilium agent configuration rollout did not reach the expected owned state")

    lifecycle_marker_ok, lifecycle_marker = _wait_for_marker(lab)
    lab.check("positive", "Marker service remains reachable after the agent configuration rollout",
              lifecycle_marker_ok, lifecycle_marker)
    if not lifecycle_marker_ok:
        lab.block("Marker service did not recover after the valid Cilium agent rollout")

    good_history, good_values = _revision_and_values(lab)
    good_revision = max(int(row["revision"]) for row in good_history)
    staged_upgrade = _stage_operator_comparison(lab, chart)
    comparison_rollout = _kubectl(
        lab, "-n", "kube-system", "rollout", "status", "deployment/cilium-operator",
        "--timeout=25s", timeout=35, allow_failure=True)
    rollout_timed_out = (
        comparison_rollout.returncode != 0
        and "timed out waiting for the condition" in comparison_rollout.stderr
    )
    comparison_history, _ = _revision_and_values(lab)
    comparison_statuses = _new_revision_statuses(comparison_history, good_revision)
    failed_state = _operator_rollout_state(lab)
    failed_rollout_ok = (
        staged_upgrade.returncode == 0
        and comparison_statuses == ["deployed"]
        and rollout_timed_out
        and failed_state["candidate_template_image"]
        and failed_state["candidate_pod_observed"]
        and failed_state["updated_replica_attempted"]
        and failed_state["failed_rollout_shape"]
        and failed_state["no_surge_rollout_strategy"]
    )
    lab.check(
        "red", "Schema-valid operator image change starts and fails a real workload rollout",
        failed_rollout_ok,
        {"helm_accepted_new_revision": staged_upgrade.returncode == 0
         and comparison_statuses == ["deployed"],
         "kubernetes_rollout_wait_timed_out": rollout_timed_out,
         "exact_candidate_image_in_template": failed_state["candidate_template_image"],
         "candidate_pod_failed_not_api_rejected": failed_state["candidate_pod_observed"],
         "updated_replica_attempted": failed_state["updated_replica_attempted"],
         "single_replica_no_surge_strategy": failed_state["no_surge_rollout_strategy"],
         "ready_replicas": failed_state["updated_replicas_ready"],
         "available_replicas": failed_state["updated_replicas_available"]})

    active_agents = _agent_rollout_state(lab)
    during_marker_ok, during_marker = _wait_for_marker(lab)
    data_plane_ok = (
        active_agents["images_pinned"]
        and active_agents["all_desired_agents_updated_and_ready"]
        and active_agents["monitor_aggregation_low"]
        and during_marker_ok
    )
    lab.check(
        "positive", "Pinned Cilium datapath and marker stay healthy during operator rollout failure",
        data_plane_ok,
        {"agent_images_pinned": active_agents["images_pinned"],
         "all_agents_ready": active_agents["all_desired_agents_updated_and_ready"],
         "valid_agent_config_retained": active_agents["monitor_aggregation_low"],
         "marker_reachable": during_marker_ok,
         "marker_observed": during_marker})

    rollback = _helm(
        lab, "rollback", RELEASE, str(good_revision), "-n", "kube-system",
        "--wait", "--timeout", "90s", timeout=110, allow_failure=True,
    )
    operator_rollout = _kubectl(
        lab, "-n", "kube-system", "rollout", "status", "deployment/cilium-operator",
        "--timeout=90s", timeout=100, allow_failure=True)
    recovered_history, recovered_values = _revision_and_values(lab)
    recovery_statuses = _new_revision_statuses(recovered_history, good_revision)
    operator_state = _operator_restored(lab)
    agent_state = _agent_rollout_state(lab)
    rollback_ok = (
        rollback.returncode == 0
        and operator_rollout.returncode == 0
        and recovery_statuses == ["superseded", "deployed"]
        and recovered_values == good_values
        and operator_state["pinned_operator_image_restored"]
        and operator_state["operator_ready"]
        and agent_state["images_pinned"]
        and agent_state["all_desired_agents_updated_and_ready"]
        and agent_state["monitor_aggregation_low"]
    )
    lab.check(
        "green", "Explicit Helm rollback restores the last known-good Cilium operator revision",
        rollback_ok,
        {"rollback_succeeded": rollback.returncode == 0,
         "operator_rollout_wait_succeeded": operator_rollout.returncode == 0,
         "new_revision_statuses": recovery_statuses,
         "known_good_values_restored": recovered_values == good_values,
         "pinned_operator_image_restored": operator_state["pinned_operator_image_restored"],
         "operator_ready": operator_state["operator_ready"],
         "agent_images_pinned": agent_state["images_pinned"],
         "all_agents_ready": agent_state["all_desired_agents_updated_and_ready"],
         "valid_agent_config_retained": agent_state["monitor_aggregation_low"]})

    recovered_marker_ok, recovered_marker = _wait_for_marker(lab)
    lab.check("green", "Marker service remains reachable after operator rollback",
              recovered_marker_ok, recovered_marker)


def _install(lab, chart, values, version_overrides):
    _helm(
        lab, "install", RELEASE, str(chart), "--namespace", "kube-system",
        "--values", str(values), *version_overrides, "--wait", "--timeout", "4m",
        timeout=260,
    )
    _kubectl(lab, "wait", "--for=condition=Ready", "node", "--all",
             "--timeout=120s", timeout=135)


def _revision_and_values(lab):
    history = _json(_helm(lab, "history", RELEASE, "-n", "kube-system", "-o", "json"))
    values = _json(_helm(lab, "get", "values", RELEASE, "-n", "kube-system", "-o", "json"))
    return history, values


def _invalid_upgrade(lab, chart, *, atomic):
    settings = ["--atomic"] if atomic else []
    return _helm(
        lab, "upgrade", RELEASE, str(chart), "--namespace", "kube-system",
        "--reuse-values", "--set", "debug.enabled=true",
        "--set", "readinessProbe.failureThreshold=-1", "--skip-schema-validation",
        *settings, "--wait", "--timeout", "45s", timeout=100,
        allow_failure=True,
    )


def _invalid_probe(upgrade):
    diagnostic = (upgrade.stdout + upgrade.stderr).lower()
    return (upgrade.returncode != 0 and "readinessprobe.failurethreshold" in diagnostic
            and "invalid value" in diagnostic)


def _new_revision_statuses(history, revision):
    ordered = sorted(history, key=lambda row: int(row["revision"]))
    return [row["status"] for row in ordered if int(row["revision"]) > revision]


def _checked_chart(lab, workspace, version, expected_sha):
    _helm(lab, "pull", CHART_SOURCE, "--version", version,
          "--destination", str(workspace), "--registry-config",
          str(workspace / "helm-registry.json"), timeout=120)
    chart = workspace / f"cilium-{version}.tgz"
    digest = hashlib.sha256(chart.read_bytes()).hexdigest()
    if digest != expected_sha:
        lab.block(f"Cilium {version} chart digest mismatch: {digest}")
    return chart


def _component_pod(lab, selector, container_name, expected_image):
    found = _json(_kubectl(lab, "-n", "kube-system", "get", "pods",
                           "-l", selector, "-o", "json")).get("items", [])
    observations = []
    for pod in found:
        metadata = pod["metadata"]
        if metadata.get("deletionTimestamp") is not None:
            continue
        pinned = any(container["name"] == container_name and container["image"] == expected_image
                     for container in pod["spec"].get("containers", []))
        statuses = pod.get("status", {}).get("containerStatuses", [])
        status = next((status for status in statuses if status["name"] == container_name), {})
        if pinned and status.get("ready") and status.get("state", {}).get("running"):
            observations.append({
                "pod_uid": metadata["uid"],
                "node": pod["spec"]["nodeName"],
                "image": expected_image,
                "runtime_image_id": status.get("imageID"),
            })
    if len(observations) != 1 or not observations[0]["runtime_image_id"]:
        lab.block(f"Expected one ready fixture {container_name} with the exact pin and runtime image ID")
    return observations[0]


def _patch_observation(lab, version, agent_image, operator_image):
    for target in ("daemonset/cilium", "deployment/cilium-operator"):
        _kubectl(lab, "-n", "kube-system", "rollout", "status", target,
                 "--timeout=120s", timeout=130)
    agent = _component_pod(lab, "k8s-app=cilium", "cilium-agent", agent_image)
    operator = _component_pod(lab, "io.cilium/app=operator,name=cilium-operator",
                              "cilium-operator", operator_image)
    history, _ = _revision_and_values(lab)
    deployed = [row for row in history if row.get("status") == "deployed"]
    if len(deployed) != 1 or deployed[0].get("chart") != f"cilium-{version}":
        lab.block(f"Helm did not report a unique deployed Cilium {version} chart")
    _wait_endpoint_ready(lab)
    datapath = _effective_agent_policy_state(lab, agent_image)
    marker, _ = _wait_for_marker(lab)
    return {
        "chart": deployed[0]["chart"], "revision": int(deployed[0]["revision"]),
        "agent": agent, "operator": operator, "datapath": datapath, "marker": marker,
    }


def _patch_upgrade(lab, chart, values):
    before = _patch_observation(lab, PREVIOUS_CILIUM_VERSION,
                                PREVIOUS_AGENT_IMAGE, PREVIOUS_OPERATOR_IMAGE)
    lab.check("positive", "The earlier pinned Cilium chart and release Pods serve the approved marker",
              before["marker"],
              {"chart": before["chart"], "agent_and_operator_ready_and_pinned": True,
               "case_policy_realized": True, "approved_marker": before["marker"]})
    _helm(lab, "upgrade", RELEASE, str(chart), "-n", "kube-system",
          "--reset-values", "--values", str(values), "--atomic",
          "--wait", "--timeout", "4m", timeout=280)
    after = _patch_observation(lab, CILIUM_VERSION, AGENT_IMAGE, OPERATOR_IMAGE)
    replacements = all(
        before[role]["pod_uid"] != after[role]["pod_uid"]
        and before[role]["runtime_image_id"] != after[role]["runtime_image_id"]
        and before[role]["node"] == after[role]["node"]
        for role in ("agent", "operator")
    )
    datapath_retained = all(
        before["datapath"][key] == after["datapath"][key]
        for key in ("captured_pod_uid", "captured_policy_uid")
    )
    next_revision = after["revision"] == before["revision"] + 1
    evidence = {
        "source_chart": before["chart"], "installed_chart": after["chart"],
        "next_helm_revision_deployed": next_revision,
        "agent_and_operator_uids_and_runtime_images_changed": replacements,
        "same_workload_and_policy_uids": datapath_retained,
        "case_policy_realized_after": after["datapath"]["owned_policy_ingress_rule_count"] > 0,
        "approved_marker": after["marker"],
    }
    (lab.evidence / "cilium-patch-upgrade.json").write_text(json.dumps(
        {"before": before, "after": after, "observations": evidence},
        indent=2, sort_keys=True) + "\n")
    lab.check("green", "Cilium patch upgrade rolls both pinned components and the same realized policy serves its approved marker",
              replacements and datapath_retained and next_revision and after["marker"], evidence)


def _observe_agent_start_failure(lab, option, known_good_uid):
    deadline = time.monotonic() + 48
    while time.monotonic() < deadline:
        pods = _json(_kubectl(lab, "-n", "kube-system", "get", "pods",
                               "-l", "k8s-app=cilium", "-o", "json"))
        for pod in pods.get("items", []):
            metadata = pod["metadata"]
            if metadata.get("deletionTimestamp") or metadata["uid"] == known_good_uid:
                continue
            containers = [container for container in pod["spec"]["containers"]
                          if container["name"] == "cilium-agent"]
            if len(containers) != 1:
                continue
            container = containers[0]
            if container["image"] != AGENT_IMAGE or option not in container.get("args", []):
                continue
            status = next((entry for entry in pod.get("status", {}).get("containerStatuses", [])
                           if entry["name"] == "cilium-agent"), {})
            failures = [status.get("state", {}).get("terminated", {}),
                        status.get("lastState", {}).get("terminated", {})]
            if status.get("ready") or not any(entry.get("exitCode", 0) != 0 for entry in failures):
                continue
            result = _kubectl(lab, "-n", "kube-system", "logs", "pod/" + metadata["name"],
                              "-c", "cilium-agent", timeout=15, allow_failure=True)
            if result.returncode or f"unknown flag: {option}" not in result.stdout + result.stderr:
                result = _kubectl(lab, "-n", "kube-system", "logs", "pod/" + metadata["name"],
                                  "-c", "cilium-agent", "--previous", timeout=15, allow_failure=True)
            if result.returncode == 0 and f"unknown flag: {option}" in result.stdout + result.stderr:
                return {"pod_uid": metadata["uid"], "pinned_image": True, "agent_unready": True,
                        "process_rejected_option": True, "nonzero_exit_observed": True}
        time.sleep(0.6)
    return {}


def _prove_agent_start_recovery(lab, chart):
    option = "--saf-lab-unrecognized-agent-option"
    before = _component_pod(lab, "k8s-app=cilium", "cilium-agent", AGENT_IMAGE)
    previous_policy = _effective_agent_policy_state(lab)
    history, good_values = _revision_and_values(lab)
    good_revision = max(int(row["revision"]) for row in history)
    observed_failure = {}
    staged_statuses = []
    stage = _helm(lab, "upgrade", RELEASE, str(chart), "-n", "kube-system",
                  "--reuse-values", "--set-string", f"extraArgs[0]={option}",
                  timeout=55, allow_failure=True)
    try:
        if stage.returncode == 0:
            history, _ = _revision_and_values(lab)
            staged_statuses = _new_revision_statuses(history, good_revision)
            observed_failure = _observe_agent_start_failure(lab, option, before["pod_uid"])
    finally:
        rollback = _helm(lab, "rollback", RELEASE, str(good_revision), "-n", "kube-system",
                         "--wait", "--timeout", "110s", timeout=125, allow_failure=True)
    lab.check("red", "A schema-valid configuration reaches the pinned Cilium agent and the new process refuses it",
              stage.returncode == 0 and staged_statuses == ["deployed"] and bool(observed_failure),
              {"staged_as_helm_revision": staged_statuses == ["deployed"],
               "replacement_pinned_agent_unready": observed_failure.get("agent_unready", False),
               "exact_option_rejected_by_process": observed_failure.get("process_rejected_option", False),
               "nonzero_agent_exit": observed_failure.get("nonzero_exit_observed", False)})

    rollout = _kubectl(lab, "-n", "kube-system", "rollout", "status", "daemonset/cilium",
                       "--timeout=110s", timeout=120, allow_failure=True)
    if rollback.returncode != 0 or rollout.returncode != 0:
        lab.block("Rollback did not restore the known-good Cilium agent rollout")
    restored = _component_pod(lab, "k8s-app=cilium", "cilium-agent", AGENT_IMAGE)
    restored_history, restored_values = _revision_and_values(lab)
    _wait_endpoint_ready(lab)
    restored_policy = _effective_agent_policy_state(lab)
    marker_ok, _ = _wait_for_marker(lab)
    observations = {
        "rollback_deployed": _new_revision_statuses(restored_history, good_revision) ==
            ["superseded", "deployed"],
        "restored_exact_values": restored_values == good_values,
        "new_ready_agent_on_approved_pin": restored["pod_uid"] not in
            {before["pod_uid"], observed_failure.get("pod_uid")},
        "same_workload_and_realized_ingress_policy": all(
            previous_policy[key] == restored_policy[key]
            for key in ("captured_pod_uid", "captured_policy_uid")),
        "restored_approved_marker": marker_ok,
    }
    (lab.evidence / "cilium-agent-start-recovery.json").write_text(json.dumps(
        {"known_good": before, "failed_candidate": observed_failure, "restored": restored,
         "policy_before": previous_policy, "policy_after": restored_policy,
         "observations": observations}, indent=2, sort_keys=True) + "\n")
    lab.check("green", "Helm rollback restores the pinned Cilium agent, original realized policy and approved marker",
              all(observations.values()), observations)


def run(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith(KIND_VERSION):
        lab.block(f"Expected {KIND_VERSION}, got {kind_version!r}")
    server_version = _json(_kubectl(lab, "version", "-o", "json"))
    actual_k8s = server_version.get("serverVersion", {}).get("gitVersion")
    if actual_k8s != KUBERNETES_VERSION:
        lab.block(f"Expected Kubernetes {KUBERNETES_VERSION}, got {actual_k8s!r}")

    work = Path(lab.kubeconfig).parent
    previous_chart = _checked_chart(lab, work, PREVIOUS_CILIUM_VERSION, PREVIOUS_CHART_SHA256)
    chart = _checked_chart(lab, work, CILIUM_VERSION, CHART_SHA256)
    values = Path(__file__).with_name("cilium-values.yaml")
    _install(lab, previous_chart, values, [
        "--set-string", f"image.tag=v{PREVIOUS_CILIUM_VERSION}",
        "--set-string", f"image.digest={PREVIOUS_AGENT_IMAGE.split('@', 1)[1]}",
        "--set-string", f"operator.image.genericDigest={PREVIOUS_OPERATOR_IMAGE.split('@', 1)[1]}",
    ])
    _prepare_workloads(lab)
    approved_policy = _approved_marker_policy()
    _create(lab, approved_policy)
    _patch_upgrade(lab, chart, values)

    images_ok, images = _assert_images(lab)
    lab.check("positive", "Baseline Cilium agent and operator images match digest pins",
              images_ok, images)
    baseline_ok, baseline_result = _wait_for_marker(lab)
    lab.check("positive", "Baseline in-cluster marker service is reachable",
              baseline_ok, baseline_result)

    policy_before_upgrade = _wait_endpoint_ready(lab)
    effective_policy_before_upgrade = _effective_agent_policy_state(lab)
    policy_marker_ok, policy_marker = _wait_for_marker(lab)
    if not policy_marker_ok:
        lab.block("The approved marker flow was not reachable with its Cilium allow policy active")

    # A negative threshold survives API defaulting and produces a typed
    # Kubernetes validation error for both otherwise identical upgrades.
    before_history, baseline_values = _revision_and_values(lab)
    original_revision = max(int(row["revision"]) for row in before_history)
    plain_upgrade = _invalid_upgrade(lab, chart, atomic=False)
    plain_history, _ = _revision_and_values(lab)
    plain_new = _new_revision_statuses(plain_history, original_revision)
    lab.check("red", "A failed non-atomic upgrade has no automatic rollback revision",
              _invalid_probe(plain_upgrade) and plain_new == ["failed"],
              {"api_rejected_readiness_threshold": _invalid_probe(plain_upgrade),
               "new_revision_statuses": plain_new})

    _helm(lab, "rollback", RELEASE, str(original_revision), "-n", "kube-system",
          "--wait", "--timeout", "90s", timeout=110)
    restored_history, restored_baseline = _revision_and_values(lab)
    if restored_baseline != baseline_values:
        lab.block("Manual reset did not restore the approved baseline before the atomic trial")
    restored_revision = max(int(row["revision"]) for row in restored_history)

    failed_upgrade = _invalid_upgrade(lab, chart, atomic=True)
    after_history, restored_values = _revision_and_values(lab)
    statuses = _new_revision_statuses(after_history, restored_revision)
    lab.check("green", "The same invalid upgrade triggers atomic rollback to approved values",
              _invalid_probe(failed_upgrade) and statuses == ["failed", "deployed"]
              and rollback_observation(failed_upgrade.returncode, after_history,
                                       restored_values, baseline_values),
              {"api_rejected_readiness_threshold": _invalid_probe(failed_upgrade),
               "new_revision_statuses": statuses,
               "values_restored": restored_values == baseline_values})

    images_restored, restored_image_details = _assert_images(lab)
    lab.check("green", "Rollback restored the digest-pinned CNI workloads",
              images_restored, restored_image_details)
    green_ok, green_result = _wait_for_marker(lab)
    lab.check("green", "Post-rollback marker service remains reachable",
              green_ok, green_result)
    _run_rollout_recovery(lab, chart)
    _prove_agent_start_recovery(lab, chart)
    policy_after_rollback = _wait_endpoint_ready(lab)
    effective_policy_after_rollback = _effective_agent_policy_state(lab)
    stored_policy = _json(_kubectl(lab, "-n", NAMESPACE, "get", "ciliumnetworkpolicy", CNP_NAME, "-o", "json"))
    removed = _kubectl(lab, "-n", NAMESPACE, "delete", "ciliumnetworkpolicy", CNP_NAME,
                       "--wait=true", allow_failure=True)
    absent_after_removal = _kubectl(lab, "-n", NAMESPACE, "get", "ciliumnetworkpolicy", CNP_NAME,
                                    "-o", "name", allow_failure=True)
    final_marker_ok, final_marker = _wait_for_marker(lab)
    policy_lifecycle_ok = (
        stored_policy.get("spec") == approved_policy["spec"]
        and policy_before_upgrade.get("endpoint_identity", 0) > 1
        and policy_after_rollback.get("endpoint_identity", 0) > 1
        and policy_before_upgrade.get("endpoint_state") == "ready"
        and policy_after_rollback.get("endpoint_state") == "ready"
        and effective_policy_before_upgrade.get("owned_policy_ingress_rule_count", 0) > 0
        and effective_policy_after_rollback.get("owned_policy_ingress_rule_count", 0) > 0
        and policy_marker_ok and removed.returncode == 0
        and absent_after_removal.returncode != 0 and final_marker_ok
    )
    lab.check("positive", "The pinned local Cilium agent reports the exact case-owned ingress rule as realized across Helm lifecycle changes",
              policy_lifecycle_ok,
              {"policy_spec_restored_exactly": stored_policy.get("spec") == approved_policy["spec"],
               "endpoint_ready_before_upgrade": policy_before_upgrade.get("endpoint_state"),
               "endpoint_ready_after_rollback": policy_after_rollback.get("endpoint_state"),
               "endpoint_policy_status_present_before_and_after": (
                   policy_before_upgrade.get("policy_status_present")
                   and policy_after_rollback.get("policy_status_present")),
               "agent_realized_exact_rule_before_upgrade": effective_policy_before_upgrade["owned_policy_ingress_rule_count"] > 0,
               "agent_realized_exact_rule_after_rollback": effective_policy_after_rollback["owned_policy_ingress_rule_count"] > 0,
               "managed_server_endpoint_identity_present_before_and_after": (
                   policy_before_upgrade.get("endpoint_identity", 0) > 1
                   and policy_after_rollback.get("endpoint_identity", 0) > 1),
               "marker_before_upgrade": policy_marker,
               "policy_removed_after_lifecycle": removed.returncode == 0 and absent_after_removal.returncode != 0,
               "marker_after_policy_removal": final_marker})
    (lab.evidence / "cilium-policy-lifecycle.json").write_text(json.dumps({
        "control": "SAF-K8S-0502-004",
        "scope": "One case-owned Cilium endpoint, realized TCP ingress rule and approved marker traffic across Helm lifecycle changes.",
        "policy": approved_policy,
        "endpoint_before_upgrade": policy_before_upgrade,
        "endpoint_after_rollback": policy_after_rollback,
        "agent_realized_policy_before_upgrade": effective_policy_before_upgrade,
        "agent_realized_policy_after_rollback": effective_policy_after_rollback,
        "policy_object_after_rollback": stored_policy,
        "approved_marker_after_policy_install": policy_marker,
        "approved_marker_after_helm_lifecycle": final_marker,
        "policy_removed": removed.returncode == 0 and absent_after_removal.returncode != 0,
        "endpoint_policy_status_present": (
            policy_before_upgrade.get("policy_status_present")
            or policy_after_rollback.get("policy_status_present")),
        "effective_agent_policy_observed": (
            effective_policy_before_upgrade.get("owned_policy_ingress_rule_count", 0) > 0
            and effective_policy_after_rollback.get("owned_policy_ingress_rule_count", 0) > 0),
        "denial_tested": False,
        "check": policy_lifecycle_ok,
    }, sort_keys=True, indent=2) + "\n")
