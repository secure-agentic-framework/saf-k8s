"""Review a synthetic Kubernetes maintenance plan against live fixture versions."""
from copy import deepcopy
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent
FIXTURE_PATH = HERE / "fixtures" / "maintenance.json"
CONTROL_ID = "SAF-K8S-1007-011"
NAMESPACE = "saf-test"
DEPLOYMENT = "saf-1007-011-mock-workload"
LABEL_KEY = "saf-lab.example/control"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "One disposable default-profile Kind v1.36.1 cluster. The case reads live API server, "
    "kubectl, controller-manager, scheduler, kubelet, and kube-proxy versions; evaluates a "
    "synthetic one-minor maintenance sequence against the official Kubernetes v1.36 skew "
    "policy; and records a deliberately out-of-order/incompatible plan as red. A single-replica, "
    "tokenless Python Deployment performs no network I/O and carries reserved fixture "
    "release markers. The case applies a candidate marker, consumes a synthetic failed-health "
    "fixture to choose a rollback target, and verifies Kubernetes API rollout back to the stable "
    "marker. It does not upgrade Kubernetes components, cordon/drain nodes, install or upgrade "
    "add-ons, perform a Kubernetes version downgrade, or exercise production recovery. It does "
    "not establish organizational change approval, managed-service coordination, vendor add-on "
    "compatibility, or production service health."
)


VERSION_RE = re.compile(r"(?:^|[^0-9])(\d+)\.(\d+)\.(\d+)(?:[^0-9]|$)")


def _version(value):
    match = VERSION_RE.search(str(value or ""))
    if not match:
        raise ValueError(f"Unrecognized Kubernetes component version: {value!r}")
    return tuple(int(part) for part in match.groups())


def _version_text(value):
    major, minor, patch = _version(value)
    return f"v{major}.{minor}.{patch}"


def _image_version(image):
    # Kubernetes component images in the Kind node image use version tags.
    match = re.search(r":v?(\d+\.\d+\.\d+)(?:@|$)", str(image or ""))
    if not match:
        raise ValueError(f"Component image has no explicit Kubernetes version tag: {image!r}")
    return _version_text(match.group(1))


def _minor_distance(left, right):
    left_major, left_minor, _ = _version(left)
    right_major, right_minor, _ = _version(right)
    if left_major != right_major:
        return None
    return right_minor - left_minor


def _component_versions(lab):
    control_plane = f"{lab.cluster}-control-plane"
    lab.kubectl("-n", "kube-system", "wait", "--for=create", "--for=condition=Ready",
                f"pod/kube-controller-manager-{control_plane}", f"pod/kube-scheduler-{control_plane}",
                "--timeout=35s")
    lab.kubectl("-n", "kube-system", "wait", "--for=create", "--for=condition=Ready",
                "pods", "-l", "k8s-app=kube-proxy", "--timeout=35s")
    version_doc = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server = _version_text(version_doc.get("serverVersion", {}).get("gitVersion"))
    client = _version_text(version_doc.get("clientVersion", {}).get("gitVersion"))
    node_doc = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)
    nodes = []
    for node in node_doc.get("items", []):
        metadata = node.get("metadata", {})
        info = node.get("status", {}).get("nodeInfo", {})
        nodes.append({
            "name": metadata.get("name"),
            "uid": metadata.get("uid"),
            "role_labels": {key: value for key, value in metadata.get("labels", {}).items()
                            if key.startswith("node-role.kubernetes.io/")},
            "ready": any(condition.get("type") == "Ready" and condition.get("status") == "True"
                          for condition in node.get("status", {}).get("conditions", [])),
            "kubelet": _version_text(info.get("kubeletVersion")),
        })
    pods_doc = json.loads(lab.kubectl("-n", "kube-system", "get", "pods", "-o", "json").stdout)
    components = {}
    raw_pods = []
    wanted = {
        "kube-controller-manager": "controller_manager",
        "kube-scheduler": "scheduler",
        "kube-proxy": "kube_proxy",
    }
    for pod in pods_doc.get("items", []):
        metadata = pod.get("metadata", {})
        name = metadata.get("name", "")
        component = next((key for prefix, key in wanted.items() if name.startswith(prefix)), None)
        if component is None:
            continue
        containers = pod.get("spec", {}).get("containers", [])
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if len(containers) != 1 or len(statuses) != len(containers):
            raise ValueError(f"Expected one container for observed {component} Pod {name}")
        image = containers[0].get("image", "")
        container_status = statuses[0]
        observed = {
            "name": name,
            "uid": metadata.get("uid"),
            "ready": container_status.get("ready") is True,
            "image": image,
            "image_id": container_status.get("imageID"),
            "version": _image_version(image),
        }
        if not observed["ready"] or not observed["image_id"]:
            raise ValueError(f"Observed {component} Pod {name} is not Ready with a resolved image")
        if component == "kube_proxy":
            components.setdefault(component, []).append(observed["version"])
        else:
            if component in components:
                raise ValueError(f"Expected one {component} Pod in the default Kind profile")
            components[component] = observed["version"]
        raw_pods.append(observed)
    if len(nodes) != 1:
        lab.block("Expected one node in the default Kind profile")
    node = nodes[0]
    if not (node["ready"] and node["kubelet"] and node["name"] and node["uid"]
            and "node-role.kubernetes.io/control-plane" in node["role_labels"]):
        lab.block("Control-plane node identity, version, or Ready evidence is incomplete")
    if not all(key in components for key in ("controller_manager", "scheduler", "kube_proxy")):
        raise ValueError("Could not observe controller-manager, scheduler, and kube-proxy versions")
    if len(set(components["kube_proxy"])) != 1:
        raise ValueError("Default-profile kube-proxy Pods report inconsistent versions")
    components["kube_proxy"] = components["kube_proxy"][0]
    versions = {
        "api_server": server,
        "kubectl": client,
        "controller_manager": components["controller_manager"],
        "scheduler": components["scheduler"],
        "kube_proxy": components["kube_proxy"],
        "kubelets": {"control-plane": node["kubelet"]},
    }
    raw = {"version_response": version_doc, "nodes": node_doc, "component_pods": raw_pods}
    return versions, raw, node


def _skew_findings(versions, *, api_server=None, policy=None):
    policy = policy or {
        "max_kubelet_minor_lag": 3,
        "max_kube_proxy_minor_lag": 3,
        "max_controller_minor_lag": 1,
        "max_kubectl_minor_skew": 1,
    }
    api = api_server or versions["api_server"]
    findings = {}
    for component in ("controller_manager", "scheduler"):
        distance = _minor_distance(versions[component], api)
        findings[f"{component}_not_newer_and_within_one_minor"] = (
            distance is not None and 0 <= distance <= policy["max_controller_minor_lag"]
        )
    for node, kubelet in versions["kubelets"].items():
        distance = _minor_distance(kubelet, api)
        findings[f"kubelet_{node}_not_newer_and_within_three_minors"] = (
            distance is not None and 0 <= distance <= policy["max_kubelet_minor_lag"]
        )
    proxy_distance = _minor_distance(versions["kube_proxy"], api)
    findings["kube_proxy_not_newer_and_within_three_minors_of_api_server"] = (
        proxy_distance is not None and 0 <= proxy_distance <= policy["max_kube_proxy_minor_lag"]
    )
    proxy_kubelet_distances = [
        _minor_distance(versions["kube_proxy"], kubelet)
        for kubelet in versions["kubelets"].values()
    ]
    findings["kube_proxy_within_three_minors_of_each_kubelet"] = all(
        distance is not None and -policy["max_kube_proxy_minor_lag"] <= distance
        <= policy["max_kube_proxy_minor_lag"] for distance in proxy_kubelet_distances
    )
    client_distance = _minor_distance(versions["kubectl"], api)
    findings["kubectl_within_one_minor_of_api_server"] = (
        client_distance is not None and -policy["max_kubectl_minor_skew"] <= client_distance
        <= policy["max_kubectl_minor_skew"]
    )
    return findings


def _next_minor_version(current):
    major, minor, _ = _version(current)
    return f"v{major}.{minor + 1}.0"


def _evaluate_sequence(versions, order, target, policy):
    required = [
        "control_plane_api_server",
        "control_plane_components",
        "drain_each_node_then_kubelet",
        "kube_proxy_after_api_server",
        "post_upgrade_validation",
    ]
    order_ok = order == required
    state = deepcopy(versions)
    stages = []
    state["api_server"] = target
    findings = _skew_findings(state, policy=policy)
    stages.append({"stage": required[0], "versions": deepcopy(state), "findings": findings})
    state["controller_manager"] = target
    state["scheduler"] = target
    findings = _skew_findings(state, policy=policy)
    stages.append({"stage": required[1], "versions": deepcopy(state), "findings": findings})
    state["kubelets"] = {node: target for node in versions["kubelets"]}
    findings = _skew_findings(state, policy=policy)
    stages.append({"stage": required[2], "versions": deepcopy(state), "findings": findings})
    state["kube_proxy"] = target
    findings = _skew_findings(state, policy=policy)
    stages.append({"stage": required[3], "versions": deepcopy(state), "findings": findings})
    findings = _skew_findings(state, policy=policy)
    stages.append({"stage": required[4], "versions": deepcopy(state), "findings": findings})
    skew_ok = all(all(stage["findings"].values()) for stage in stages)
    return {"accepted": order_ok and skew_ok, "order_matches_policy": order_ok,
            "all_intermediate_skew_checks_pass": skew_ok, "target_version": target,
            "stages": stages}


def _deployment(fixture, release, release_ref):
    labels = {LABEL_KEY: CONTROL_ID, "saf-lab.example/fixture": "synthetic"}
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": DEPLOYMENT, "namespace": NAMESPACE, "labels": labels,
                     "annotations": {"kubernetes.io/change-cause": f"fixture release {release}"}},
        "spec": {
            "replicas": 1,
            "revisionHistoryLimit": 3,
            "selector": {"matchLabels": {"app": DEPLOYMENT}},
            "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}},
            "template": {"metadata": {"labels": {"app": DEPLOYMENT, **labels}},
                          "spec": {
                              "automountServiceAccountToken": False,
                              "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                  "seccompProfile": {"type": "RuntimeDefault"}},
                              "containers": [{
                                  "name": "mock-workload", "image": fixture["image"],
                                  "imagePullPolicy": "IfNotPresent",
                                  "command": ["python", "-B", "-c", "import time; time.sleep(3600)"],
                                  "env": [{"name": "SAF_FIXTURE_RELEASE", "value": release},
                                          {"name": "SAF_FIXTURE_RELEASE_REF", "value": release_ref}],
                                  "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                "limits": {"cpu": "100m", "memory": "64Mi"}},
                                  "securityContext": {"allowPrivilegeEscalation": False,
                                                      "readOnlyRootFilesystem": True,
                                                      "capabilities": {"drop": ["ALL"]}},
                              }],
                          }},
        },
    }


def _apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource))


def _wait_rollout(lab):
    lab.kubectl("-n", NAMESPACE, "rollout", "status", f"deployment/{DEPLOYMENT}",
                "--timeout=120s", timeout=130)


def _deployment_live(lab):
    return json.loads(lab.kubectl("-n", NAMESPACE, "get", "deployment", DEPLOYMENT, "-o", "json").stdout)


def _view(resource):
    metadata = resource.get("metadata", {})
    spec = resource.get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", {})
    container = (pod_spec.get("containers") or [{}])[0]
    env = {entry.get("name"): entry.get("value") for entry in container.get("env", [])}
    status = resource.get("status", {})
    return {
        "uid": metadata.get("uid"),
        "generation": metadata.get("generation"),
        "observed_generation": status.get("observedGeneration"),
        "revision": metadata.get("annotations", {}).get("deployment.kubernetes.io/revision"),
        "image": container.get("image"),
        "release": env.get("SAF_FIXTURE_RELEASE"),
        "release_ref": env.get("SAF_FIXTURE_RELEASE_REF"),
        "replicas": status.get("replicas", 0),
        "ready_replicas": status.get("readyReplicas", 0),
        "updated_replicas": status.get("updatedReplicas", 0),
        "available_replicas": status.get("availableReplicas", 0),
    }


def _save_raw(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _ready_marker(lab):
    pods = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-l", f"app={DEPLOYMENT}", "-o", "json").stdout)
    ready = [pod for pod in pods.get("items", []) if not pod.get("metadata", {}).get("deletionTimestamp")
             and any(item.get("type") == "Ready" and item.get("status") == "True"
                     for item in pod.get("status", {}).get("conditions", []))]
    if len(ready) != 1:
        raise ValueError("Expected exactly one Ready case-owned mock Pod")
    pod_name = ready[0]["metadata"]["name"]
    probe = (
        "import json, os; print(json.dumps([os.environ['SAF_FIXTURE_RELEASE'], "
        "os.environ['SAF_FIXTURE_RELEASE_REF']]))"
    )
    return json.loads(lab.kubectl("-n", NAMESPACE, "exec", f"pod/{pod_name}", "--", "python", "-c", probe).stdout)


def run(lab):
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if fixture.get("fixture_id") != "SYNTH-1007-011-MAINTENANCE-001" or fixture.get("fixture_only") is not True:
        lab.block("Unexpected maintenance fixture identity")
    workload = fixture["mock_workload"]
    if workload.get("image") != PYTHON_IMAGE:
        lab.block("Mock workload image differs from the reviewed digest-pinned reference")

    versions, raw_versions, node = _component_versions(lab)
    policy = fixture["version_policy"]
    baseline_findings = _skew_findings(versions, policy=policy)
    if not all(baseline_findings.values()):
        lab.block(f"Observed baseline components violate or exceed the modeled skew policy: {baseline_findings}")
    target = _next_minor_version(versions["api_server"])
    expected_step = fixture["target_minor_step"]
    if _minor_distance(versions["api_server"], target) != expected_step:
        lab.block("Fixture target does not represent the configured one-minor step")

    ordered = list(fixture["maintenance_order"])
    green_plan = _evaluate_sequence(versions, ordered, target, policy)
    bad_order = ["drain_each_node_then_kubelet", "control_plane_api_server",
                 "control_plane_components", "kube_proxy_after_api_server", "post_upgrade_validation"]
    red_plan = _evaluate_sequence(versions, bad_order, target, policy)
    red_kubelet_state = deepcopy(versions)
    red_kubelet_state["kubelets"] = {"control-plane": target}
    red_skew = _skew_findings(red_kubelet_state, policy=policy)
    red_observation = {
        "observed_versions": versions,
        "candidate_version": target,
        "incorrect_order": bad_order,
        "incorrect_order_rejected": not red_plan["accepted"],
        "target_kubelet_before_api_server_findings": red_skew,
        "target_kubelet_before_api_server_rejected": not all(red_skew.values()),
    }
    if not red_observation["incorrect_order_rejected"] or red_observation["target_kubelet_before_api_server_rejected"] is not True:
        lab.block("The intentionally invalid ordering/skew fixture was not rejected")
    _save_raw(lab, "component-versions.raw.json", raw_versions)
    _save_raw(lab, "red-maintenance-plan.raw.json", red_observation)
    lab.check("red", "Out-of-order kubelet-first plan and a newer kubelet against the old API server are rejected",
              red_observation["incorrect_order_rejected"] and red_observation["target_kubelet_before_api_server_rejected"],
              red_observation)

    green_observation = {
        "observed_baseline_versions": versions,
        "observed_versions_are_live_api_observations": True,
        "candidate_version": target,
        "candidate_version_status": "modeled_not_installed",
        "baseline_skew_findings": baseline_findings,
        "ordered_plan": ordered,
        "plan_evaluation": green_plan,
        "control_plane_node": {"name_and_uid_present": bool(node["name"] and node["uid"]),
                               "ready": node["ready"], "role_labels": node["role_labels"],
                               "kubelet": node["kubelet"]},
        "execution_boundary": "plan-only; no Kubernetes component is upgraded",
    }
    _save_raw(lab, "green-maintenance-plan.raw.json", green_observation)
    lab.check("green", "One-minor maintenance stages remain within official component skew bounds",
              green_plan["accepted"] and all(baseline_findings.values()), green_observation)
    if not green_plan["accepted"]:
        lab.block("Ordered synthetic maintenance plan did not pass all intermediate skew checks")

    baseline = _deployment(workload, workload["baseline_release"], workload["baseline_ref"])
    _apply(lab, baseline)
    _wait_rollout(lab)
    baseline_live = _deployment_live(lab)
    baseline_view = _view(baseline_live)
    baseline_marker = _ready_marker(lab)
    baseline_ready = (baseline_view["ready_replicas"] == 1
                      and baseline_marker == [workload["baseline_release"], workload["baseline_ref"]])
    if not baseline_ready:
        lab.block("Stable mock workload did not become Ready with its fixture marker")

    candidate = _deployment(workload, workload["candidate_release"], workload["candidate_ref"])
    _apply(lab, candidate)
    _wait_rollout(lab)
    candidate_live = _deployment_live(lab)
    candidate_view = _view(candidate_live)
    candidate_marker = _ready_marker(lab)
    candidate_ready = (candidate_view["ready_replicas"] == 1
                       and candidate_marker == [workload["candidate_release"], workload["candidate_ref"]])
    if not candidate_ready:
        lab.block("Candidate mock workload did not become Ready with its fixture marker")
    candidate_result = {
        "candidate_ref": workload["candidate_ref"],
        "health": workload["candidate_health"],
        "fixture_only": True,
    }
    should_rollback = candidate_result["health"] == "synthetic-failed"
    decision = {
        "decision_id": "urn:example:saf:decision:maintenance-fixture-011-001",
        "fixture_only": True,
        "observed_kubernetes_versions": versions,
        "observed_versions_are_live_api_observations": True,
        "candidate_kubernetes_version": target,
        "candidate_kubernetes_version_status": "modeled_not_installed",
        "ordered_maintenance_plan_accepted": green_plan["accepted"],
        "skew_findings_by_stage": [stage["findings"] for stage in green_plan["stages"]],
        "candidate_workload": candidate_result,
        "decision": "rollback_mock_workload_to_fixture_baseline" if should_rollback else "retain_candidate_fixture",
        "rollback_target": workload["rollback_target"],
        "reason": "Synthetic candidate health fixture is failed; this decision changes only the named sleeping mock Deployment.",
        "production_readiness": "unverified",
        "kubernetes_version_downgrade_performed": False,
    }
    _save_raw(lab, "mock-rollback-decision.raw.json", decision)
    if not should_rollback or decision["rollback_target"] != workload["baseline_ref"]:
        lab.block("Synthetic rollback fixture did not select the exact stable fixture reference")
    lab.kubectl("-n", NAMESPACE, "rollout", "undo", f"deployment/{DEPLOYMENT}", timeout=90)
    _wait_rollout(lab)
    rollback_live = _deployment_live(lab)
    rollback_view = _view(rollback_live)
    rollback_marker = _ready_marker(lab)
    same_workload = bool(baseline_view["uid"]) and (
        baseline_view["uid"] == candidate_view["uid"] == rollback_view["uid"]
    )
    restored = (same_workload
                and rollback_view["release"] == workload["baseline_release"]
                and rollback_view["release_ref"] == workload["rollback_target"]
                and rollback_view["ready_replicas"] == 1
                and rollback_view["observed_generation"] == rollback_view["generation"]
                and rollback_marker == [workload["baseline_release"], workload["rollback_target"]]
                and rollback_view["revision"] != baseline_view["revision"])
    _save_raw(lab, "mock-workload-rollback.raw.json", {
        "decision": decision,
        "baseline_deployment": baseline_live,
        "candidate_deployment": candidate_live,
        "rollback_deployment": rollback_live,
        "baseline_marker": baseline_marker,
        "candidate_marker": candidate_marker,
        "rollback_marker": rollback_marker,
    })
    lab.check("positive", "Synthetic failure selects the exact inert prior fixture and API-observed rollout undo restores it",
              should_rollback and restored,
              {"decision": decision["decision"], "target": decision["rollback_target"],
               "baseline_marker": baseline_marker, "candidate_marker": candidate_marker,
               "rollback_marker": rollback_marker, "same_deployment_uid": same_workload,
               "rollback_deployment": {key: value for key, value in rollback_view.items()
                                       if key != "uid"},
               "kubernetes_version_downgrade_performed": False})
