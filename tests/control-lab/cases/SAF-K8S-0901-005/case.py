"""Verify namespace isolation and run the pinned Flower workflow through a scoped egress policy."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import time

from fixtures import container

SCOPE = 'One disposable Kind cluster on Kubernetes v1.36.1 with two synthetic participant namespaces and one case-owned local aggregation namespace. Two participant mock HTTP responders first exchange only fixed /healthz markers before NetworkPolicy, then the same ordinary health path is checked after namespace policies isolate participants and permit the approved aggregation Service. Both participants independently contact the identical aggregation ClusterIP and port. No model, training, gradient, adversarial input, real service, feed, or external target is used. The same disposable cluster also runs the pinned Flower SecAgg+ workflow with an exact participant egress allowlist. Two directed owned peer marker routes are checked before and after policy, and the actual authorized Flower workflow completes one equal-weight and one fixed 1-2-3-weight round in the same four Flower Pods. A separately scoped Kubernetes workload checks the exact approved receipt digest for each aggregate. The fixture uses fixed inert vectors. Deployed boundaries, identity, privacy settings and protocol security require separate evidence.'
HERE = Path(__file__).resolve().parent
BASE_CASE = HERE / "base_case.py"
FLOWER_CASE = HERE / "flower" / "case.py"
FLOWER_SHA256 = {
    "case.py": "5921cd325ca6f1c5fad7200ff47a40b9a0150ae0b2e609a6e0b819996cbe991d",
    "image-pins.json": "fde49a4c12553bea10ab575db996b474641811037acb955135ebc024991fc3d3",
    "pyproject.toml": "e11968913fe24652ac78e5b2e6dcafcba3c1357eef3a853b60387dec443a497a",
    "client_app.py": "33aa44312d25471d07034a77cfdbe4c25f2aff8d289f95c4c1fa305b4a049a4f",
    "server_app.py": "a27846b420d8b4a20c5b6545ee6c002df81a955f593896d54a1fcd730c092ad1",
    "aggregation.py": "91c0b961a19a490451217fa4a2ed4ad7fbac883fb7d5dfaff4865830993656fc",
    "base_case.py": "c355b4fa2528a95c31932d451edb8f1eedd6e11f6431f05b65b6272bf9fa3f7c",
}
HEALTH_SERVER = HERE / "health_server.py"
HEALTH_PROBE = HERE / "health_probe.py"
HEALTH_CONFIG = "fixture-flower-peer-health"
NETWORK_POLICY = "fixture-flower-participant-egress"
FLOWER_LABEL = "saf-k8s-fixture-flower-secagg"
SUPERLINK = "fixture-flower-superlink"
SUPER_NODES = ("fixture-flower-supernode-a", "fixture-flower-supernode-b",
               "fixture-flower-supernode-c")
HEALTH_MARKERS = {
    SUPER_NODES[0]: "SAF-0901-005-FLOWER-PARTICIPANT-A-HEALTH-51a7",
    SUPER_NODES[1]: "SAF-0901-005-FLOWER-PARTICIPANT-B-HEALTH-92ce",
    SUPER_NODES[2]: "SAF-0901-005-FLOWER-PARTICIPANT-C-HEALTH-3d84",
}
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load pinned companion module {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def probe(kubectl, source, address):
    result = kubectl("exec", f"pod/{source}", "-c", "peer-health", "--",
                     "python", "/case/health_probe.py", f"http://{address}:8080/healthz",
                     timeout=12, allow_failure=True)
    try:
        observed = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        observed = {"result": "no-json-observation"}
    return {"exit_code": result.returncode, "observation": observed}


def stable_pair(kubectl, source, address, *, reachable, marker=None):
    samples = []
    consecutive = 0
    for _ in range(8):
        sample = probe(kubectl, source, address)
        observation = sample["observation"]
        if reachable:
            match = (observation.get("result") == "response"
                     and observation.get("status") == 200
                     and observation.get("body") == marker)
        else:
            match = (observation.get("result") == "no-response"
                     and observation.get("failure_class") == "TimeoutError")
        samples.append(sample)
        consecutive = consecutive + 1 if match else 0
        if consecutive == 2:
            return True, samples[-2:]
        time.sleep(0.4)
    return False, samples[-2:]


def policy_spec():
    return {
        "podSelector": {"matchLabels": {"fixture": FLOWER_LABEL, "flower-role": "supernode"}},
        "policyTypes": ["Egress"],
        "egress": [
            {"to": [{"namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": "kube-system"}},
                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
             "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]},
            {"to": [{"podSelector": {"matchLabels": {"flower-role": "superlink"}}}],
             "ports": [{"protocol": "TCP", "port": 9092}]},
        ],
    }


def add_health_sidecar(resource):
    pod_spec = resource["spec"]
    pod_spec.setdefault("volumes", []).append({"name": "peer-health-source", "configMap": {
        "name": HEALTH_CONFIG,
        "items": [{"key": "health_server.py", "path": "health_server.py"},
                  {"key": "health_probe.py", "path": "health_probe.py"}],
    }})
    pod_spec["containers"].append(container(
        "peer-health", image=PYTHON_IMAGE, imagePullPolicy="IfNotPresent",
        command=["python", "/case/health_server.py"],
        env=[{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
             {"name": "SAF_FIXTURE_NAME", "value": resource["metadata"]["name"]},
             {"name": "SAF_HEALTH_MARKER", "value": HEALTH_MARKERS[resource["metadata"]["name"]]}],
        ports=[{"name": "peer-health", "containerPort": 8080}],
        resources={"requests": {"cpu": "10m", "memory": "24Mi"},
                   "limits": {"cpu": "100m", "memory": "64Mi"}},
        volumeMounts=[{"name": "peer-health-source", "mountPath": "/case", "readOnly": True}],
        securityContext={"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                         "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                         "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
    ))


def run(lab):
    for name, checksum in FLOWER_SHA256.items():
        path = FLOWER_CASE.parent / name
        if not path.is_file() or sha256(path.read_bytes()).hexdigest() != checksum:
            lab.block(f"The pinned Flower companion file differs: {name}")
    base = load(BASE_CASE, "saf_0901_005_original")
    base.run(lab)

    flower = load(FLOWER_CASE, "saf_0908_006_verified_companion")
    images = flower.pin_images(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": HEALTH_CONFIG}, "immutable": True,
                "data": {"health_server.py": HEALTH_SERVER.read_text(),
                         "health_probe.py": HEALTH_PROBE.read_text()}})

    original_create = lab.create
    original_kubectl = lab.kubectl
    state = {}

    def create_hook(resource, **kwargs):
        name = resource.get("metadata", {}).get("name")
        if resource.get("kind") == "Pod" and name in SUPER_NODES:
            add_health_sidecar(resource)
        return original_create(resource, **kwargs)

    def capture_and_apply_policy():
        if state:
            return
        pod_data = {}
        sidecars_validated = True
        participant_labels_valid = True
        for name in SUPER_NODES:
            obj = json.loads(original_kubectl("get", "pod", name, "-o", "json").stdout)
            pod_data[name] = {"uid": obj.get("metadata", {}).get("uid"),
                              "pod_ip": obj.get("status", {}).get("podIP")}
            labels = obj.get("metadata", {}).get("labels", {})
            participant_labels_valid = participant_labels_valid and (
                labels.get("fixture") == FLOWER_LABEL
                and labels.get("flower-role") == "supernode")
            peer = next((item for item in obj.get("spec", {}).get("containers", [])
                         if item.get("name") == "peer-health"), {})
            peer_env = {item.get("name"): item.get("value") for item in peer.get("env", [])}
            peer_status = next((item for item in obj.get("status", {}).get("containerStatuses", [])
                                if item.get("name") == "peer-health"), {})
            sidecars_validated = sidecars_validated and (
                peer.get("image") == PYTHON_IMAGE
                and peer.get("command") == ["python", "/case/health_server.py"]
                and peer_env.get("SAF_FIXTURE_NAME") == name
                and peer_env.get("SAF_HEALTH_MARKER") == HEALTH_MARKERS[name]
                and peer_status.get("ready") is True)
        if any(not row["uid"] or not row["pod_ip"] for row in pod_data.values()):
            lab.block("The exact case-owned Flower participant Pods need UID and Pod IP observations")

        inventory = json.loads(original_kubectl("get", "pods", "-l",
                                                 f"fixture={FLOWER_LABEL}", "-o", "json").stdout)
        expected_pods = set(SUPER_NODES) | {SUPERLINK}
        exact_inventory = {item.get("metadata", {}).get("name")
                           for item in inventory.get("items", [])} == expected_pods

        baseline = {}
        for source, target in ((SUPER_NODES[0], SUPER_NODES[1]),
                               (SUPER_NODES[1], SUPER_NODES[0])):
            ok, samples = stable_pair(original_kubectl, source,
                                      pod_data[target]["pod_ip"], reachable=True,
                                      marker=HEALTH_MARKERS[target])
            baseline[f"{source}_to_{target}"] = {"matched": ok, "samples": samples}

        expected = policy_spec()
        policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                  "metadata": {"name": NETWORK_POLICY}, "spec": expected}
        created = original_kubectl("create", "-f", "-", "-o", "json",
                                   payload=json.dumps(policy), timeout=30)
        policy_object = json.loads(created.stdout)
        stored = json.loads(original_kubectl("get", "networkpolicy", NETWORK_POLICY,
                                             "-o", "json").stdout)
        exact_policy = (stored.get("metadata", {}).get("uid") ==
                        policy_object.get("metadata", {}).get("uid")
                        and stored.get("spec") == expected)

        denied = {}
        for source, target in ((SUPER_NODES[0], SUPER_NODES[1]),
                               (SUPER_NODES[1], SUPER_NODES[0])):
            ok, samples = stable_pair(original_kubectl, source,
                                      pod_data[target]["pod_ip"], reachable=False)
            denied[f"{source}_to_{target}"] = {"matched": ok, "samples": samples}

        local = {}
        for name in SUPER_NODES[:2]:
            ok, samples = stable_pair(original_kubectl, name, "127.0.0.1",
                                      reachable=True, marker=HEALTH_MARKERS[name])
            local[name] = {"matched": ok, "samples": samples}

        state.update({"pod_data": pod_data, "baseline": baseline,
                      "denied": denied, "local": local,
                      "network_policy_uid": policy_object.get("metadata", {}).get("uid"),
                      "network_policy_spec_exact": exact_policy,
                      "sidecars_validated": sidecars_validated,
                      "participant_labels_valid": participant_labels_valid,
                      "exact_flower_pod_inventory": exact_inventory})
        gate_ok = (
            exact_policy
            and sidecars_validated
            and participant_labels_valid
            and exact_inventory
            and all(row.get("matched") is True for row in baseline.values())
            and len(baseline) == 2
            and all(row.get("matched") is True for row in denied.values())
            and len(denied) == 2
            and all(row.get("matched") is True for row in local.values())
            and len(local) == 2
        )
        lab.check("supplement", "Flower participant peers are isolated while local listeners remain healthy",
                  gate_ok,
                  {"policy_spec_exact": exact_policy,
                   "exact_flower_pod_inventory": exact_inventory,
                   "participant_pod_labels_exact": participant_labels_valid,
                   "fixed_health_sidecars_ready": sidecars_validated,
                   "both_peer_paths_reachable_before_policy": all(
                       row.get("matched") is True for row in baseline.values()),
                   "both_peer_paths_blocked_after_policy": all(
                       row.get("matched") is True for row in denied.values()),
                   "both_local_peer_listeners_remain_healthy": all(
                       row.get("matched") is True for row in local.values())})
        if not gate_ok:
            lab.block("Flower egress policy boundary failed; do not run the workflow without the gate")

    def kubectl_hook(*args, **kwargs):
        if (any(isinstance(arg, str) and "flwr run . fixture --stream" in arg for arg in args)
                and not state):
            lab.block("The Flower workflow cannot start before the participant egress policy gate")
        result = original_kubectl(*args, **kwargs)
        if (not state and "wait" in args and
                f"pod/{SUPER_NODES[-1]}" in args):
            capture_and_apply_policy()
        return result

    lab.create = create_hook
    lab.kubectl = kubectl_hook
    try:
        reports = flower.start_flower(lab, images)
    finally:
        lab.create = original_create
        lab.kubectl = original_kubectl
        original_kubectl("delete", "networkpolicy", NETWORK_POLICY,
                         "--ignore-not-found=true", timeout=20, allow_failure=True)
        original_kubectl("delete", "configmap", HEALTH_CONFIG,
                         "--ignore-not-found=true", timeout=20, allow_failure=True)

    checks = [check for check in lab.checks
              if check.get("claim") == "Pinned Flower SecAgg+ completes one fixed-vector round"]
    flower_round_passed = len(checks) == 1 and checks[0].get("matched") is True
    weighted_checks = [check for check in lab.checks
                       if check.get("claim") == "Flower SecAgg+ returns the fixed nonuniform 1-2-3 weighted aggregate"]
    weighted_round_passed = len(weighted_checks) == 1 and weighted_checks[0].get("matched") is True
    (lab.evidence / "flower-networkpolicy-observations.json").write_text(
        json.dumps({"case": "SAF-K8S-0901-005",
                    "scope": "pinned-flower-1.29/synthetic-peer-health/egress-policy",
                    "network_policy_uid": state.get("network_policy_uid"),
                    "participant_pods": state.get("pod_data", {}),
                    "baseline": state.get("baseline", {}),
                    "denied": state.get("denied", {}),
                    "local": state.get("local", {}),
                    "policy_spec_exact": state.get("network_policy_spec_exact") is True,
                    "exact_flower_pod_inventory": state.get("exact_flower_pod_inventory") is True,
                    "participant_pod_labels_exact": state.get("participant_labels_valid") is True,
                    "fixed_health_sidecars_ready": state.get("sidecars_validated") is True,
                    "equal_weight_round_passed_under_policy": flower_round_passed,
                    "weighted_round_passed_under_policy": weighted_round_passed},
                   sort_keys=True, indent=2) + "\n")

    if reports is None:
        lab.block("Both Flower aggregate reports are required before release verification")
    flower.verify_workload_release(lab, reports)
