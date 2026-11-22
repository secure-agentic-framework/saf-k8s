"""Evaluate synthetic skew boundaries and inspect the runner-owned lab inventory."""
import json
import importlib.util
from pathlib import Path

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("saf_k8s_0104_021_evaluator", HERE / "evaluator.py")
evaluator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evaluator)

SCOPE = (
    "Synthetic Kubernetes v1.36 component-skew boundaries, including mixed-API-server HA "
    "intersections, plus read-only version inventory from the runner-owned single-version "
    "kind v1.36.1 cluster. This does not test a mixed-version upgrade, an HA cluster, or "
    "production inventory; enterprise-wide governance and deployment-tool restrictions "
    "require separate evidence."
)


def _version(git_version):
    value = git_version[1:] if git_version.startswith("v") else git_version
    evaluator.parse_version(value)
    return value


def _image_version(container):
    image = container.get("image", "")
    tag = image.rsplit("@", 1)[0].rsplit("/", 1)[-1].rsplit(":", 1)
    if len(tag) != 2:
        raise AssertionError(f"container image has no explicit version tag: {image!r}")
    return _version(tag[1])


def _synthetic_checks(lab):
    policy = json.loads((HERE / "policy.json").read_text())
    samples = json.loads((HERE / "samples.json").read_text())["cases"]
    results = []
    for sample in samples:
        failures = evaluator.evaluate(sample["inventory"], policy)
        actual = {failure["code"] for failure in failures}
        matched = actual == set(sample.get("expected_codes", []))
        results.append({"name": sample["name"], "expected_valid": sample["expect_valid"],
                        "observed_valid": not failures, "violations": failures})
        if not matched:
            lab.block(f"synthetic sample did not match expectation: {sample['name']}")
    lab.check("red", "One-beyond synthetic samples are rejected for a policy violation",
              all(not item["expected_valid"] and not item["observed_valid"]
                  for item in results if not item["expected_valid"]),
              {"rejected_samples": [item["name"] for item in results
                                    if not item["expected_valid"]],
               "violation_codes": sorted({failure["code"] for item in results
                                          for failure in item["violations"]})})
    lab.check("green", "Supported synthetic boundaries are accepted",
              all(item["expected_valid"] and item["observed_valid"]
                  for item in results if item["expected_valid"]),
              {"accepted_samples": [item["name"] for item in results
                                    if item["expected_valid"]]})


def _live_single_version_inventory(lab):
    # Read-only Kubernetes API queries; no objects are changed by this check.
    version_info = json.loads(lab.kubectl("version", "-o", "json").stdout)
    client = _version(version_info["clientVersion"]["gitVersion"])
    server = _version(version_info["serverVersion"]["gitVersion"])
    node_data = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)
    nodes = node_data.get("items", [])
    if not nodes:
        lab.check("positive", "The lab exposes at least one node version", False, {"nodes": 0})
        return
    kubelets = []
    for node in nodes:
        name = node["metadata"]["name"]
        kubelets.append({"id": name,
                         "version": _version(node["status"]["nodeInfo"]["kubeletVersion"]),
                         "api_servers": ["lab-api"]})

    pod_data = json.loads(lab.kubectl("get", "pods", "-n", "kube-system", "-o", "json").stdout)
    control_components = {"kube-controller-manager": [], "kube-scheduler": [], "kube-proxy": []}
    for pod in pod_data.get("items", []):
        name = pod["metadata"]["name"]
        component = next((kind for kind in control_components
                          if name == kind or name.startswith(kind + "-")), None)
        if component is None:
            continue
        for container in pod.get("spec", {}).get("containers", []):
            record = {"id": name, "version": _image_version(container),
                      "api_servers": ["lab-api"]}
            if component == "kube-proxy":
                record["kubelet"] = pod.get("spec", {}).get("nodeName")
            control_components[component].append(record)

    inventory = {
        "api_servers": [{"id": "lab-api", "version": server}],
        "kubelets": kubelets,
        "kube_controller_managers": control_components["kube-controller-manager"],
        "kube_schedulers": control_components["kube-scheduler"],
        "kubectl_clients": [{"id": "lab-client", "version": client,
                             "api_servers": ["lab-api"]}],
        "kube_proxies": control_components["kube-proxy"],
    }
    missing = [key for key in ("kube_controller_managers", "kube_schedulers", "kube_proxies")
               if not inventory[key]]
    violations = evaluator.evaluate(inventory, json.loads((HERE / "policy.json").read_text()))
    observed_versions = {item["version"]
                         for group in inventory.values() if isinstance(group, list)
                         for item in group if isinstance(item, dict) and "version" in item}
    versions_match = server == "1.36.1" and all(
        entry["version"] == server
        for group in ("kubelets", "kube_controller_managers", "kube_schedulers", "kube_proxies")
        for entry in inventory[group]
    )
    summary = {"server_version": server, "client_version": client,
               "node_count": len(kubelets),
               "kubelet_versions": sorted({item["version"] for item in kubelets}),
               "controller_manager_versions": sorted({item["version"] for item in control_components["kube-controller-manager"]}),
               "scheduler_versions": sorted({item["version"] for item in control_components["kube-scheduler"]}),
               "proxy_versions": sorted({item["version"] for item in control_components["kube-proxy"]}),
               "all_observed_versions": sorted(observed_versions),
               "missing_components": missing, "skew_violations": violations}
    lab.check("positive", "Pinned lab components and the active kubectl client satisfy the version policy",
              versions_match and not missing and not violations, summary)


def run(lab):
    _synthetic_checks(lab)
    _live_single_version_inventory(lab)
