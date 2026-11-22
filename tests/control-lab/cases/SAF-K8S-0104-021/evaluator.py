"""Data-driven evaluator for the Kubernetes v1.36 component skew policy."""
import re


VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse_version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError(f"version must be a stable x.y.z value: {value!r}")
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def _failure(code, component, instance, related, detail):
    return {"code": code, "component": component, "instance": instance,
            "related": related, "detail": detail}


def evaluate(inventory, policy):
    """Return policy violations; unknown references and malformed inventory fail closed."""
    violations = []
    api_servers = inventory.get("api_servers", [])
    if not isinstance(api_servers, list) or not api_servers:
        return [_failure("api_server_required", "api_server", None, None,
                         "inventory must contain at least one API server")]

    parsed = {}
    groups = {"api_server": api_servers}
    for group_name in ("kubelets", "kube_controller_managers", "cloud_controller_managers", "kube_schedulers",
                       "kubectl_clients", "kube_proxies"):
        groups[group_name] = inventory.get(group_name, [])

    for group_name, entries in groups.items():
        if not isinstance(entries, list):
            violations.append(_failure("invalid_group", group_name, None, None,
                                       "component group must be a list"))
            groups[group_name] = []
            continue
        seen = set()
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                violations.append(_failure("invalid_instance", group_name, None, None,
                                           "each instance needs a string id and version"))
                continue
            identity = entry["id"]
            if identity in seen:
                violations.append(_failure("duplicate_instance", group_name, identity, None,
                                           "instance ids must be unique within a component group"))
                continue
            seen.add(identity)
            try:
                parsed[(group_name, identity)] = parse_version(entry.get("version"))
            except ValueError as error:
                violations.append(_failure("invalid_version", group_name, identity, None,
                                           str(error)))

    api_by_id = {entry["id"]: entry for entry in api_servers
                 if isinstance(entry, dict) and isinstance(entry.get("id"), str)}
    api_versions = {identity: parsed[("api_server", identity)]
                    for identity in api_by_id if ("api_server", identity) in parsed}
    rule = policy["minor_version_rules"]

    if api_versions:
        minors = [version[1] for version in api_versions.values()]
        spread = max(minors) - min(minors)
        if any(version[0] != next(iter(api_versions.values()))[0]
               for version in api_versions.values()) or spread > rule["api_server_ha_max_spread"]:
            violations.append(_failure("api_server_ha_spread", "api_server", "all",
                                       sorted(api_versions),
                                       f"HA API server spread is {spread} minor versions"))

    def targets(entry, component, identity):
        refs = entry.get("api_servers")
        if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) for ref in refs):
            violations.append(_failure("api_server_target_required", component, identity, None,
                                       "instance must list every API server it can communicate with"))
            return []
        missing = [ref for ref in refs if ref not in api_versions]
        if missing:
            violations.append(_failure("unknown_api_server", component, identity, missing,
                                       "target references an absent or invalid API server"))
        return [(ref, api_versions[ref]) for ref in refs if ref in api_versions]

    def compare(entry, group, component, max_behind=None, max_distance=None,
                must_not_exceed=False):
        identity = entry["id"]
        version = parsed.get((group, identity))
        if version is None:
            return
        if component in ("kubelet", "kube-proxy") and version[:2] < (1, 25):
            max_behind = rule["legacy_node_component_max_behind"]
        for api_id, api_version in targets(entry, component, identity):
            if version[0] != api_version[0]:
                violations.append(_failure("major_version_mismatch", component, identity,
                                           api_id, "major versions must match"))
                continue
            delta = version[1] - api_version[1]
            if must_not_exceed and delta > 0:
                violations.append(_failure("newer_than_api_server", component, identity,
                                           api_id, f"{component} is {delta} minor versions newer"))
            if max_behind is not None and delta < -max_behind:
                violations.append(_failure("too_old_for_api_server", component, identity,
                                           api_id, f"{component} is {-delta} minor versions older"))
            if max_distance is not None and abs(delta) > max_distance:
                violations.append(_failure("outside_api_server_distance", component, identity,
                                           api_id, f"distance is {abs(delta)} minor versions"))

    for entry in groups.get("kubelets", []):
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            compare(entry, "kubelets", "kubelet",
                    max_behind=rule["kubelet_api_server_max_behind"],
                    must_not_exceed=rule["kubelet_must_not_exceed_api_server"])
    for group, component, behind_key in (
            ("kube_controller_managers", "kube-controller-manager", "kube_controller_manager_api_server_max_behind"),
            ("cloud_controller_managers", "cloud-controller-manager", "kube_controller_manager_api_server_max_behind"),
            ("kube_schedulers", "kube-scheduler", "kube_scheduler_api_server_max_behind")):
        for entry in groups.get(group, []):
            if isinstance(entry, dict) and isinstance(entry.get("id"), str):
                compare(entry, group, component,
                        max_behind=rule[behind_key],
                        must_not_exceed=rule["control_plane_must_not_exceed_api_server"])
    for entry in groups.get("kubectl_clients", []):
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            compare(entry, "kubectl_clients", "kubectl",
                    max_distance=rule["kubectl_max_distance_from_each_api_server"])

    kubelet_versions = {entry["id"]: parsed[("kubelets", entry["id"])]
                        for entry in groups.get("kubelets", [])
                        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
                        and ("kubelets", entry["id"]) in parsed}
    for entry in groups.get("kube_proxies", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            continue
        identity = entry["id"]
        compare(entry, "kube_proxies", "kube-proxy",
                max_behind=rule["kube_proxy_api_server_max_behind"],
                must_not_exceed=rule["kube_proxy_must_not_exceed_api_server"])
        proxy_version = parsed.get(("kube_proxies", identity))
        node_id = entry.get("kubelet")
        node_version = kubelet_versions.get(node_id) if isinstance(node_id, str) else None
        if node_version is None:
            violations.append(_failure("unknown_kubelet", "kube-proxy", identity, node_id,
                                       "proxy must identify its colocated kubelet"))
        elif proxy_version:
            if proxy_version[0] != node_version[0]:
                violations.append(_failure("major_version_mismatch", "kube-proxy", identity,
                                           node_id, "major versions must match its kubelet"))
            else:
                max_distance = (rule["legacy_node_component_max_behind"] if proxy_version[:2] < (1, 25)
                                else rule["kube_proxy_kubelet_max_absolute_distance"])
                if abs(proxy_version[1] - node_version[1]) > max_distance:
                    violations.append(_failure("outside_kubelet_distance", "kube-proxy", identity,
                                               node_id, "proxy/kubelet distance exceeds policy"))

    return violations
