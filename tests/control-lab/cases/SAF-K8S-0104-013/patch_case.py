"""Rehearse the current pinned patch and minor upgrades on the owned node."""
import importlib.util
import json
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


original = load("case")
artifacts = load("patch_artifacts")
canary = load("userns_canary")
preflight = load("userns_preflight")
NODE_IMAGE = original.NODE_IMAGE
TARGETS = ("v1.36.7", "v1.37.3")
POD_ID = re.compile(r"(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})")
SCOPE = (
    "Single-node owned Kind rehearsal starting at v1.36.1 and applying official checksummed "
    "v1.36.7 and v1.37.3 binaries and pinned component images in version order. A read-only "
    "user-namespace preflight checks bounded on-disk allocation and runtime inputs before each "
    "change. A non-root opted-in fixture Pod keeps its UID and effective namespace mappings. "
    "Marker retention and a fixture Deployment rollback are observed. Etcd, certificate "
    "renewal, control-plane downgrade and deployment-specific recovery are outside this case."
)


def disk_inventory(lab, pod_uid):
    node = original.node
    directory = "/var/lib/kubelet/pods"
    seen = node(lab, "find", directory, "-mindepth", "1", "-maxdepth", "1",
                "-type", "d", "-printf", "%f\n", timeout=20).stdout.splitlines()
    if pod_uid not in seen or not 0 < len(seen) <= 64 or not all(POD_ID.fullmatch(uid) for uid in seen):
        lab.block("The bounded owned-node inventory did not identify the expected canary Pod")
    entries = []
    for uid in sorted(seen):
        file = f"{directory}/{uid}/userns"
        present = node(lab, "test", "-e", file, allow_failure=True)
        if present.returncode not in (0, 1):
            lab.block("Could not establish whether a persisted Pod mapping exists")
        entry = {"uid": uid}
        if present.returncode == 0:
            entry["userns"] = json.loads(node(lab, "cat", file).stdout)
        entries.append(entry)
    if not any(entry["uid"] == pod_uid and "userns" in entry for entry in entries):
        lab.block("The opted-in canary did not have a persisted mapping")
    return {"complete_read_only_inventory": True, "pods": entries}


def effective_source(lab):
    node = original.node
    account = node(lab, "getent", "passwd", "kubelet", allow_failure=True)
    helper = node(lab, "sh", "-c", "if command -v getsubids; then exit 0; else exit 1; fi", allow_failure=True)
    if account.returncode not in (0, 2) or helper.returncode not in (0, 1):
        lab.block("The owned node could not establish kubelet account or sub-ID helper presence")
    has_account, has_helper = account.returncode == 0, helper.returncode == 0
    output = {"kubelet_account_present": has_account, "getsubids_present": has_helper}
    if not has_account or not has_helper:
        output.update({"range_source": "target_default_fallback", "target_fallback_confirmed": True,
                       "fallback_reason": "helper_absent" if has_account else "account_absent"})
    else:
        executable = helper.stdout.strip()
        if re.fullmatch(r"/[A-Za-z0-9_./+-]+", executable) is None:
            lab.block("The owned node's reported helper path was malformed")
        digest = node(lab, "sha256sum", executable).stdout.split()[0]
        uids = node(lab, executable, "kubelet").stdout
        gids = node(lab, executable, "-g", "kubelet").stdout
        output.update({"range_source": "getsubids", "getsubids_uid_output": uids,
                       "getsubids_gid_output": gids, "helper_provenance": {
                           "resolved_path": executable, "package_or_build": f"sha256 {digest}",
                           "uid_command": "getsubids kubelet", "gid_command": "getsubids -g kubelet"}})
    return output


def configuration(lab, base, target, canary_state):
    node_name = lab.cluster + "-control-plane"
    config = json.loads(lab.kubectl(
        "get", "--raw", f"/api/v1/nodes/{node_name}/proxy/configz", timeout=20,
    ).stdout)["kubeletconfig"]
    observed_ids = (config.get("userNamespaces") or {}).get("idsPerPod")
    ids = 65536 if observed_ids is None else observed_ids
    inventory = disk_inventory(lab, canary_state["pod_uid"])
    events = json.loads(lab.kubectl(
        "get", "events", "--all-namespaces", "--field-selector", "reason=FailedCreatePodSandBox",
        "-o", "json", timeout=20,
    ).stdout)["items"]
    existing = {entry["uid"] for entry in inventory["pods"]}
    invalid = any(event.get("involvedObject", {}).get("uid") in existing for event in events)
    return {"observation_mode": "read_only", "source_kubelet_version": base,
            "target_kubelet_version": target, "userns_in_use": True,
            "ids_per_pod": ids, "max_pods": config["maxPods"],
            "persisted_mapping_inventory": inventory, "failed_create_pod_sandbox_event": invalid,
            **effective_source(lab)}


def run(lab):
    original.setup(lab)
    base = original.BASE
    state = canary.create_and_snapshot(lab)
    initial = original.versions(lab)
    lab.check("red", "The owned node and live canary start on the exact baseline",
              initial == {"apiserver": base, "kubelet": base} and original.marker(lab),
              {**initial, "original_workload_accessible": original.marker(lab)})
    results = []
    for target in TARGETS:
        record = configuration(lab, base, target, state)
        decision = preflight.evaluate(record)
        (lab.evidence / f"userns-{target}-preflight.raw.json").write_text(
            json.dumps({"observed": record, "decision": decision}, indent=2) + "\n")
        if decision["decision"] != "ELIGIBLE_FOR_SEPARATE_CHANGE_APPROVAL":
            lab.block(f"The versioned read-only preflight held the owned node transition: {decision['reason']}")
        pins = artifacts.stage(lab, original.node, target, original.NEW_BIN)
        plan = original.node(lab, original.KUBEADM, "upgrade", "plan", target, timeout=100)
        if base not in plan.stdout or target not in plan.stdout:
            lab.block("The exact planned kubeadm transition did not match the selected versions")
        ordered, final, exit_code = original.apply_version(lab, base, target)
        expected = {"apiserver": target, "kubelet": target}
        observed = artifacts.observe(lab, original.node, pins)
        retained = original.marker(lab)
        lab.check(
            "green", f"The owned node reaches {target} using the reviewed artifacts after a passing preflight",
            ordered and final == expected and retained and exit_code == 0
            and observed["pinned_kubelet_matches"] and observed["api_go_version_matches"]
            and observed["component_image_aliases_match"] and observed["component_payloads_match"],
            {**final, "previous": base, "pin_verified": observed["pinned_kubelet_matches"],
             "api_go_version_matches": observed["api_go_version_matches"],
             "component_image_aliases_match": observed["component_image_aliases_match"],
             "component_payloads_match": observed["component_payloads_match"], "control_plane_first": ordered,
             "retained_marker": retained, "preflight_passed": True, "explicit_target_planned": True},
        )
        next_state = canary.snapshot(lab, stage=target, expected_uid=state["pod_uid"])
        canary.check_preserved(lab, state, next_state)
        results.append({"previous": base, "target": target, "pins": pins, "observed": observed,
                        "canary_before": state, "canary_after": next_state, "kubeadm_exit": exit_code})
        state = next_state
        base = target
    original.exercise_workload_recovery(lab, {"apiserver": base, "kubelet": base})
    (lab.evidence / "patch-upgrade.raw.json").write_text(
        json.dumps({"rehearsal": results, "etcd_upgrade_tested": False,
                    "control_plane_downgrade_or_restore_tested": False}, indent=2) + "\n")
