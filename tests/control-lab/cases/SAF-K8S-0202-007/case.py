"""Compare the host UID mapping for vanilla and Pod user-namespace workloads."""
import json
import re
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE, pod

SCOPE = (
    "One disposable Kind Kubernetes v1.36.1 cluster using its pinned node image and containerd CRI. "
    "Compares the kernel UID and GID mappings in default and explicit hostUsers:false Pods and observes "
    "server-side admission under a scoped opt-in policy. Corroborates the exact fixture processes in the node "
    "Linux user namespace context and checks the separate optional rootless node signal. Runtime observations apply to these "
    "workloads on this fixture. Production fleet support, exception governance, and rootless node operation "
    "require independent evidence."
)
NAMESPACE = "saf-test"
NODE_SIGNAL = "runningInUserNamespace"


def workload(name, userns=False):
    spec = {"hostUsers": False} if userns else {}
    return pod(name, [{
        "name": "probe", "image": BUSYBOX_IMAGE,
        "command": ["sh", "-c", "while :; do sleep 3600; done"],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsUser": 0, "runAsGroup": 0,
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }], automountServiceAccountToken=False, **spec)


def kernel_map(lab, pod_name, mapping):
    return parse_uid_map(lab.kubectl("exec", pod_name, "-c", "probe", "--", "cat",
                                    f"/proc/self/{mapping}_map").stdout)


def parse_uid_map(text):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 3 or not all(field.isdecimal() for field in fields):
            raise ValueError(f"Unexpected kernel ID map row: {line!r}")
        rows.append(tuple(map(int, fields)))
    return rows


def node_process(lab, name):
    pod_data = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    node = pod_data["spec"]["nodeName"]
    if node != f"{lab.cluster}-control-plane":
        lab.block("Fixture Pod was not assigned to the owned Kind control-plane node")
    container = pod_data["status"]["containerStatuses"][0]
    identifier = container["containerID"]
    if not re.fullmatch(r"containerd://[0-9a-f]{64}", identifier):
        lab.block("Expected a containerd container identity for the fixture Pod")
    runtime_id = identifier.split("://", 1)[1]
    runtime = json.loads(lab.command("docker", "exec", node, "crictl", "inspect",
                                      runtime_id).stdout)
    pid = int(runtime["info"]["pid"])
    status = runtime["status"]
    pod_uid = pod_data["metadata"]["uid"]
    if status["id"] != runtime_id or pid < 2 or status["labels"].get("io.kubernetes.pod.uid") != pod_uid:
        lab.block("Runtime container inspection did not match the owned running Pod")
    context = {}
    for key, process in (("container", pid), ("node", 1)):
        context[key] = {
            "namespace": lab.command("docker", "exec", node, "readlink",
                                     f"/proc/{process}/ns/user").stdout.strip(),
            **{mapping: parse_uid_map(lab.command("docker", "exec", node, "cat",
                                                f"/proc/{process}/{mapping}_map").stdout)
               for mapping in ("uid", "gid")},
        }
    return {"pod_uid": pod_uid, "container_id": runtime_id, "pid": pid, **context}


def run(lab):
    case_dir = Path(__file__).parent
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/require-pod-userns=enabled")
    guard = workload("admission-guard-probe")
    before = lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                         payload=json.dumps(guard), allow_failure=True)
    lab.check("red", "A workload omitting hostUsers is admitted before the guard",
              before.returncode == 0, before.stderr.strip() or "server dry-run admitted")

    vanilla = workload("vanilla")
    lab.create(vanilla)
    lab.kubectl("wait", "--for=condition=Ready", "pod/vanilla", "--timeout=95s", timeout=105)
    lab.apply(case_dir / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        rejected = lab.create(guard, dry_run=True, allow_failure=True)
        denied = (rejected.returncode != 0 and "(Forbidden)" in rejected.stderr
                  and "hostUsers must be false" in rejected.stderr)
        if denied or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The namespace guard rejects workloads without hostUsers false",
              denied, rejected.stderr.strip() or "unexpected admission success")
    explicit_host = workload("explicit-host-probe")
    explicit_host["spec"]["hostUsers"] = True
    explicit_result = lab.create(explicit_host, dry_run=True, allow_failure=True)
    explicitly_denied = (explicit_result.returncode != 0 and "(Forbidden)" in explicit_result.stderr
                         and "hostUsers must be false" in explicit_result.stderr)
    lab.check("green", "The scoped policy rejects explicit use of the host user namespace",
              explicitly_denied, {"explicit_true_denied": explicitly_denied})
    lab.kubectl("create", "namespace", "saf-userns-outside-policy")
    outside = lab.kubectl("-n", "saf-userns-outside-policy", "create", "-f", "-", "--dry-run=server",
                           payload=json.dumps(explicit_host))
    lab.check("positive", "The opt-in admission guard stays within the governed namespace",
              outside.returncode == 0, {"outside_scope_admitted": outside.returncode == 0})
    lab.create(workload("userns", True))
    lab.kubectl("wait", "--for=condition=Ready", "pod/userns", "--timeout=95s", timeout=105)
    maps = {
        pod_name: {mapping: kernel_map(lab, pod_name, mapping) for mapping in ("uid", "gid")}
        for pod_name in ("vanilla", "userns")
    }
    process_contexts = {name: node_process(lab, name) for name in ("vanilla", "userns")}
    baseline_process = process_contexts["vanilla"]
    opted_process = process_contexts["userns"]
    node_maps_initial = all(baseline_process["node"][key] == opted_process["node"][key] == [(0, 0, 4294967295)]
                            for key in ("uid", "gid"))
    contexts_match = baseline_process["node"]["namespace"] == opted_process["node"]["namespace"]
    baseline_shared = bool(baseline_process["node"]["namespace"]) and (
        baseline_process["container"]["namespace"] == baseline_process["node"]["namespace"]
    )
    opted_separate = bool(opted_process["container"]["namespace"]) and (
        opted_process["container"]["namespace"] != opted_process["node"]["namespace"]
    )
    maps_corroborate = all(process_contexts[name]["container"][key] == maps[name][key]
                           for name in maps for key in ("uid", "gid"))
    lab.check("green", "The node corroborates live Pod maps and the opted-in user namespace boundary",
              node_maps_initial and contexts_match and baseline_shared and opted_separate and maps_corroborate,
              {"node_has_initial_id_ranges": node_maps_initial, "same_node_context": contexts_match,
               "default_pod_shares_node_user_namespace": baseline_shared,
               "opted_in_pod_has_distinct_user_namespace": opted_separate,
               "node_side_maps_match_in_pod_observations": maps_corroborate})
    for mapping in ("uid", "gid"):
        default_root = any(start == 0 and host == 0 and size > 0
                           for start, host, size in maps["vanilla"][mapping])
        lab.check("red", f"Default Pod {mapping.upper()} zero maps to host ID zero",
                  default_root, {"identity_root_mapping": default_root})
        isolated = maps["userns"][mapping]
        container_root_mapped = any(start == 0 and host > 0 and size > 1
                                    for start, host, size in isolated)
        all_host_starts_nonzero = bool(isolated) and all(host > 0 and size > 0
                                                        for _, host, size in isolated)
        lab.check("green", f"Pod user namespace maps {mapping.upper()} zero to a nonzero host ID",
                  container_root_mapped and all_host_starts_nonzero,
                  {"container_root_maps_to_nonzero_host_id": container_root_mapped,
                   "all_host_ranges_have_nonzero_start": all_host_starts_nonzero})

    isolated_pod = json.loads(lab.kubectl("get", "pod", "userns", "-o", "json").stdout)
    node = json.loads(lab.kubectl("get", "node", isolated_pod["spec"]["nodeName"],
                                  "-o", "json").stdout)
    info = node.get("status", {}).get("nodeInfo", {})
    field_present = NODE_SIGNAL in info
    selection = isolated_pod["spec"].get("hostUsers")
    lab.check("positive", "The opted-in Pod runs with remapped IDs while the node rootless signal is unavailable",
              selection is False and not field_present,
              {"pod_hostUsers": selection, "node_rootless_signal_present": field_present,
               "node_rootless_classification": "unknown" if not field_present else "separate signal"})

    for pod_name in ("vanilla", "userns"):
        result = lab.kubectl("exec", pod_name, "-c", "probe", "--", "sh", "-c",
                             "test \"$(id -u)\" = 0 && test \"$(id -g)\" = 0 && printf 'busybox-ok\\n'").stdout.strip()
        lab.check("positive", f"Benign BusyBox command works as workload UID and GID zero in {pod_name}",
                  result == "busybox-ok", result)
    (lab.evidence / "pod-id-mappings.raw.json").write_text(json.dumps({
        "kernel_mappings": maps,
        "node_process_contexts": process_contexts,
        "pod_hostUsers": selection,
        "node_version": info.get("kubeletVersion"),
        "node_rootless_signal": {"present": field_present, "value": info.get(NODE_SIGNAL)},
    }, indent=2) + "\n")
