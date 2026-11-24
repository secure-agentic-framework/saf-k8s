"""Check the patched kube-proxy path on an owned, disposable Kind node."""
import argparse
import json
from pathlib import Path
import re
import sys
import time

import yaml

RUNNER = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RUNNER))
import lab as harness
from fixtures import container, pod

CONTROL = "SAF-K8S-0205-009"
LOCAL_NODE_VERSION = "v1.36.6"
SCOPE = (
    "One disposable upstream Kubernetes v1.36.6 Kind control plane. Observe the "
    "pre-existing higher conntrack limit, configure a smaller minimum with optional "
    "timeout writes disabled, and roll out the native kube-proxy without privileged "
    "mode using only NET_ADMIN. Check its read-only proc sysctl mount and a new "
    "fixture ClusterIP route. The test only reads the node's sysctl directly."
)
LIMIT = "net.netfilter.nf_conntrack_max"
CONFIG = {"maxPerCore": 1, "min": 1024, "tcpEstablishedTimeout": "0s",
          "tcpCloseWaitTimeout": "0s", "udpTimeout": "0s", "udpStreamTimeout": "0s",
          "tcpBeLiberal": False}
PROFILE = {"privileged": False, "runAsUser": 0, "allowPrivilegeEscalation": False,
           "capabilities": {"drop": ["ALL"], "add": ["NET_ADMIN"]},
           "readOnlyRootFilesystem": False, "seccompProfile": {"type": "RuntimeDefault"}}


def api(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def node(lab, *args):
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", *args, timeout=30).stdout.strip()


def capacity(lab):
    return int(node(lab, "sysctl", "-n", LIMIT))


def proxy(lab):
    listed = api(lab, "-n", "kube-system", "get", "pods", "-l", "k8s-app=kube-proxy")["items"]
    return [x for x in listed if not x["metadata"].get("deletionTimestamp")]


def route(lab, name):
    service = lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                          "spec": {"selector": {"fixture.saf/conntrack": "backend"},
                                   "ports": [{"port": 8080, "targetPort": 8080}]}})
    address = service["spec"]["clusterIP"]
    for _ in range(18):
        result = lab.kubectl("exec", "fixture-conntrack-reader", "--", "wget", "-q", "-T", "2", "-O", "-",
                             f"http://{address}:8080/", allow_failure=True, timeout=12)
        if result.returncode == 0 and result.stdout == "owned-proxy-marker":
            return {"name": name, "uid": service["metadata"]["uid"], "ip": address, "served": True}
        time.sleep(0.4)
    return {"name": name, "uid": service["metadata"]["uid"], "ip": address, "served": False}


def measure_process(lab, chosen):
    statuses = chosen["status"]["containerStatuses"]
    current = next(x for x in statuses if x["name"] == "kube-proxy")
    runtime_id = current["containerID"].split("://", 1)[1]
    info = json.loads(node(lab, "crictl", "inspect", runtime_id))
    pid = int(info["info"]["pid"])
    status = node(lab, "cat", f"/proc/{pid}/status")
    mask = int(re.search(r"(?m)^CapEff:\s+([0-9a-f]+)$", status).group(1), 16)
    mounts = node(lab, "cat", f"/proc/{pid}/mountinfo")
    sysctl_mount = [r for r in (line.split() for line in mounts.splitlines()) if r[4] == "/proc/sys"]
    mount_read_only = len(sysctl_mount) == 1 and "ro" in sysctl_mount[0][5].split(",")
    return {"runtime_id": runtime_id, "pid": pid, "effective_capabilities": mask,
            "proc_sys_read_only": mount_read_only, "container_ready": current["ready"]}


def run(lab):
    cohort = api(lab, "get", "nodes")["items"]
    if len(cohort) != 1 or cohort[0]["metadata"]["name"] != lab.cluster + "-control-plane":
        lab.block("Expected one owned Kind node")
    if cohort[0]["status"]["nodeInfo"]["kubeletVersion"] != LOCAL_NODE_VERSION:
        lab.block("Unexpected kubelet version for the patched proxy check")
    original = proxy(lab)
    if len(original) != 1:
        lab.block("Expected a single native kube-proxy")
    baseline_proxy = original[0]
    baseline_spec = next(x for x in baseline_proxy["spec"]["containers"] if x["name"] == "kube-proxy")
    if not baseline_spec["image"].endswith(f":{LOCAL_NODE_VERSION}") or not baseline_proxy["spec"]["hostNetwork"]:
        lab.block("The native proxy image or network profile differs from the patched fixture")

    serve = pod("fixture-conntrack-backend", [container(
        "http", command=["sh", "-ec", "mkdir -p /tmp/web; printf owned-proxy-marker >/tmp/web/index.html; "
                         "exec httpd -f -p 8080 -h /tmp/web"])], automountServiceAccountToken=False)
    serve["metadata"]["labels"] = {"fixture.saf/conntrack": "backend"}
    lab.create(serve)
    lab.create(pod("fixture-conntrack-reader", [container("client")], automountServiceAccountToken=False))
    lab.kubectl("wait", "--for=condition=Ready", "pod/fixture-conntrack-backend", "pod/fixture-conntrack-reader",
                "--timeout=95s", timeout=105)
    prior = route(lab, "proxy-before-hardening")
    initial = capacity(lab)
    target = max(int(node(lab, "nproc", "--all")), CONFIG["min"])
    red = {"native_route_served": prior["served"], "baseline_is_higher_than_configured_target": initial > target,
           "baseline_proxy_privileged": baseline_spec.get("securityContext", {}).get("privileged") is True}
    lab.check("red", "The default proxy serves the fixture route with a pre-existing higher limit",
              all(red.values()), red)

    system_config = api(lab, "-n", "kube-system", "get", "configmap", "kube-proxy")
    selected = yaml.safe_load(system_config["data"]["config.conf"])
    if "conntrack" not in selected or selected["kind"] != "KubeProxyConfiguration":
        lab.block("The Kind fixture has no recognized kube-proxy configuration")
    selected["conntrack"] = CONFIG
    selected["iptables"]["localhostNodePorts"] = False
    selected["logging"]["verbosity"] = 4
    change = json.dumps({"data": {"config.conf": yaml.safe_dump(selected)}})
    lab.kubectl("-n", "kube-system", "patch", "configmap", "kube-proxy", "--type=merge", "--patch", change)
    template = {"spec": {"template": {"spec": {"containers": [{
        "name": "kube-proxy", "securityContext": PROFILE
    }]}}}}
    lab.kubectl("-n", "kube-system", "patch", "daemonset", "kube-proxy", "--type=strategic",
                "--patch", json.dumps(template))
    rolled = lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kube-proxy",
                         "--timeout=75s", timeout=85, allow_failure=True)
    if rolled.returncode:
        lab.kubectl("-n", "kube-system", "logs", "-l", "k8s-app=kube-proxy", "--all-containers=true",
                    "--tail=60", allow_failure=True)
        lab.block("The restricted patched proxy did not become Ready")
    health = None
    for _ in range(16):
        health = lab.command("docker", "exec", f"{lab.cluster}-control-plane",
                             "curl", "--fail", "--silent", "--show-error", "--max-time", "2",
                             "http://127.0.0.1:10256/healthz", allow_failure=True, timeout=8)
        if health.returncode == 0:
            break
        time.sleep(0.7)
    if health is None or health.returncode:
        pods = proxy(lab)
        for item in pods:
            name = item["metadata"]["name"]
            lab.kubectl("-n", "kube-system", "logs", name, "--tail=80", allow_failure=True)
            lab.kubectl("-n", "kube-system", "logs", name, "--previous", "--tail=80", allow_failure=True)
        lab.block("The replacement pod did not become a healthy native kube-proxy")
    listed = proxy(lab)
    if len(listed) != 1:
        lab.block("Expected only the replacement kube-proxy")
    chosen = listed[0]
    final_spec = next(x for x in chosen["spec"]["containers"] if x["name"] == "kube-proxy")
    try:
        actual = measure_process(lab, chosen)
    except harness.InfrastructureError:
        name = chosen["metadata"]["name"]
        lab.kubectl("-n", "kube-system", "logs", name, "--tail=80", allow_failure=True)
        lab.kubectl("-n", "kube-system", "logs", name, "--previous", "--tail=80", allow_failure=True)
        raise
    after_restart = capacity(lab)
    green = {"proxy_replaced": chosen["metadata"]["uid"] != baseline_proxy["metadata"]["uid"],
             "exact_profile_active": final_spec.get("securityContext") == PROFILE,
             "effective_net_admin_only": actual["effective_capabilities"] == (1 << 12),
             "sysctl_files_read_only_to_proxy": actual["proc_sys_read_only"],
             "configured_higher_limit_preserved_after_restart": initial == after_restart and initial > target}
    lab.check("green", "The restarted restricted proxy preserves the pre-existing higher limit",
              all(green.values()), green)

    fresh = route(lab, "proxy-after-hardening")
    after_traffic = capacity(lab)
    positive = {"new_cluster_ip_served": fresh["served"] and prior["ip"] != fresh["ip"],
                "proxy_still_ready": actual["container_ready"],
                "configured_higher_limit_preserved_during_traffic": after_traffic == initial}
    lab.check("positive", "The restricted proxy programs a new owned ClusterIP and retains the limit",
              all(positive.values()), positive)
    logs = lab.kubectl("-n", "kube-system", "logs", chosen["metadata"]["name"], "--tail=70").stdout
    result = {"control": CONTROL, "patch": LOCAL_NODE_VERSION, "baseline": red, "restricted": green,
              "positive": positive}
    raw = {"result": result, "node_uid": cohort[0]["metadata"]["uid"],
           "proxy_uids": [baseline_proxy["metadata"]["uid"], chosen["metadata"]["uid"]],
           "node_kernel": node(lab, "uname", "-r"), "configuration": CONFIG,
           "initial_limit": initial, "requested_target_bound": target,
           "after_restart": after_restart, "after_traffic": after_traffic,
           "actual_process": actual, "routes": [prior, fresh], "proxy_log_tail": logs.splitlines()}
    for name, value in (("kube-proxy-conntrack-raw.json", raw), ("kube-proxy-conntrack-normalized.json", result)):
        (lab.evidence / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-node-image", required=True)
    parser.add_argument("--docker-context", default="desktop-linux")
    parser.add_argument("--catalog-index", type=Path, default=RUNNER / "catalog/index.json")
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.local_node_image):
        parser.error("Pass the full verified Docker image ID")
    return harness.run(CONTROL, sys.modules[__name__], json.loads(args.catalog_index.read_text()),
                       args.docker_context, local_node_image=args.local_node_image)


if __name__ == "__main__":
    raise SystemExit(main())
