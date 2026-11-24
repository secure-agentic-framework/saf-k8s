"""Verify effective kubelet service restrictions and fresh Pod operation on Kind."""

import json
from pathlib import Path
import time

SCOPE = (
    "Pinned IPv4 Kind v1.36.1. Compare the actual kubelet service's process state and a "
    "harmless unit-start probe before and after scoped capability, path and socket-family "
    "constraints. Keep its approved ConfigMap workload operating and restore the original unit."
)
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
DROPIN = "/etc/systemd/system/kubelet.service.d/99-saf-unit-fixture.conf"
NET_RAW = 1 << 13
PROBE_DIR = "/run/saf-unit-proof"
PROTECTED = f"{PROBE_DIR}/protected"
MARKER_PREFIX = "SAF-UNIT-PROBE "
BASELINE_PROBE = {
    "protected_read": "matched", "protected_write": "wrote", "permitted_write": "wrote",
    "unix_socket": "opened", "ipv4_socket": "opened", "ipv6_socket": "opened",
}
HARDENED_PROBE = {**BASELINE_PROBE, "protected_write": "read-only", "ipv6_socket": "unsupported-family"}
PUBLIC = "systemd fixture marker"


def node(lab, *args, **kwargs):
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", *args, **kwargs)


def observe(lab):
    raw = node(lab, "systemctl", "show", "kubelet.service", "--property=MainPID",
               "--property=NoNewPrivileges", "--property=PrivateTmp", "--property=InvocationID",
               "--property=ReadOnlyPaths", "--property=RestrictAddressFamilies").stdout
    unit = dict(line.split("=", 1) for line in raw.splitlines())
    pid = int(unit["MainPID"])
    if not pid:
        return None
    output = node(lab, "cat", f"/proc/{pid}/status", allow_failure=True)
    if output.returncode:
        return None
    status = dict(line.split(":", 1) for line in output.stdout.splitlines() if ":" in line)
    if status["Name"].strip() != "kubelet":
        return None
    init_mount = node(lab, "readlink", "/proc/1/ns/mnt").stdout.strip()
    kubelet_mount = node(lab, "readlink", f"/proc/{pid}/ns/mnt", allow_failure=True)
    if kubelet_mount.returncode:
        return None
    effective = int(status["CapBnd"].strip(), 16)
    mount_flags = node(lab, "awk", "-v", f"path={PROTECTED}", '$5 == path {print $6}',
                       f"/proc/{pid}/mountinfo", allow_failure=True)
    if mount_flags.returncode:
        return None
    return {"pid": pid, "invocation_id": unit["InvocationID"], "capability_mask": effective,
            "protected_mount_readonly": "ro" in mount_flags.stdout.strip().split(","),
            "unit_readonly_path": unit["ReadOnlyPaths"] == PROTECTED,
            "unit_ipv6_deny": unit["RestrictAddressFamilies"] == "~AF_INET6",
            "nnp": status["NoNewPrivs"].strip() == "1",
            "raw_socket_capability_bounded": not (effective & NET_RAW),
            "private_mount_namespace": kubelet_mount.stdout.strip() != init_mount,
            "unit_nnp": unit["NoNewPrivileges"] == "yes", "unit_private_tmp": unit["PrivateTmp"] == "yes"}


def put(lab, path, data):
    lab.command("docker", "exec", "-i", f"{lab.cluster}-control-plane", "tee", path, payload=data)


def install_probe(lab):
    node(lab, "test", "!", "-e", DROPIN)
    node(lab, "test", "!", "-e", PROBE_DIR)
    node(lab, "install", "-d", "-m", "0700", PROBE_DIR)
    node(lab, "mkdir", "-p", DROPIN.rsplit("/", 1)[0])
    put(lab, f"{PROBE_DIR}/probe.pl", Path(__file__).with_name("probe.pl").read_text())


def wait_process(lab, previous):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        result = observe(lab)
        if result and result["pid"] != previous["pid"] and result["invocation_id"] != previous["invocation_id"]:
            return result
        time.sleep(0.7)
    lab.block("A new kubelet process and invocation did not become observable")


def launch(lab, previous, hardened):
    for path in (PROTECTED, f"{PROBE_DIR}/permitted"):
        put(lab, path, "owned marker\n")
    profile = ["[Service]", f"ExecStartPost=/usr/bin/perl {PROBE_DIR}/probe.pl"]
    if hardened:
        profile.extend(("NoNewPrivileges=yes", "PrivateTmp=yes", "CapabilityBoundingSet=~CAP_NET_RAW",
                        f"ReadOnlyPaths={PROTECTED}", "RestrictAddressFamilies=~AF_INET6"))
    put(lab, DROPIN, "\n".join(profile) + "\n")
    node(lab, "systemctl", "daemon-reload")
    node(lab, "systemctl", "restart", "kubelet.service", timeout=40)
    state = wait_process(lab, previous)
    evidence = node(lab, "journalctl", "--no-pager", "-o", "cat", "--grep", "^SAF-UNIT-PROBE ",
                    f"_SYSTEMD_INVOCATION_ID={state['invocation_id']}").stdout
    rows = [line.removeprefix(MARKER_PREFIX) for line in evidence.splitlines() if line.startswith(MARKER_PREFIX)]
    if len(rows) != 1:
        lab.block("Expected one unit probe result for the observed kubelet invocation")
    return state, dict(field.split("=", 1) for field in rows[0].split())


def fresh_job(lab, target):
    name = "fixture-kubelet-unit-marker"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {"marker": PUBLIC}})
    unit = {"name": "marker", "image": IMAGE, "command": ["python", "-c",
             "from pathlib import Path; print(Path('/fixture/marker').read_text())"],
            "volumeMounts": [{"name": "marker", "mountPath": "/fixture", "readOnly": True}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "48Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name}, "spec": {
        "backoffLimit": 0, "template": {"spec": {"nodeName": target, "automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [unit], "volumes": [{"name": "marker", "configMap": {"name": name}}]}}}})
    lab.kubectl("wait", "--for=condition=Complete", "job/" + name, "--timeout=55s", timeout=65)
    return lab.kubectl("logs", "job/" + name).stdout.strip() == PUBLIC


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    target = f"{lab.cluster}-control-plane"
    node_object = json.loads(lab.kubectl("get", "node", target, "-o", "json").stdout)
    node_info = node_object["status"]["nodeInfo"]
    if any(":" in cidr for cidr in node_object["spec"]["podCIDRs"]):
        lab.block("The IPv6-family-denial example requires an IPv4 fixture node")
    kindnet = json.loads(lab.kubectl("-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    cni_images = [image["image"] for image in kindnet["spec"]["template"]["spec"]["containers"]]
    platform = {"kindnet_images": cni_images, "systemd": node(lab, "systemctl", "--version").stdout.splitlines()[0],
                "kernel": node_info["kernelVersion"], "runtime": node_info["containerRuntimeVersion"],
                "os_image": node_info["osImage"], "architecture": node_info["architecture"],
                "kubelet": node_info["kubeletVersion"]}
    before = observe(lab)
    if before is None:
        lab.block("The owned baseline kubelet was not running under systemd")
    install_probe(lab)
    try:
        baseline, original = launch(lab, before, False)
        lab.check("red", "The same unit probe can write the owned marker and open IPv6 at baseline",
                  original == BASELINE_PROBE and not baseline["nnp"] and not baseline["protected_mount_readonly"]
                  and not baseline["raw_socket_capability_bounded"],
                  {"probe": original, "selected_runtime_restrictions_absent": (
                      not baseline["nnp"] and not baseline["protected_mount_readonly"]
                      and not baseline["raw_socket_capability_bounded"])})
        after, restricted = launch(lab, baseline, True)
        flags = {key: value for key, value in after.items()
                 if key not in {"pid", "invocation_id", "capability_mask"}}
        exact_mask = after["capability_mask"] == baseline["capability_mask"] & ~NET_RAW
        lab.check("green", "The running kubelet has the exact new capability bound and protected file mount",
                  all(flags.values()) and exact_mask,
                  {"runtime_restrictions": flags, "exact_capability_delta": exact_mask})
        lab.check("green", "The same service probe reports exact file and socket restrictions with permitted controls",
                  restricted == HARDENED_PROBE, {"probe": restricted})
        lab.kubectl("wait", "--for=condition=Ready", "node/" + target, "--timeout=60s", timeout=70)
        consumed = fresh_job(lab, target)
        lab.check("positive", "The hardened kubelet completes a fresh restricted ConfigMap marker Job",
                  consumed, {"fresh_restricted_job_completed": consumed})
    finally:
        node(lab, "rm", "--", DROPIN)
        node(lab, "systemctl", "daemon-reload")
        node(lab, "systemctl", "restart", "kubelet.service", timeout=40)

    restored = wait_process(lab, after)
    cleared = (restored["capability_mask"] == before["capability_mask"]
               and restored["nnp"] == before["nnp"] and not restored["unit_readonly_path"]
               and not restored["unit_ipv6_deny"] and not restored["protected_mount_readonly"])
    lab.check("positive", "Removing the fixture drop-in restores the original effective restrictions",
              cleared, {"original_policy_restored": cleared})
    (lab.evidence / "kubelet-systemd-observations.json").write_text(json.dumps({
        "platform": platform, "runtime_settings": flags,
        "baseline_capability_mask": format(baseline["capability_mask"], "x"),
        "hardened_capability_mask": format(after["capability_mask"], "x"),
        "baseline_probe": original, "hardened_probe": restricted,
        "fresh_pod_completed": consumed, "original_policy_restored": cleared,
        "deployment_scope": "owned disposable IPv4 Kind node",
    }, indent=2) + "\n")
