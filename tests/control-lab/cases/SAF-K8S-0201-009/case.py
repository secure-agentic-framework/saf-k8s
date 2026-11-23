"""Verify effective kubelet service restrictions and fresh Pod operation on Kind."""

import json
import time

SCOPE = "Apply a systemd drop-in only to the kubelet on a disposable Kind node and observe its effective process state."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
DROPIN = "/etc/systemd/system/kubelet.service.d/99-saf-unit-fixture.conf"
NET_RAW = 1 << 13
PUBLIC = "systemd fixture marker"


def node(lab, *args, **kwargs):
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", *args, **kwargs)


def observe(lab):
    raw = node(lab, "systemctl", "show", "kubelet.service", "--property=MainPID",
               "--property=NoNewPrivileges", "--property=PrivateTmp").stdout
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
    return {"pid": pid, "nnp": status["NoNewPrivs"].strip() == "1",
            "raw_socket_capability_bounded": not (effective & NET_RAW),
            "private_mount_namespace": kubelet_mount.stdout.strip() != init_mount,
            "unit_nnp": unit["NoNewPrivileges"] == "yes", "unit_private_tmp": unit["PrivateTmp"] == "yes"}


def install(lab):
    node(lab, "test", "!", "-e", DROPIN)
    node(lab, "mkdir", "-p", DROPIN.rsplit("/", 1)[0])
    config = "[Service]\nNoNewPrivileges=yes\nPrivateTmp=yes\nCapabilityBoundingSet=~CAP_NET_RAW\n"
    lab.command("docker", "exec", "-i", f"{lab.cluster}-control-plane", "tee", DROPIN, payload=config)
    node(lab, "systemctl", "daemon-reload")
    node(lab, "systemctl", "restart", "kubelet.service", timeout=25)


def fresh_job(lab):
    name = "fixture-kubelet-unit-marker"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {"marker": PUBLIC}})
    unit = {"name": "marker", "image": IMAGE, "command": ["python", "-c",
             "from pathlib import Path; print(Path('/fixture/marker').read_text())"],
            "volumeMounts": [{"name": "marker", "mountPath": "/fixture", "readOnly": True}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "48Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name}, "spec": {
        "backoffLimit": 0, "template": {"spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [unit], "volumes": [{"name": "marker", "configMap": {"name": name}}]}}}})
    lab.kubectl("wait", "--for=condition=Complete", "job/" + name, "--timeout=55s", timeout=65)
    return lab.kubectl("logs", "job/" + name).stdout.strip() == PUBLIC


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    before = observe(lab)
    if before is None:
        lab.block("The owned baseline kubelet was not running under systemd")
    baseline = not before["nnp"] and not before["raw_socket_capability_bounded"]
    lab.check("red", "The pinned baseline does not apply the selected privilege settings",
              baseline, {"baseline_nnp": before["nnp"], "baseline_raw_capability_bounded": before["raw_socket_capability_bounded"]})
    install(lab)
    deadline = time.monotonic() + 35
    after = None
    while time.monotonic() < deadline:
        after = observe(lab)
        if after and after["pid"] != before["pid"]:
            break
        time.sleep(0.7)
    if not after:
        lab.block("The hardened kubelet process was not available after restart")
    result = {key: value for key, value in after.items() if key != "pid"}
    result["new_process"] = after["pid"] != before["pid"]
    lab.check("green", "The new kubelet actually runs with no new privileges and a reduced capability bound",
              all(result.values()), result)
    target = f"{lab.cluster}-control-plane"
    lab.kubectl("wait", "--for=condition=Ready", "node/" + target, "--timeout=60s", timeout=70)
    consumed = fresh_job(lab)
    lab.check("positive", "The hardened kubelet starts and completes a new marker workload",
              consumed, {"fresh_restricted_job_completed": consumed, "marker_mount_readable": consumed})
    (lab.evidence / "kubelet-systemd-observations.json").write_text(json.dumps({
        "runtime_settings": result, "fresh_pod_completed": consumed, "production_host_tested": False,
    }, indent=2) + "\n")
