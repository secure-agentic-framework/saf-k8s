"""Observe debug listener removal while the pinned container runtime still serves CRI."""

import json
import re

SCOPE = "An owned Kind containerd service toggles a dedicated Unix debug listener; its normal CRI and new Pods remain functional."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
CONFIG = "/etc/containerd/config.toml"
SOCKET = "/run/containerd/saf-debug-fixture.sock"
MARKER = "new runtime marker"
DEBUG_SECTION = re.compile(r"(?ms)^\[debug\][^\n]*\n.*?(?=^\[|\Z)")
DEBUG_ADDRESS = re.compile(r'(?m)^[ \t]*address[ \t]*=[ \t]*(["\'])([^"\']*)\1')


def node(lab, *args, **kwargs):
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", *args, **kwargs)


def address_setting(source):
    plugin = re.search(
        r"""(?ms)^[ \t]*\[plugins\.['"]io\.containerd\.server\.v1\.debug['"]\][^\n]*\n.*?(?=^[ \t]*\[|\Z)""",
        source,
    )
    section = plugin or DEBUG_SECTION.search(source)
    if not section:
        return ""
    match = DEBUG_ADDRESS.search(section.group())
    return match.group(2) if match else ""


def profile(source, address):
    section = f'[debug]\n  address = "{address}"\n'
    matched = DEBUG_SECTION.search(source)
    if matched:
        original = matched.group()
        line = f'  address = "{address}"'
        edited, count = re.subn(r"(?m)^[ \t]*address[ \t]*=.*$", line, original)
        if not count:
            edited = original.replace("\n", "\n" + line + "\n", 1)
        content = source[:matched.start()] + edited + source[matched.end():]
    else:
        content = source.rstrip() + "\n\n" + section
    if address_setting(content) != address:
        raise ValueError("The selected debug listener was not serialized as intended")
    return content


def apply(lab, source, address):
    config = profile(source, address)
    lab.command("docker", "exec", "-i", f"{lab.cluster}-control-plane",
                "tee", CONFIG + ".saf-next", payload=config)
    node(lab, "mv", CONFIG + ".saf-next", CONFIG)
    node(lab, "systemctl", "restart", "containerd.service", timeout=30)
    effective = node(lab, "containerd", "config", "dump", timeout=20).stdout
    return address_setting(effective)


def listening(lab):
    sockets = node(lab, "ss", "-xlH").stdout
    return any(SOCKET in line.split() for line in sockets.splitlines())


def cri_ready(lab):
    listing = node(lab, "crictl", "info", "-o", "json", timeout=25).stdout
    conditions = json.loads(listing)["status"]["conditions"]
    return any(item["type"] == "RuntimeReady" and item["status"] is True for item in conditions)


def fresh_marker(lab):
    name = "fixture-runtime-continuity"
    unit = {"name": "unit", "image": IMAGE, "command": ["python", "-c", f"print({MARKER!r})"],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "48Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name}, "spec": {
        "backoffLimit": 0, "template": {"spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [unit]}}}})
    lab.kubectl("wait", "--for=condition=Complete", "job/" + name, "--timeout=60s", timeout=70)
    return lab.kubectl("logs", "job/" + name).stdout.strip() == MARKER


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    config = node(lab, "cat", CONFIG).stdout
    version = node(lab, "containerd", "--version").stdout.split()
    active = apply(lab, config, SOCKET)
    opened = listening(lab)
    lab.check("red", "The fixture's deliberately enabled diagnostic Unix listener is active",
              active == SOCKET and opened, {"fixture_listener_configured": active == SOCKET, "fixture_listener_active": opened})

    disabled = apply(lab, config, "") == ""
    inactive = not listening(lab)
    ready = cri_ready(lab)
    lab.check("green", "Disabling the diagnostic listener removes its socket while the required CRI stays ready",
              disabled and inactive and ready, {"debug_address_unset": disabled, "debug_listener_absent": inactive, "cri_ready": ready})
    started = fresh_marker(lab)
    lab.check("positive", "Kubelet still creates a new workload through the hardened runtime",
              started, {"fresh_job_completed": started})
    (lab.evidence / "runtime-debug-observations.json").write_text(json.dumps({
        "runtime_version": version, "listener_removed": inactive, "cri_ready": ready,
        "fresh_workload_started": started, "provider_runtime_tested": False,
    }, indent=2) + "\n")
