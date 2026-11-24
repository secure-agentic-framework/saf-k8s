"""Observe debug listener removal while the pinned container runtime still serves CRI."""

import json
import re

SCOPE = (
    "On disposable Kind v1.36.1, compare an owned containerd diagnostic Unix socket "
    "and a separately approved local HTTP metrics listener supplied by a config import. "
    "Verify the respective disabled states and CRI v1 over the actual Unix endpoint, "
    "then start a fresh marker Job. "
    "Restore the node's original runtime configuration."
)
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
CONFIG = "/etc/containerd/config.toml"
SOCKET = "/run/containerd/saf-debug-fixture.sock"
MARKER = "new runtime marker"
METRICS_PORT = "18741"
METRICS_ADDRESS = f"127.0.0.1:{METRICS_PORT}"
CRI_ENDPOINT = "unix:///run/containerd/containerd.sock"
ADDRESS = re.compile(r'(?m)^[ \t]*address[ \t]*=[ \t]*(["\'])([^"\']*)\1')


def node(lab, *args, **kwargs):
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", *args, **kwargs)


def interface_section(source, name):
    modern = rf"plugins\.['\"]io\.containerd\.server\.v1\.{name}['\"]"
    for header in (modern, name):
        section = re.search(rf"(?ms)^[ \t]*\[{header}\][^\n]*\n.*?(?=^[ \t]*\[|\Z)", source)
        if section:
            return section
    return None


def address_setting(source, name):
    section = interface_section(source, name)
    match = ADDRESS.search(section.group()) if section else None
    return match.group(2) if match else ""


def interface_address(source, name, address):
    found = interface_section(source, name)
    line = f'  address = "{address}"'
    if found is None:
        is_v4 = re.search(r"(?m)^version\s*=\s*4\b", source)
        header = f'plugins."io.containerd.server.v1.{name}"' if is_v4 else name
        return source.rstrip() + f"\n\n[{header}]\n{line}\n"
    original = found.group()
    edited, count = ADDRESS.subn(line, original)
    if not count:
        edited = original.replace("\n", f"\n{line}\n", 1)
    return source[:found.start()] + edited + source[found.end():]


def apply(lab, profile):
    lab.command("docker", "exec", "-i", f"{lab.cluster}-control-plane", "sh", "-ceu",
                'stage=$(mktemp "$1.saf-fixture.XXXXXX"); trap "rm -f -- \"$stage\"" EXIT; '
                'cat > "$stage"; chmod --reference="$1" "$stage"; mv "$stage" "$1"; '
                'systemctl restart containerd.service', "sh", CONFIG, payload=profile, timeout=35)
    return node(lab, "containerd", "--config", CONFIG, "config", "dump", timeout=20).stdout


def debug_listener(lab):
    return any(SOCKET in line.split() for line in node(lab, "ss", "-xlH").stdout.splitlines())


def metrics_listeners(lab):
    output = node(lab, "ss", "-lntH", f"sport = :{METRICS_PORT}").stdout
    return [line.split()[3] for line in output.splitlines()]


def cri_ready(lab):
    command = ("crictl", "--runtime-endpoint", CRI_ENDPOINT)
    status = node(lab, *command, "info", "-o", "json", timeout=25).stdout
    conditions = json.loads(status)["status"]["conditions"]
    version = node(lab, *command, "version", timeout=25).stdout
    return bool(re.search(r"(?m)^RuntimeApiVersion:\s+v1\s*$", version)) and any(
        item["type"] == "RuntimeReady" and item["status"] is True for item in conditions
    )


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
    original_profile = node(lab, "containerd", "--config", CONFIG, "config", "dump").stdout
    version = node(lab, "containerd", "--version").stdout.split()
    if metrics_listeners(lab):
        lab.block("The dedicated loopback port is already in use in the owned node")
    version_line = re.search(r"(?m)^version[ \t]*=[ \t]*[234][ \t]*$", config)
    imports = re.search(r"(?m)^imports[ \t]*=[ \t]*(.*)$", config)
    if not version_line or (imports and imports.group(1).strip() != "[]"):
        lab.block("The pinned fixture needs a versioned configuration with no pre-existing imports")
    source = re.sub(r"(?m)^imports[ \t]*=.*\n", "", config)
    import_file = f"/etc/containerd/{lab.cluster}-metrics.toml"
    imported = interface_address(version_line.group(), "metrics", METRICS_ADDRESS)
    with_import = f"imports = [{json.dumps(import_file)}]\n" + source
    debug_on_profile = interface_address(interface_address(with_import, "metrics", ""), "debug", SOCKET)
    debug_off_profile = interface_address(debug_on_profile, "debug", "")
    disabled = interface_address(interface_address(source, "debug", ""), "metrics", "")
    node(lab, "test", "!", "-e", import_file)
    try:
        lab.command("docker", "exec", "-i", f"{lab.cluster}-control-plane", "sh", "-ceu",
                    'set -C; umask 077; cat > "$1"', "sh", import_file, payload=imported)
        current = apply(lab, debug_on_profile)
        debug_on = address_setting(current, "debug") == SOCKET and debug_listener(lab)
        lab.check("red", "The deliberately enabled diagnostic Unix listener is active",
                  debug_on, {"fixture_diagnostic_listener_active": debug_on})
        current = apply(lab, debug_off_profile)
        debug_off = address_setting(current, "debug") == "" and not debug_listener(lab)
        lab.check("green", "The diagnostic Unix listener disappears after its address is cleared",
                  debug_off, {"fixture_diagnostic_listener_removed": debug_off})

        local_metrics = address_setting(current, "metrics") == METRICS_ADDRESS and (
            metrics_listeners(lab) == [METRICS_ADDRESS]
        )
        http = node(lab, "curl", "-q", "--silent", "--show-error", "--noproxy", "*",
                    "--max-time", "5", "--output", "/dev/null", "--write-out", "%{http_code}",
                    f"http://{METRICS_ADDRESS}/v1/metrics").stdout.strip()
        lab.check("positive", "Imported metrics configuration binds only to node loopback after diagnostics are disabled",
                  local_metrics and http == "200",
                  {"metrics_only_loopback": local_metrics, "metrics_http_status": http})

        current = apply(lab, disabled)
        metrics_off = address_setting(current, "metrics") == "" and not metrics_listeners(lab)
        ready = cri_ready(lab)
        lab.check("green", "Removing the metrics import and clearing the address disables metrics while CRI v1 stays ready",
                  metrics_off and ready, {"metrics_listener_removed": metrics_off, "cri_v1_ready": ready})
        started = fresh_marker(lab)
        lab.check("positive", "Kubelet creates a fresh workload through the reviewed runtime profile",
                  started, {"fresh_job_completed": started})
    finally:
        try:
            current = apply(lab, config)
        finally:
            node(lab, "rm", "-f", "--", import_file)
    restored = node(lab, "cat", CONFIG).stdout == config and all(address_setting(current, kind) == address_setting(original_profile, kind)
                   for kind in ("debug", "metrics"))
    lab.check("positive", "The original runtime profile and local CRI v1 readiness are restored",
              restored and cri_ready(lab), {"original_addresses_restored": restored, "cri_v1_ready": True})
    (lab.evidence / "runtime-debug-observations.json").write_text(json.dumps({
        "runtime_version": version, "debug_listener_removed": debug_off,
        "metrics_only_loopback": local_metrics, "metrics_http_status": http,
        "metrics_listener_removed": metrics_off, "cri_v1_ready": ready,
        "fresh_workload_started": started, "original_profile_restored": restored,
    }, indent=2) + "\n")
