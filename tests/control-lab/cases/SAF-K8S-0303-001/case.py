"""Exercise PSA seccomp admission and harmless seccomp runtime behavior."""
import json
from pathlib import Path

from fixtures import container, pod, ready

HERE = Path(__file__).parent
NAMESPACE = "saf-test"
PSA_VERSION = "v1.36"
LOCALHOST_PROFILE = "saf-k8s-0303-001/deny-uname.json"
DENIAL_MARKER = "seccompProfile"
MODE_COMMAND = "awk '$1 == \"Seccomp:\" {print $2}' /proc/self/status"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
UNAME_PROBE = """
import ctypes
import errno
from pathlib import Path
import sys

print(next(line for line in Path('/proc/self/status').read_text().splitlines()
           if line.startswith('Seccomp:')).split()[1])
libc = ctypes.CDLL(None, use_errno=True)
result = libc.syscall(int(sys.argv[1]), ctypes.create_string_buffer(4096))
if result == 0:
    print('uname=allowed')
elif result == -1 and ctypes.get_errno() == errno.EPERM:
    print('uname=EPERM')
    sys.exit(47)
else:
    print('unexpected uname result')
    sys.exit(48)
"""
SCOPE = (
    "PSA Restricted seccomp admission for regular, init, and ephemeral containers; Pod-level "
    "RuntimeDefault inheritance and explicit per-container RuntimeDefault are "
    "observed on a pinned kind node. A read-only custom Localhost profile denies "
    "only the uname syscall in a benign pinned Python fixture. Other runtimes, "
    "SPO lifecycle, profile rollout/rotation, and production exceptions are out of scope."
)


def seccomp(value):
    return {"seccompProfile": value}


def workload(name, *, pod_profile=None, app_profile="omit", init_profile="omit",
             app_command=None, init_command=None):
    spec = {}
    if pod_profile is not None:
        spec["securityContext"] = seccomp(pod_profile)
    app_sc = {} if app_profile == "omit" else seccomp(app_profile)
    init_sc = {} if init_profile == "omit" else seccomp(init_profile)
    app = container("app", command=app_command or ["sh", "-c", "sleep 3600"])
    if app_profile == "omit":
        app["securityContext"].pop("seccompProfile", None)
    app["securityContext"].update(app_sc)
    items = [app]
    if init_command is not None:
        init = container("init", command=init_command)
        if init_profile == "omit":
            init["securityContext"].pop("seccompProfile", None)
        init["securityContext"].update(init_sc)
        spec["initContainers"] = [init]
    obj = pod(name, items, **spec)
    obj["metadata"]["namespace"] = NAMESPACE
    return obj


def dry_run(lab, obj):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(obj), allow_failure=True)


def restricted_denial(result):
    text = result.stderr.lower()
    return (result.returncode != 0 and "(forbidden)" in text
            and "podsecurity" in text and DENIAL_MARKER.lower() in text)


def seccomp_mode(lab, pod_name, container_name):
    result = lab.kubectl("exec", pod_name, "-c", container_name, "--", "sh", "-c",
                         MODE_COMMAND)
    return result.stdout.strip()


def run(lab):
    version = f"pod-security.kubernetes.io/enforce-version={PSA_VERSION}"
    lab.kubectl("label", "namespace", NAMESPACE,
                "pod-security.kubernetes.io/enforce=baseline", version,
                "pod-security.kubernetes.io/audit=baseline",
                f"pod-security.kubernetes.io/audit-version={PSA_VERSION}",
                "pod-security.kubernetes.io/warn=baseline",
                f"pod-security.kubernetes.io/warn-version={PSA_VERSION}", "--overwrite")

    absent = workload("seccomp-missing", app_profile="omit")
    absent_result = dry_run(lab, absent)
    lab.check("red", "Baseline PSA admits a Pod without a seccomp setting",
              absent_result.returncode == 0,
              absent_result.stderr.strip() or "server dry-run accepted before enforcement")

    lab.kubectl("label", "namespace", NAMESPACE,
                "pod-security.kubernetes.io/enforce=restricted",
                "pod-security.kubernetes.io/audit=restricted",
                "pod-security.kubernetes.io/warn=restricted", "--overwrite")
    denied = dry_run(lab, absent)
    lab.check("green", "Restricted PSA rejects omitted seccomp with a seccomp-specific reason",
              restricted_denial(denied), denied.stderr.strip())

    # A pod-level profile satisfies the admission requirement for containers
    # that omit their own field. Runtime mode is read independently in each.
    inherited = workload(
        "seccomp-inherited", pod_profile={"type": "RuntimeDefault"},
        app_profile="omit", init_profile="omit", init_command=["sh", "-c", MODE_COMMAND])
    admitted = dry_run(lab, inherited)
    lab.check("positive", "Pod-level RuntimeDefault with omitted child fields is admitted",
              admitted.returncode == 0, admitted.stderr.strip() or "server dry-run accepted")
    lab.kubectl("create", "-f", "-", payload=json.dumps(inherited))
    ready(lab, "seccomp-inherited")
    mode = seccomp_mode(lab, "seccomp-inherited", "app")
    init_mode = lab.kubectl("logs", "seccomp-inherited", "-c", "init").stdout.strip()
    lab.check("positive", "App and init containers inherit RuntimeDefault and report Seccomp mode 2",
              mode == init_mode == "2", {"app": mode, "init": init_mode})

    # Per-container RuntimeDefault can satisfy Restricted when the Pod-level
    # field is absent; every regular/init container must carry the setting.
    per_container = workload(
        "seccomp-per-container", app_profile={"type": "RuntimeDefault"},
        init_profile={"type": "RuntimeDefault"}, init_command=["sh", "-c", MODE_COMMAND])
    admitted = dry_run(lab, per_container)
    lab.check("positive", "Explicit per-container RuntimeDefault passes admission",
              admitted.returncode == 0, admitted.stderr.strip() or "server dry-run accepted")
    lab.kubectl("create", "-f", "-", payload=json.dumps(per_container))
    ready(lab, "seccomp-per-container")
    mode = seccomp_mode(lab, "seccomp-per-container", "app")
    init_mode = lab.kubectl("logs", "seccomp-per-container", "-c", "init").stdout.strip()
    lab.check("positive", "Explicit RuntimeDefault reports Seccomp mode 2 in app and init containers",
              mode == init_mode == "2", {"app": mode, "init": init_mode})

    for profile in ("RuntimeDefault", "Unconfined", None):
        ephemeral = container("seccomp-ephemeral", command=["sh", "-c", MODE_COMMAND])
        if profile is None:
            del ephemeral["securityContext"]["seccompProfile"]
        else:
            ephemeral["securityContext"]["seccompProfile"] = {"type": profile}
        patch = json.dumps({"spec": {"ephemeralContainers": [ephemeral]}})
        result = lab.kubectl("patch", "pod/seccomp-per-container", "--subresource=ephemeralcontainers",
                             "--type=merge", "-p", patch, "--dry-run=server", "-o", "name",
                             allow_failure=True)
        ok = result.returncode == 0 if profile == "RuntimeDefault" else restricted_denial(result)
        lab.check("green", f"Ephemeral container admission checks {profile or 'missing'} seccomp",
                  ok, result.stderr.strip() or "server dry-run accepted")

    partial = workload(
        "seccomp-partial-container", app_profile={"type": "RuntimeDefault"},
        init_profile="omit", init_command=["sh", "-c", "exit 0"])
    partial_result = dry_run(lab, partial)
    lab.check("green", "Restricted PSA rejects one init container omitted from per-container seccomp",
              restricted_denial(partial_result), partial_result.stderr.strip())

    explicit_unconfined = workload(
        "seccomp-unconfined", app_profile={"type": "Unconfined"})
    unconfined_result = dry_run(lab, explicit_unconfined)
    lab.check("green", "Restricted PSA rejects explicit Unconfined seccomp",
              restricted_denial(unconfined_result), unconfined_result.stderr.strip())

    # Localhost admission only validates the selector. The fixture file is
    # installed on the case-owned node and made read-only. `uname` is ordinary
    # and non-destructive; same image/command under RuntimeDefault is oracle.
    node = f"{lab.cluster}-control-plane"
    machine = lab.command("docker", "exec", node, "uname", "-m").stdout.strip()
    architecture, syscall = {"aarch64": ("SCMP_ARCH_AARCH64", 160),
                             "x86_64": ("SCMP_ARCH_X86_64", 63)}.get(machine, (None, None))
    if architecture is None:
        lab.block(f"The harmless uname fixture has no syscall number recorded for {machine}")
    profile = f"/var/lib/kubelet/seccomp/{LOCALHOST_PROFILE}"
    policy = json.loads((HERE / "profiles/deny-uname.json").read_text())
    policy["architectures"] = [architecture]
    lab.command("docker", "exec", node, "mkdir", "-p", str(Path(profile).parent))
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat > "$1"; chmod 0444 "$1"',
                "fixture-profile", profile, payload=json.dumps(policy))
    probe_command = ["python3", "-c", UNAME_PROBE, str(syscall)]
    baseline = workload(
        "seccomp-uname-baseline", app_profile={"type": "RuntimeDefault"},
        app_command=probe_command)
    baseline["spec"]["containers"][0]["image"] = PYTHON
    baseline_result = dry_run(lab, baseline)
    lab.check("positive", "RuntimeDefault uname counterfactual is admitted",
              baseline_result.returncode == 0, baseline_result.stderr.strip() or "accepted")
    baseline["metadata"]["name"] = "seccomp-uname-runtime-default"
    lab.kubectl("create", "-f", "-", payload=json.dumps(baseline))
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded",
                "pod/seccomp-uname-runtime-default", "--timeout=30s", timeout=40)
    baseline_output = lab.kubectl("logs", "seccomp-uname-runtime-default", "-c", "app",
                                  allow_failure=True)

    localhost = workload(
        "seccomp-localhost-uname", app_profile={"type": "Localhost",
                                               "localhostProfile": LOCALHOST_PROFILE},
        app_command=probe_command)
    localhost["spec"]["containers"][0]["image"] = PYTHON
    local_admission = dry_run(lab, localhost)
    lab.check("positive", "Localhost profile reference passes Restricted admission",
              local_admission.returncode == 0,
              local_admission.stderr.strip() or "admitted; profile validity is runtime-side")
    lab.kubectl("create", "-f", "-", payload=json.dumps(localhost))
    waited = lab.kubectl("wait", "--for=jsonpath={.status.phase}=Failed", "pod/seccomp-localhost-uname",
                         "--timeout=30s", timeout=40, allow_failure=True)
    if waited.returncode:
        state = lab.kubectl("get", "pod/seccomp-localhost-uname", "-o", "json")
        events = lab.kubectl("get", "events", "--field-selector",
                            "involvedObject.name=seccomp-localhost-uname", "-o", "json")
        parsed = json.loads(state.stdout)["status"]
        lab.kubectl("logs", "seccomp-localhost-uname", "-c", "app", allow_failure=True)
        for row in parsed.get("containerStatuses", []):
            runtime_id = row.get("containerID", "").removeprefix("containerd://")
            if runtime_id:
                lab.command("docker", "exec", node, "sh", "-ceu",
                            'crictl inspect "$1" | jq \'{seccomp: .info.runtimeSpec.linux.seccomp}\'',
                            "fixture-oci", runtime_id, allow_failure=True)
        capture = [item.get("message") for item in json.loads(events.stdout)["items"]]
        lab.block(f"Localhost fixture phase {parsed.get('phase')}; events: {capture}")
    local_logs = lab.kubectl("logs", "seccomp-localhost-uname", "-c", "app",
                             allow_failure=True)
    local_mode_observed = "2" in local_logs.stdout.splitlines()
    local_output = local_logs.stdout + local_logs.stderr
    lab.check("green", "Custom Localhost filter denies the same harmless uname call",
              local_mode_observed and baseline_output.returncode == 0
              and baseline_output.stdout.splitlines() == ["2", "uname=allowed"]
              and local_logs.returncode == 0 and local_output.splitlines() == ["2", "uname=EPERM"],
              {"local_seccomp_mode_2": local_mode_observed,
               "runtime_default_output": baseline_output.stdout.strip(),
               "runtime_default_exit": baseline_output.returncode,
               "localhost_logs": local_output.strip()})
