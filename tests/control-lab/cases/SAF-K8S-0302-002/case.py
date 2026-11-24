"""Defensive capability admission boundary with harmless runtime evidence."""
import json
from pathlib import Path
import re
import time

from fixtures import container, pod, ready

SCOPE = (
    "Admission of Pod regular, init, and ephemeral container capability settings, plus a "
    "drop-all versus NET_BIND_SERVICE comparison using process masks and a loopback-only "
    "low-port bind for UID 65534 and container UID 0. This case does not "
    "establish GPU approval, real-device scope, or provider behavior. Another namespace "
    "exercises native Restricted Pod Security Admission. Jobs verify the pinned NVIDIA "
    "device-plugin argument parser in help mode, without GPU registration or allocation."
)
NAMESPACE = "saf-test"
POLICY_MESSAGE = "every regular, init, and ephemeral container must drop ALL"
LOW_PORT = 80
UNPRIVILEGED_PORT_THRESHOLD = 1024
NET_BIND_SERVICE_MASK = 1 << 10


def probe_container(name, *, add=None, drop=None, command=None):
    fields = {"drop": ["ALL"] if drop is None else drop}
    if add is not None:
        fields["add"] = add
    return container(name, command=command or ["sh", "-c", "sleep 3600"],
                     securityContext={
                         "allowPrivilegeEscalation": False,
                         "capabilities": fields,
                         "runAsNonRoot": True,
                         "runAsUser": 65534,
                         "seccompProfile": {"type": "RuntimeDefault"},
                     })


def workload(name, regular=None, init=None, ephemeral=None):
    obj = pod(name, regular or [probe_container("regular")],
              **({"initContainers": init} if init is not None else {}))
    obj["metadata"]["namespace"] = NAMESPACE
    if ephemeral is not None:
        obj["spec"]["ephemeralContainers"] = ephemeral
    return obj


def server_dry_run(lab, obj, *, verb="create", args=(), allow_failure=False):
    return lab.kubectl(*args, verb, "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(obj), allow_failure=allow_failure)


def denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and POLICY_MESSAGE in result.stderr)


def capability_probe_command():
    # BusyBox nc listens only on this Pod's loopback interface.  The listener is
    # stopped immediately after checking whether it could bind the low port.
    return "\n".join((
        "awk '/^CapEff:/ {print \"CAP_EFF=\" $2} /^CapBnd:/ {print \"CAP_BND=\" $2}' /proc/1/status",
        "printf 'PROBE_UID=%s\\n' \"$(id -u)\"",
        "printf 'PORT_THRESHOLD=%s\\n' \"$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start)\"",
        f"busybox nc -l -s 127.0.0.1 -p {LOW_PORT} >/dev/null 2>&1 &",
        "listener=$!",
        "sleep 1",
        "if kill -0 \"$listener\" 2>/dev/null; then",
        "  bind_exit=0",
        "  kill \"$listener\" 2>/dev/null || true",
        "  wait \"$listener\" 2>/dev/null || true",
        "else",
        "  wait \"$listener\"",
        "  bind_exit=$?",
        "fi",
        "printf 'BIND_EXIT=%s\\n' \"$bind_exit\"",
        "touch /tmp/capability-probe-complete",
        "sleep 3600",
    ))


def capability_probe_workload(name, *, uid=65534, add=None):
    probe = probe_container("probe", add=add, command=["sh", "-c", capability_probe_command()])
    probe["securityContext"]["runAsUser"] = uid
    probe["securityContext"]["runAsNonRoot"] = uid != 0
    probe["readinessProbe"] = {
        "exec": {"command": ["test", "-f", "/tmp/capability-probe-complete"]},
        "periodSeconds": 1,
    }
    obj = workload(name, [probe])
    obj["spec"]["securityContext"] = {"sysctls": [{
        "name": "net.ipv4.ip_unprivileged_port_start",
        "value": str(UNPRIVILEGED_PORT_THRESHOLD),
    }]}
    return obj


def read_capability_probe(lab, name):
    output = lab.kubectl("logs", name).stdout
    keys = {"CAP_EFF", "CAP_BND", "PROBE_UID", "PORT_THRESHOLD", "BIND_EXIT"}
    fields = dict(re.findall(r"^([A-Z_]+)=(\S+)$", output, re.MULTILINE))
    if not keys <= fields.keys():
        lab.block(f"Capability probe output was incomplete for {name}: {output.strip()}")
    return {
        "cap_eff": fields["CAP_EFF"].lower(),
        "cap_bnd": fields["CAP_BND"].lower(),
        "uid": int(fields["PROBE_UID"]),
        "port_threshold": int(fields["PORT_THRESHOLD"]),
        "bind_exit": int(fields["BIND_EXIT"]),
    }


def run(lab):
    case_dir = Path(__file__).parent
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/capability-reference=enabled")
    bad_regular = workload("saf-0302-002-bad-regular", [probe_container(
        "regular", add=["FOWNER"], drop=["ALL"])])
    bad_init = workload("saf-0302-002-bad-init", init=[probe_container(
        "initializer", add=["FOWNER"], drop=["ALL"], command=["sh", "-c", "exit 0"])])

    for label, obj in (("regular", bad_regular), ("init", bad_init)):
        before = server_dry_run(lab, obj, allow_failure=True)
        lab.check("red", f"API accepts out-of-set {label} capability before policy",
                  before.returncode == 0, before.stderr.strip() or "server dry-run accepted")

    lab.apply(case_dir / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        regular_result = server_dry_run(lab, bad_regular, allow_failure=True)
        if denied(regular_result) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    init_result = server_dry_run(lab, bad_init, allow_failure=True)
    for label, result in (("regular", regular_result), ("init", init_result)):
        lab.check("green", f"Admission denies out-of-set {label} capability",
                  denied(result), result.stderr.strip())

    missing_drop = workload("saf-0302-002-missing-drop",
                            [probe_container("regular", drop=[])])
    missing = server_dry_run(lab, missing_drop, allow_failure=True)
    lab.check("green", "Admission denies omission of the drop-all rule",
              denied(missing), missing.stderr.strip())
    single = workload("saf-0302-002-single-approved",
                      [probe_container("regular", add=["NET_BIND_SERVICE"])])
    allowed = server_dry_run(lab, single, allow_failure=True)
    lab.check("positive", "Admission accepts an explicit approved capability",
              allowed.returncode == 0, allowed.stderr.strip() or "server dry-run admitted")

    variants = (
        ("saf-0302-002-cap-eff-drop-all", 65534, False, False),
        ("saf-0302-002-cap-eff-net-bind-service", 65534, True, False),
        ("saf-0302-002-root-drop-all", 0, False, False),
        ("saf-0302-002-root-net-bind-service", 0, True, True),
    )
    for name, uid, add, _ in variants:
        lab.create(capability_probe_workload(name, uid=uid, add=["NET_BIND_SERVICE"] if add else None))
    observations = {}
    for name, uid, add, effective in variants:
        ready(lab, name)
        observed = read_capability_probe(lab, name)
        observations[name] = observed
        lab.check("positive", f"{name} matches the pinned runtime process masks and low-port bind result",
                  observed["uid"] == uid
                  and observed["port_threshold"] == UNPRIVILEGED_PORT_THRESHOLD
                  and int(observed["cap_bnd"], 16) == (NET_BIND_SERVICE_MASK if add else 0)
                  and int(observed["cap_eff"], 16) == (NET_BIND_SERVICE_MASK if effective else 0)
                  and (observed["bind_exit"] == 0) == effective,
                  observed)
    (lab.evidence / "capability-observations.json").write_text(
        json.dumps({"port": LOW_PORT, "unprivileged_port_threshold": UNPRIVILEGED_PORT_THRESHOLD,
                    "observations": observations},
                   sort_keys=True, indent=2) + "\n")

    # Ephemeral containers are checked on the dedicated subresource. This input is
    # a server dry-run only and is never persisted or launched.
    patch = {"spec": {"ephemeralContainers": [probe_container(
        "ephemeral-probe", add=["FOWNER"], drop=["ALL"],
        command=["sh", "-c", "sleep 1"])]}}
    eph_result = lab.kubectl(
        "patch", "pod", "saf-0302-002-cap-eff-drop-all", "--subresource=ephemeralcontainers",
        "--type=merge", "--patch", json.dumps(patch), "--dry-run=server", "-o", "json",
        allow_failure=True)
    lab.check("green", "Ephemeral-container subresource denies out-of-set capability",
              denied(eph_result), eph_result.stderr.strip())

    namespace = "saf-native-restricted"
    args = ("-n", namespace)
    lab.kubectl("create", "namespace", namespace)
    lab.kubectl("label", "namespace", namespace,
                "pod-security.kubernetes.io/enforce=restricted",
                "pod-security.kubernetes.io/enforce-version=v1.36")
    fresh = workload("native-restricted-probe", [probe_container("fixture", add=["NET_BIND_SERVICE"])])
    fresh["metadata"]["namespace"] = namespace
    good = server_dry_run(lab, fresh, args=args, allow_failure=True)
    # The case's own allowlist permits CHOWN. The native Restricted policy is narrower.
    fresh["spec"]["containers"][0]["securityContext"]["capabilities"]["add"] = ["CHOWN"]
    bad = server_dry_run(lab, fresh, args=args, allow_failure=True)
    native_denial = (bad.returncode != 0 and 'violates PodSecurity "restricted:v1.36"' in bad.stderr
                     and "CHOWN" in bad.stderr)
    lab.check("green", "Native Restricted admission accepts only its permitted add-back in the comparison",
              good.returncode == 0 and native_denial,
              {"net_bind_service_admitted": good.returncode == 0, "chown_denied_by_restricted": native_denial})

    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("saf_nvidia_cli", case_dir / "nvidia_cli.py")
    vendor = module_from_spec(spec)
    spec.loader.exec_module(vendor)
    vendor.run(lab)
