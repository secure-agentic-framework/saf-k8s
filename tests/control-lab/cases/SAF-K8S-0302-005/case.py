"""Compare an unconfined baseline with a confined CPU-only AI-shaped fixture."""
import json
from pathlib import Path
import time

from fixtures import pod

HERE = Path(__file__).parent
IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)
PROFILE_NAME = "saf-k8s-0302-005/ai-cpu-deny-uname.json"
PROFILE_PATH = f"/var/lib/kubelet/seccomp/{PROFILE_NAME}"

PROBE = r'''
import ctypes
import errno
import os
from pathlib import Path
import time
import sys

uname_nr = int(sys.argv[1])
expected_uname = sys.argv[2]
expected_root_write = sys.argv[3]
libc = ctypes.CDLL(None, use_errno=True)

uname_result = libc.syscall(uname_nr, ctypes.create_string_buffer(4096))
if uname_result == 0:
    uname_state = "allowed"
elif uname_result == -1 and ctypes.get_errno() == errno.EPERM:
    uname_state = "EPERM"
else:
    raise SystemExit(f"unexpected uname syscall result: {uname_result}, errno={ctypes.get_errno()}")
if uname_state != expected_uname:
    raise SystemExit(f"expected uname={expected_uname}, got {uname_state}")

pid = libc.syscall(int(sys.argv[4]))
if pid <= 0:
    raise SystemExit(f"getpid should be permitted, got {pid}")

root_probe = Path("/saf-root-write-probe")
try:
    with root_probe.open("x") as stream:
        stream.write("synthetic\n")
    root_write = "allowed"
    root_probe.unlink()
except OSError as error:
    root_write = "EROFS" if error.errno == errno.EROFS else f"errno-{error.errno}"
if root_write != expected_root_write:
    raise SystemExit(f"expected root_write={expected_root_write}, got {root_write}")

scratch = Path("/scratch/saf-k8s-0302-005-marker")
scratch.write_text("synthetic\n")
if scratch.read_text() != "synthetic\n":
    raise SystemExit("scratch readback mismatch")
scratch.unlink()

seccomp = next(line.split()[1] for line in Path("/proc/self/status").read_text().splitlines()
               if line.startswith("Seccomp:"))
print(f"uid={os.geteuid()} seccomp={seccomp} uname={uname_state} "
      f"getpid=allowed root_write={root_write} scratch_write=ok")
'''

SCOPE = (
    "One synthetic CPU-only Python workload on the lab's pinned Kubernetes v1.36.1 kind "
    "node/containerd: red baseline runs as root with a writable root filesystem and "
    "RuntimeDefault; green runs as UID 65534 with readOnlyRootFilesystem, dropped "
    "capabilities, no privilege escalation, and a case-owned Localhost seccomp profile "
    "that returns EPERM only for uname. The fixture confirms getpid and an emptyDir scratch "
    "write remain permitted. Server-dry-run admission samples cover the exact profile and "
    "read-only-root guard for regular/init containers on Pod CREATE and ephemeral containers "
    "on pods/ephemeralcontainers UPDATE. GPU ioctl, shared GPU memory, RDMA verbs, hardware "
    "integration, production profile discovery, and provider/runtime variants are not exercised."
)


def workload(name, *, hardened, uname_nr, getpid_nr):
    args = ["python3", "-c", PROBE, str(uname_nr),
            "EPERM" if hardened else "allowed",
            "EROFS" if hardened else "allowed", str(getpid_nr)]
    security = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    }
    if hardened:
        security.update({
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "readOnlyRootFilesystem": True,
            "seccompProfile": {"type": "Localhost", "localhostProfile": PROFILE_NAME},
        })
    else:
        security["seccompProfile"] = {"type": "RuntimeDefault"}

    app = {
        "name": "cpu-fixture",
        "image": IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": args,
        "securityContext": security,
        "resources": {
            "requests": {"cpu": "25m", "memory": "64Mi"},
            "limits": {"cpu": "100m", "memory": "128Mi"},
        },
        "volumeMounts": [{"name": "scratch", "mountPath": "/scratch"}],
    }
    spec = {
        "restartPolicy": "Never",
        "activeDeadlineSeconds": 60,
        "terminationGracePeriodSeconds": 1,
        "automountServiceAccountToken": False,
        "containers": [app],
        "volumes": [{"name": "scratch", "emptyDir": {"sizeLimit": "8Mi"}}],
    }
    if hardened:
        spec["securityContext"] = {
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "fsGroup": 65534,
        }
    obj = pod(name, [app], **{key: value for key, value in spec.items()
                              if key not in ("containers", "restartPolicy")})
    obj["metadata"]["namespace"] = "saf-test"
    return obj


def _admission_probe(lab, scenario, result, *, denied):
    accepted = result.returncode == 0
    marker = "the fixture requires its exact profile and a read-only root filesystem"
    policy_denial = marker in result.stderr
    correct = (not accepted and policy_denial) if denied else accepted
    lab.check(
        "green" if denied else "positive",
        f"{scenario} is {'denied by' if denied else 'accepted by'} the workload policy",
        correct,
        {
            "admission_outcome": "accepted" if accepted else "denied",
            "expected_policy_denial": denied,
            "policy_denial_marker": policy_denial,
        },
    )
    return {
        "scenario": scenario,
        "expected": "denied" if denied else "accepted",
        "observed": "accepted" if accepted else "denied",
        "policy_denial_marker": policy_denial,
    }


def _server_dry_run_create(lab, obj):
    return lab.create(obj, dry_run=True, allow_failure=True)


def _server_dry_run_ephemeral(lab, pod_name, container):
    patch = {"spec": {"ephemeralContainers": [container]}}
    return lab.kubectl(
        "patch", f"pod/{pod_name}", "-n", "saf-test",
        "--subresource=ephemeralcontainers", "--type=merge",
        "--dry-run=server", "-p", json.dumps(patch), "-o", "name",
        allow_failure=True,
    )


def install_profile(lab, node, architecture):
    policy = json.loads((HERE / "profiles/deny-uname.json").read_text())
    policy["architectures"] = [architecture]
    lab.command("docker", "exec", node, "mkdir", "-p", str(Path(PROFILE_PATH).parent))
    lab.command("docker", "exec", "-i", node, "sh", "-ceu",
                'cat > "$1"; chmod 0444 "$1"', "fixture-profile", PROFILE_PATH,
                payload=json.dumps(policy))


def run(lab):
    node = f"{lab.cluster}-control-plane"
    machine = lab.command("docker", "exec", node, "uname", "-m").stdout.strip()
    architecture, uname_nr, getpid_nr = {
        "x86_64": ("SCMP_ARCH_X86_64", 63, 39),
        "aarch64": ("SCMP_ARCH_AARCH64", 160, 172),
    }.get(machine, (None, None, None))
    if architecture is None:
        lab.block(f"No syscall-number mapping for the fixture node architecture {machine!r}")

    # This is the same harmless syscall oracle under RuntimeDefault before the
    # profile is installed and requested.
    baseline = workload("ai-cpu-red", hardened=False,
                        uname_nr=uname_nr, getpid_nr=getpid_nr)
    lab.create(baseline)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/ai-cpu-red",
                "--timeout=30s", timeout=40)
    red = lab.kubectl("logs", "ai-cpu-red", "-c", "cpu-fixture").stdout.strip()
    lab.check("red", "RuntimeDefault baseline permits uname and root filesystem writes",
              red == "uid=0 seccomp=2 uname=allowed getpid=allowed "
              "root_write=allowed scratch_write=ok", red)

    install_profile(lab, node, architecture)
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "pod-security.kubernetes.io/enforce-version=v1.36",
                "saf-k8s.example/cpu-profile-enforcement=enabled")
    psa_only = workload("ai-cpu-psa-only", hardened=True, uname_nr=uname_nr, getpid_nr=getpid_nr)
    settings = psa_only["spec"]["containers"][0]["securityContext"]
    settings["readOnlyRootFilesystem"] = False
    settings["seccompProfile"] = {"type": "RuntimeDefault"}
    allowed = lab.create(psa_only, dry_run=True, allow_failure=True)
    lab.check("red", "Restricted PSA admits a non-root fixture with RuntimeDefault and writable rootfs",
              allowed.returncode == 0, {"admitted_by_restricted_psa": allowed.returncode == 0})

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 25
    while True:
        blocked = lab.create(psa_only, dry_run=True, allow_failure=True)
        if blocked.returncode or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    deny = blocked.returncode != 0 and "(Forbidden)" in blocked.stderr and (
        "the fixture requires its exact profile and a read-only root filesystem" in blocked.stderr
    )
    lab.check("green", "Workload-specific admission rejects the exact weaker configuration",
              deny, {"expected_workload_policy_denial": deny})

    # Admission-only samples use server dry-run. The normal container is
    # compliant in each sample so the mutation isolates the init/ephemeral
    # container path under test.
    admission_observations = []
    compliant = workload("ai-cpu-admission-positive", hardened=True,
                         uname_nr=uname_nr, getpid_nr=getpid_nr)
    admission_observations.append(_admission_probe(
        lab, "compliant regular container", _server_dry_run_create(lab, compliant), denied=False
    ))

    init_compliant = workload("ai-cpu-init-positive", hardened=True,
                              uname_nr=uname_nr, getpid_nr=getpid_nr)
    init_app = dict(init_compliant["spec"]["containers"][0])
    init_app["name"] = "cpu-init-fixture"
    init_compliant["spec"]["initContainers"] = [init_app]
    admission_observations.append(_admission_probe(
        lab, "compliant init container", _server_dry_run_create(lab, init_compliant), denied=False
    ))

    init_weaker = workload("ai-cpu-init-negative", hardened=True,
                           uname_nr=uname_nr, getpid_nr=getpid_nr)
    init_app = dict(init_weaker["spec"]["containers"][0])
    init_app["name"] = "cpu-init-fixture"
    init_app["securityContext"] = dict(init_app["securityContext"])
    init_app["securityContext"]["readOnlyRootFilesystem"] = False
    init_weaker["spec"]["initContainers"] = [init_app]
    admission_observations.append(_admission_probe(
        lab, "init container with writable root filesystem",
        _server_dry_run_create(lab, init_weaker), denied=True,
    ))
    init_wrong_profile = workload("ai-cpu-init-wrong-profile", hardened=True,
                                  uname_nr=uname_nr, getpid_nr=getpid_nr)
    init_app = dict(init_wrong_profile["spec"]["containers"][0])
    init_app["name"] = "cpu-init-fixture"
    init_app["securityContext"] = dict(init_app["securityContext"])
    init_app["securityContext"]["seccompProfile"] = {"type": "RuntimeDefault"}
    init_wrong_profile["spec"]["initContainers"] = [init_app]
    admission_observations.append(_admission_probe(
        lab, "init container with a non-exact seccomp profile",
        _server_dry_run_create(lab, init_wrong_profile), denied=True,
    ))

    green_pod = workload("ai-cpu-green", hardened=True,
                         uname_nr=uname_nr, getpid_nr=getpid_nr)
    lab.create(green_pod)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/ai-cpu-green",
                "--timeout=30s", timeout=40)
    green = lab.kubectl("logs", "ai-cpu-green", "-c", "cpu-fixture").stdout.strip()
    lab.check("green", "Non-root read-only workload receives EPERM for uname only",
              green == "uid=65534 seccomp=2 uname=EPERM getpid=allowed "
              "root_write=EROFS scratch_write=ok", green)
    lab.check("positive", "The confined fixture can call getpid and write its bounded emptyDir",
              "getpid=allowed" in green and "scratch_write=ok" in green,
              {"getpid": "allowed" if "getpid=allowed" in green else "not observed",
               "scratch_write": "ok" if "scratch_write=ok" in green else "not observed"})

    # The pod is an already-created, case-owned compliant target; both
    # ephemeral-container requests are server dry-runs and leave it unchanged.
    ephemeral_base = {
        "name": "cpu-ephemeral-fixture",
        "image": IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "securityContext": dict(green_pod["spec"]["containers"][0]["securityContext"]),
        "targetContainerName": "cpu-fixture",
    }
    admission_observations.append(_admission_probe(
        lab, "compliant ephemeral container",
        _server_dry_run_ephemeral(lab, "ai-cpu-green", ephemeral_base), denied=False,
    ))
    ephemeral_weaker = dict(ephemeral_base)
    ephemeral_weaker["securityContext"] = dict(ephemeral_base["securityContext"])
    ephemeral_weaker["securityContext"]["readOnlyRootFilesystem"] = False
    admission_observations.append(_admission_probe(
        lab, "ephemeral container with writable root filesystem",
        _server_dry_run_ephemeral(lab, "ai-cpu-green", ephemeral_weaker), denied=True,
    ))
    ephemeral_wrong_profile = dict(ephemeral_base)
    ephemeral_wrong_profile["securityContext"] = dict(ephemeral_base["securityContext"])
    ephemeral_wrong_profile["securityContext"]["seccompProfile"] = {"type": "RuntimeDefault"}
    admission_observations.append(_admission_probe(
        lab, "ephemeral container with a non-exact seccomp profile",
        _server_dry_run_ephemeral(lab, "ai-cpu-green", ephemeral_wrong_profile), denied=True,
    ))

    # Retain normalized observations only: no cluster/node names, timestamps,
    # raw API errors, or other run-specific strings enter the evidence file.
    (lab.evidence / "cpu-profile-admission-observations.json").write_text(
        json.dumps({
            "schema": "saf-k8s-0302-005/admission-observations-v1",
            "admission_baseline": {
                "restricted_psa_admitted_weaker_request": allowed.returncode == 0,
                "workload_policy_denied_weaker_request": deny,
            },
            "runtime": {
                "baseline": red,
                "confined": green,
            },
            "server_dry_run": admission_observations,
        }, indent=2, sort_keys=True) + "\n"
    )
