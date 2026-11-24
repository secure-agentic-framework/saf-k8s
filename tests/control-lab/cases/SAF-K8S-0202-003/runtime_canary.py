"""Rehearse a digest-pinned containerd daemon update on one owned Kind worker."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time

from fixtures import container, pod


VERSION = "2.3.7"
ARCHIVE_HASH = {
    "arm64": "e08530c6c8a23c612606da5d2832aed9bed8fc7f8c1b41df0f148a701b931d69",
    "amd64": "09a1b669ac6d21e7e24c3c33a9805b48987ba5845e8d88f039c47013a0c0025c",
}
RUNTIME_ENDPOINT = "unix:///run/containerd/containerd.sock"
BINARY = "/usr/local/bin/containerd"
STAGED_BINARY = BINARY + ".saf-verified-update"
ORIGINAL_BINARY = BINARY + ".saf-original"
WORKER_ROLE = "worker"


def worker_exec(lab, *command, **options):
    return lab.command("docker", "exec", f"{lab.cluster}-{WORKER_ROLE}", *command, **options)


def release_binary(lab, architecture, directory):
    archive = directory / f"containerd-{VERSION}-linux-{architecture}.tar.gz"
    if architecture not in ARCHIVE_HASH:
        lab.block("The verified daemon archive must match the owned worker architecture")
    source = f"https://github.com/containerd/containerd/releases/download/v{VERSION}/{archive.name}"
    lab.command("curl", "-q", "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--connect-timeout", "15", "--max-time", "100", "--output",
                str(archive), source, timeout=110)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    if checksum != ARCHIVE_HASH[architecture]:
        lab.block("The downloaded containerd archive did not match the reviewed digest")
    with tarfile.open(archive, "r:gz") as artifacts:
        member = artifacts.getmember("bin/containerd")
        if not member.isfile() or not 1_000_000 <= member.size <= 100_000_000:
            lab.block("The reviewed archive did not contain the expected daemon binary")
        binary = artifacts.extractfile(member).read()
    return binary, checksum


def stage_binary(lab, binary):
    node = f"{lab.cluster}-{WORKER_ROLE}"
    worker_exec(lab, "test", "!", "-e", STAGED_BINARY)
    result = subprocess.run(
        ["docker", "exec", "-i", node, "sh", "-ceu",
         'set -C; umask 077; cat > "$1"; chmod 0755 "$1"', "sh", STAGED_BINARY],
        input=binary, capture_output=True, env=lab.env, timeout=40,
    )
    if result.returncode:
        lab.block("The verified binary could not be staged inside the owned worker")
    checksum = worker_exec(lab, "sha256sum", STAGED_BINARY).stdout.split()[0]
    if checksum != hashlib.sha256(binary).hexdigest():
        lab.block("The worker staged binary did not match the artifact")


def installed_runtime(lab):
    worker = f"{lab.cluster}-{WORKER_ROLE}"
    status = lab.kubectl("get", "node", worker, "-o", "json").stdout
    row = json.loads(status)
    return row["metadata"]["uid"], row["status"]["nodeInfo"]


def runtime_ready(lab, expected, node_uid):
    worker = f"{lab.cluster}-{WORKER_ROLE}"
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        version = worker_exec(lab, "crictl", "--runtime-endpoint", RUNTIME_ENDPOINT, "version",
                              allow_failure=True, timeout=12)
        uid, info = installed_runtime(lab)
        matches = (re.search(r"(?m)^RuntimeVersion:\s+v?" + re.escape(expected) + r"\s*$", version.stdout)
                   and re.search(r"(?m)^RuntimeApiVersion:\s+v1\s*$", version.stdout))
        if uid == node_uid and not version.returncode and matches and (
            info["containerRuntimeVersion"] == f"containerd://{expected}"
        ):
            lab.kubectl("wait", "--for=condition=Ready", f"node/{worker}", "--timeout=25s")
            return
        time.sleep(1)
    lab.block("The worker did not report the expected live daemon version through CRI v1 and the Node API")


def canary_workload(lab, stage):
    name = f"runtime-canary-{stage}"
    worker = f"{lab.cluster}-{WORKER_ROLE}"
    marker = container("marker",
                       command=["sh", "-ceu", 'test "$(id -u)" = 65534; printf "runtime-canary-ok\\n"'],
                       resources={"requests": {"cpu": "5m", "memory": "2Mi"},
                                  "limits": {"cpu": "25m", "memory": "16Mi"}})
    lab.create(pod(name, [marker], nodeSelector={"kubernetes.io/hostname": worker},
                   automountServiceAccountToken=False))
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=60s", timeout=70)
    ran = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    output = lab.kubectl("logs", name, "-c", "marker").stdout.strip()
    return ran["spec"].get("nodeName") == worker and output == "runtime-canary-ok"


def verify_runtime_canary(lab):
    node_uid, info = installed_runtime(lab)
    before = info["containerRuntimeVersion"].removeprefix("containerd://")
    if before != "2.3.1":
        lab.block("The pinned canary expects the reviewed 2.3.1 daemon on the disposable worker")
    # Restrict the update to the executable actually owned by containerd.service.
    worker_exec(lab, "sh", "-ceu",
                'pid=$(systemctl show --property=MainPID --value containerd.service); '
                'test "$(readlink -f "/proc/$pid/exe")" = "$1"; test ! -e "$2"',
                "sh", BINARY, ORIGINAL_BINARY)
    original_digest = worker_exec(lab, "sha256sum", BINARY).stdout.split()[0]
    runtime_ready(lab, before, node_uid)
    before_ok = canary_workload(lab, "before")
    lab.check("red", "The owned canary worker starts workloads on its original daemon before the update",
              before_ok, {"daemon": before, "cri_api": "v1", "canary_completed": before_ok})
    with tempfile.TemporaryDirectory(prefix="saf-containerd-canary-") as temporary:
        binary, checksum = release_binary(lab, info["architecture"], Path(temporary))
        try:
            stage_binary(lab, binary)
            worker_exec(lab, "sh", "-ceu",
                        'test ! -e "$2"; cp -p "$1" "$2"; mv "$3" "$1"; '
                        'systemctl restart containerd.service',
                        "sh", BINARY, ORIGINAL_BINARY, STAGED_BINARY, timeout=45)
            runtime_ready(lab, VERSION, node_uid)
            upgraded = canary_workload(lab, "updated")
            lab.check("green", "The exact worker reports the reviewed daemon through CRI v1 and starts a new canary",
                      upgraded, {"daemon": VERSION, "cri_api": "v1", "canary_completed": upgraded,
                                 "release_archive_sha256": checksum})
        finally:
            worker_exec(lab, "sh", "-ceu",
                        'if test -f "$2"; then mv "$2" "$1"; systemctl restart containerd.service; fi; '
                        'rm -f -- "$3"', "sh", BINARY, ORIGINAL_BINARY, STAGED_BINARY, timeout=45)
    runtime_ready(lab, before, node_uid)
    restored = canary_workload(lab, "restored")
    exact_original = worker_exec(lab, "sha256sum", BINARY).stdout.split()[0] == original_digest
    lab.check("positive", "The exact restored daemon serves CRI v1 and starts a separate recovery canary",
              restored and exact_original, {"daemon": before, "cri_api": "v1",
                                            "canary_completed": restored, "original_binary_restored": exact_original})
