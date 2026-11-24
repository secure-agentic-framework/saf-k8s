"""Inspect effective metadata without issuing any runtime socket request."""
from pathlib import Path
import shutil
import subprocess
import tempfile

from fixtures import container, pod, ready
from lab import NAMESPACE


SOCKET = "/run/containerd/containerd.sock"
SOCKET_PATHS = ("/", "/run", "/run/containerd", SOCKET)
HERE = Path(__file__).resolve().parent
SCOPE = (
    "Read-only metadata, ACL availability and effective pathname permissions for the stock "
    "rootful Kind containerd socket. A separate local echo fixture exercises parent traversal, "
    "socket modes and group access. Pod Security Admission denies an inert hostPath reference, "
    "and a compliant marker Pod runs. The adopter guide covers additional runtime and provider paths."
)


def inspect(lab, node):
    metadata = {}
    for path in SOCKET_PATHS:
        status = lab.command("docker", "exec", node, "stat", "-Lc", "%F|%u|%g|%a", "--", path).stdout
        file_type, uid, gid, mode = status.strip().split("|")
        metadata[path] = {"type": file_type, "uid": int(uid), "gid": int(gid), "mode": mode}
    leaf = metadata[SOCKET]
    resolved = lab.command("docker", "exec", node, "readlink", "-f", SOCKET).stdout.strip()
    groups = lab.command("docker", "exec", "--user", "65534:65534", node, "id", "-G").stdout.split()
    allowed = lab.command("docker", "exec", "--user", "65534:65534", node,
                          "test", "-w", SOCKET, allow_failure=True)
    lab.check("positive", "Actual rootful kind socket is root-owned and fails the unrelated UID permission check",
              leaf["type"] == "socket" and leaf["uid"] == 0 and leaf["gid"] == 0
              and not (int(leaf["mode"], 8) & 0o007)
              and all(metadata[path]["type"] == "directory" for path in ("/", "/run", "/run/containerd"))
              and resolved == SOCKET and groups == ["65534"] and allowed.returncode == 1,
              {"metadata": metadata, "canonical_runtime_path": resolved == SOCKET,
               "unrelated_fixture_groups": [int(group) for group in groups],
               "unrelated_uid_permission_check_denied": allowed.returncode == 1})



def verify_workload_mount_policy(lab):
    # An inert marker path and server dry-run exercise admission only.
    marker = container("marker", volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}])
    reference = pod("fixture-socket-reference", [marker], automountServiceAccountToken=False,
                    volumes=[{"name": "fixture", "hostPath": {
                        "path": "/run/saf-inert-runtime-fixture/socket", "type": "Socket",
                    }}])
    before = lab.create(reference, dry_run=True, allow_failure=True)
    lab.check("red", "The baseline namespace admits an inert socket path reference on server dry-run",
              before.returncode == 0, {"baseline_admitted": before.returncode == 0})
    lab.kubectl("label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce=baseline",
                "pod-security.kubernetes.io/enforce-version=v1.36", "--overwrite")
    result = lab.create(reference, dry_run=True, allow_failure=True)
    blocked = result.returncode != 0 and all(
        expected in result.stderr for expected in ("(Forbidden)", "violates PodSecurity", "hostPath volumes")
    )
    lab.check("green", "Pod Security Admission rejects the inert hostPath reference",
              blocked, {"specific_hostpath_denial": blocked})
    permitted = "fixture-no-runtime-socket"
    created = lab.create(pod(permitted, [container("marker")], automountServiceAccountToken=False))
    ready(lab, permitted)
    no_hostpath = all("hostPath" not in volume for volume in created["spec"].get("volumes", []))
    lab.check("positive", "A marker Pod without host paths is admitted and reaches Ready",
              no_hostpath, {"no_hostpath": no_hostpath, "pod_ready": True})


def run(lab):
    node = f"{lab.cluster}-control-plane"
    inspect(lab, node)
    arch = lab.kubectl("get", f"node/{node}", "-o", "jsonpath={.status.nodeInfo.architecture}").stdout.strip()
    if arch not in ("amd64", "arm64") or not shutil.which("go"):
        lab.block("The synthetic Linux socket probe needs Go and amd64 or arm64 kind")
    remote = f"/usr/local/bin/{lab.cluster}-fixture-dac"
    with tempfile.TemporaryDirectory(prefix="saf-unix-echo-build-") as temporary:
        probe = Path(temporary) / "probe"
        compiled = subprocess.run(
            ["go", "build", "-trimpath", "-o", str(probe), str(HERE/"probe.go")],
            env=dict(lab.env, CGO_ENABLED="0", GOOS="linux", GOARCH=arch, GOPROXY="off",
                     GOSUMDB="off", GOTOOLCHAIN="local", GOFLAGS=""),
            capture_output=True, timeout=180,
        )
        if compiled.returncode:
            lab.block("Could not build the synthetic socket probe")
        try:
            with probe.open("rb") as compiled_probe:
                installed = subprocess.run(
                    ["docker", "exec", "-i", node, "sh", "-ceu",
                     'cat > "$1"; chmod 0755 "$1"', "fixture-install", remote],
                    env=lab.env, stdin=compiled_probe, capture_output=True, timeout=15,
                )
            if installed.returncode:
                lab.block("Could not install the benign executable on the owned kind node")
            # The fixture subprocess changes only its own temporary path metadata.
            output = lab.command("docker", "exec", node, remote, timeout=30).stdout.strip()
            acl_output = lab.command("docker", "exec", node, remote, "runtime-acls").stdout
            acls = dict(line.split("=", 1) for line in acl_output.splitlines())
        finally:
            lab.command("docker", "exec", node, "rm", "-f", remote)
    lab.check("positive", "No extended POSIX access ACL is present on the sampled runtime path",
              set(acls) == set(SOCKET_PATHS) and all(state in {"absent", "unsupported"} for state in acls.values()),
              {"access_acl_state": acls})
    outcome = dict(token.split("=", 1) for token in output.split())
    lab.check("red", "A traversable directory and permissive fixture socket allow an unrelated UID to echo",
              outcome.get("public") == "echo", {"unrelated_echo": outcome.get("public") == "echo"})
    lab.check("green", "Tightening either the parent directory or fixture socket blocks the unrelated UID",
              outcome.get("parent") == "denied" and outcome.get("mode") == "denied",
              {"parent_path_denied": outcome.get("parent") == "denied",
               "socket_mode_denied": outcome.get("mode") == "denied"})
    lab.check("positive", "The fixture socket owner can still perform the same echo",
              outcome.get("owner") == "echo", {"owner_echo": outcome.get("owner") == "echo"})
    lab.check("positive", "A non-owner can echo with the approved supplementary group and is denied without it",
              outcome.get("group") == "echo" and outcome.get("no_group") == "denied",
              {"authorized_group_echo": outcome.get("group") == "echo",
               "unapproved_principal_denied": outcome.get("no_group") == "denied"})
    verify_workload_mount_policy(lab)
