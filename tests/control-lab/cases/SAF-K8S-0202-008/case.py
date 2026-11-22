"""Inspect effective metadata without issuing any runtime socket request."""
from pathlib import Path
import shutil
import subprocess
import tempfile


SOCKET = "/run/containerd/containerd.sock"
HERE = Path(__file__).resolve().parent
SCOPE = (
    "Read-only pathname metadata and DAC permission test for the stock kind containerd socket. "
    "No connection or runtime protocol operation targets that socket. On the same owned node, "
    "a separate benign synthetic socket proves the effects of parent traversal and socket "
    "permissions. External nodes, CRI-O, rootless deployments, additional host ACLs and "
    "workload mount controls remain separate."
)


def inspect(lab, node):
    metadata = {}
    for path in ("/", "/run", "/run/containerd", SOCKET):
        status = lab.command("docker", "exec", node, "stat", "-Lc", "%F|%u|%g|%a", "--", path).stdout
        file_type, uid, gid, mode = status.strip().split("|")
        metadata[path] = {"type": file_type, "uid": int(uid), "gid": int(gid), "mode": mode}
    leaf = metadata[SOCKET]
    allowed = lab.command("docker", "exec", "--user", "65534:65534", node,
                          "test", "-w", SOCKET, allow_failure=True)
    lab.check("positive", "Actual rootful kind socket is root-owned and fails the unrelated UID permission check",
              leaf["type"] == "socket" and leaf["uid"] == 0 and leaf["gid"] == 0
              and not (int(leaf["mode"], 8) & 0o007)
              and all(metadata[path]["type"] == "directory" for path in ("/", "/run", "/run/containerd"))
              and allowed.returncode == 1,
              {"metadata": metadata, "unrelated_uid_permission_check_denied": allowed.returncode == 1})


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
        finally:
            lab.command("docker", "exec", node, "rm", "-f", remote)
    outcome = dict(token.split("=", 1) for token in output.split())
    lab.check("red", "A traversable directory and permissive fixture socket allow an unrelated UID to echo",
              outcome.get("public") == "echo", {"unrelated_echo": outcome.get("public") == "echo"})
    lab.check("green", "Tightening either the parent directory or fixture socket blocks the unrelated UID",
              outcome.get("parent") == "denied" and outcome.get("mode") == "denied",
              {"parent_path_denied": outcome.get("parent") == "denied",
               "socket_mode_denied": outcome.get("mode") == "denied"})
    lab.check("positive", "The fixture socket owner can still perform the same echo",
              outcome.get("owner") == "echo", {"owner_echo": outcome.get("owner") == "echo"})
