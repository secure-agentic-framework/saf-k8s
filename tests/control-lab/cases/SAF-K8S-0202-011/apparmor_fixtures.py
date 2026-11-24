"""Run a bounded OCI/AppArmor marker check in an ephemeral mount-free Lima guest."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile


ROOT = Path(__file__).resolve().parent
BOOTSTRAP = (
    "export LC_ALL=C DEBIAN_FRONTEND=noninteractive; "
    'test "$(systemd-detect-virt)" = apple; '
    'test "$(. /etc/os-release; printf \'%s\' "$ID")" = debian; '
    "apt-get -o APT::Get::AllowUnauthenticated=false "
    "-o Acquire::AllowInsecureRepositories=false -q update; "
    "apt-get -o APT::Get::AllowUnauthenticated=false -qy --no-install-recommends "
    "install runc busybox-static"
)


def observe_guest(lab):
    """Return normalized output only; never retain raw guest command output."""
    if not shutil.which("limactl"):
        lab.block("The OCI AppArmor fixture requires Lima 2.0+ with macOS Virtualization.framework")

    script = (ROOT / "apparmor_probe.sh").read_text()
    profile = ROOT / "apparmor-vm.yaml"
    observed = {
        "guest_profile_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        "probe_sha256": hashlib.sha256(script.encode()).hexdigest(),
    }
    with tempfile.TemporaryDirectory(prefix="saf-apparmor-0202-011-", dir="/tmp") as directory:
        lima_home = Path(directory) / "lima"
        lima_home.mkdir(mode=0o700)
        lima = ("env", f"LIMA_HOME={lima_home}", "limactl")
        identity = "aa"
        try:
            lab.command(*lima, "start", "--yes", "--plain", "--mount-none", "--timeout=240s",
                        f"--name={identity}", str(profile), timeout=420)
            shell = (*lima, "shell", "--workdir", "/tmp", identity, "sudo", "-n", "bash")
            lab.command(*shell, "-ceu", BOOTSTRAP, timeout=300)
            result = lab.command(*shell, "-s", payload=script, timeout=180)
            rows = [line.removeprefix("SAF_RESULT=") for line in result.stdout.splitlines()
                    if line.startswith("SAF_RESULT=")]
            if len(rows) != 1:
                lab.block("The isolated OCI guest did not return exactly one normalized result")
            observed.update(json.loads(rows[0]))
        finally:
            lab.command(*lima, "stop", identity, allow_failure=True, timeout=60)
            lab.command(*lima, "delete", "--yes", "--force", identity, allow_failure=True, timeout=60)
        observed["guest_deleted"] = not any((lima_home / path).exists() for path in (
            identity, Path("instances") / identity,
        ))
    return observed
