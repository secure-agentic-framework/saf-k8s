"""Capture only synthetic Audit evidence in an independently booted Linux guest."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parent
AUDITD_PACKAGE = "1:4.0.2-2+deb13u1"
BOOTSTRAP = (
    "export LC_ALL=C DEBIAN_FRONTEND=noninteractive; "
    'test "$(systemd-detect-virt)" = apple; '
    f"apt-get -q update; apt-get -qy --no-install-recommends install auditd={AUDITD_PACKAGE}; "
    "systemctl start auditd"
)


def observe_guest(lab):
    if not shutil.which("limactl"):
        lab.block("The native file Audit fixture requires Lima with macOS Virtualization.framework")
    script = (ROOT / "audit_probe.sh").read_bytes()
    profile = ROOT / "audit-vm.yaml"
    observed = {"events": [], "probe_sha256": hashlib.sha256(script).hexdigest(),
                "guest_profile_sha256": hashlib.sha256(profile.read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix="saf-audit-", dir="/tmp") as directory:
        home = Path(directory) / "vm"
        home.mkdir(mode=0o700)
        lima = ("env", f"LIMA_HOME={home}", "limactl")
        identity = "ad"
        try:
            lab.command(*lima, "start", "--yes", "--plain", "--mount-none", "--timeout=240s",
                        f"--name={identity}", str(profile), timeout=420)
            shell = (*lima, "shell", "--workdir", "/tmp", identity, "sudo", "-n", "bash")
            lab.command(*shell, "-ceu", BOOTSTRAP, timeout=240)
            result = lab.command(*shell, "-s", payload=script.decode(), timeout=155)
            for line in result.stdout.splitlines():
                if line.startswith("{"):
                    row = json.loads(line)
                    if "event" in row:
                        observed["events"].append(row["event"])
                    else:
                        observed.update(row)
        finally:
            instance = home / identity
            if instance.is_dir():
                lab.command(*lima, "stop", identity, allow_failure=True, timeout=45)
                lab.command(*lima, "delete", "--yes", "--force", identity, timeout=45)
        observed["guest_deleted"] = not (home / identity).exists()
    return observed
