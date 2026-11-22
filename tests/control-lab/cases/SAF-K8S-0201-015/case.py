"""Verify real node file audit events using a separate disposable Linux kernel."""
import json
from pathlib import Path
import shutil
import tempfile


ROOT = Path(__file__).resolve().parent
SCOPE = (
    "Kind confirms the generated kubelet config, kubeconfig and PKI path types. A separate "
    "mount-free disposable Debian VM loads Linux Audit watch rules for three inert files and "
    "verifies read/write events. Deployed rules, complete node paths, and recurring "
    "production coverage require independent evidence."
)
FIXTURE_PATHS = {
    "kubelet_config": ("-s", "/var/lib/kubelet/config.yaml"),
    "kubeconfig": ("-s", "/etc/kubernetes/kubelet.conf"),
    "pki_directory": ("-d", "/var/lib/kubelet/pki"),
}
BOOTSTRAP = (
    "export LC_ALL=C DEBIAN_FRONTEND=noninteractive; "
    "test \"$(systemd-detect-virt)\" = apple; "
    "apt-get -q update; apt-get -qy --no-install-recommends install auditd; "
    "systemctl start auditd"
)


def run(lab):
    if not shutil.which("limactl"):
        lab.block("The file audit case requires Lima with macOS Virtualization.framework")
    node = f"{lab.cluster}-control-plane"
    paths = {
        field: lab.command("docker", "exec", node, "test", flag, path,
                           allow_failure=True, timeout=15).returncode == 0
        for field, (flag, path) in FIXTURE_PATHS.items()
    }
    lab.check("positive", "The disposable Kubernetes node has the expected kubelet path types",
              all(paths.values()), paths)

    with tempfile.TemporaryDirectory(prefix="saf-audit-", dir="/tmp") as directory:
        home = Path(directory) / "vm"
        home.mkdir(mode=0o700)
        lima = ("env", f"LIMA_HOME={home}", "limactl")
        identity = "ad"
        try:
            lab.command(*lima, "start", "--yes", "--plain", "--mount-none", "--timeout=240s",
                        f"--name={identity}", str(ROOT / "audit-vm.yaml"), timeout=420)
            shell = (*lima, "shell", "--workdir", "/tmp", identity, "sudo", "-n", "bash")
            lab.command(*shell, "-ceu", BOOTSTRAP, timeout=240)
            result = lab.command(*shell, "-s", payload=(ROOT / "audit_probe.sh").read_text(), timeout=130)
            observed = {}
            for line in result.stdout.splitlines():
                if line.startswith("{"):
                    observed.update(json.loads(line))
            baseline = {key: observed.get(key) is True for key in (
                "baseline_unwatched", "collector_canary_logged",
            )}
            lab.check("red", "Unwatched accesses produce no file events while the audit collector is live",
                      all(baseline.values()), baseline)
            audited = {key: observed.get(key) is True for key in (
                "watched_config_read_write", "watched_kubeconfig_read_write",
                "watched_pki_read_write", "no_audit_loss",
            )}
            lab.check("green", "Linux Audit captures successful reads and writes for all three watched paths",
                      all(audited.values()), audited)
            rules_removed = observed.get("rules_removed") is True
            lab.check("positive", "The guest returns to a clean loaded rule set",
                      rules_removed, {"rules_removed": rules_removed})
        finally:
            instance = home / identity
            if instance.is_dir():
                lab.command(*lima, "stop", identity, allow_failure=True, timeout=45)
                lab.command(*lima, "delete", "--yes", "--force", identity, timeout=45)
        lab.check("positive", "The case deletes the isolated guest instance",
                  not (home / identity).exists(), {"guest_deleted": not (home / identity).exists()})
