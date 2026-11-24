"""Rehearse the first kubeadm node's scoped client identity replacement."""
from contextlib import contextmanager
from datetime import datetime, timezone
from ipaddress import ip_address
import json
import ssl
import time

DIRECTORY = "/run/saf-client-rotation-fixture"
DROPIN = "/etc/systemd/system/kubelet.service.d/99-saf-client-rotation-fixture.conf"
KUBECONFIG = f"{DIRECTORY}/kubelet.conf"
CERTS = f"{DIRECTORY}/pki"


def node_call(lab, node, *args, **options):
    return lab.command("docker", "exec", node, *args, **options).stdout.strip()


def put(lab, node, path, contents):
    lab.command("docker", "exec", "-i", node, "sh", "-ceu",
                'umask 077; cat > "$1"', "saf-control-plane-fixture", path, payload=contents)


def effective_flags(lab, node):
    # Only expose the two fixture-relevant arguments and the process ID.
    command = r"""
      pid=$(systemctl show kubelet.service --property MainPID --value)
      test "${pid:-0}" -gt 0
      printf 'pid=%s\n' "$pid"
      tr '\000' '\n' < "/proc/$pid/cmdline" |
        awk '/^--(kubeconfig|cert-dir)=/ { sub(/^--/,""); print }'
    """
    return dict(line.split("=", 1) for line in node_call(lab, node, "sh", "-ec", command).splitlines())


def public_identity(lab, node, path, *, seed=False):
    flags = ("-noout", "-serial", "-enddate", "-subject", "-nameopt", "RFC2253")
    if seed:
        # Select public X.509 data within the disposable node. Never put the
        # kubeconfig, private key or its output into the runner's command log.
        script = r'''
            kubectl config view --raw --minify --kubeconfig="$1" \
              -o 'jsonpath={.users[0].user.client-certificate-data}' |
              base64 -d | openssl x509 -noout -serial -enddate -subject -nameopt RFC2253
        '''
        answer = node_call(lab, node, "bash", "-o", "pipefail", "-ce", script, "saf-public-leaf", path)
    else:
        answer = node_call(lab, node, "openssl", "x509", "-in", path, *flags)
    return dict((key.strip(), value.strip()) for key, value in
                (line.split("=", 1) for line in answer.splitlines()))


def deadline(fields):
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(fields["notAfter"]), timezone.utc)


@contextmanager
def use_seeded_profile(lab, control):
    if control != f"{lab.cluster}-control-plane":
        lab.block("The bootstrap rehearsal only supports the exact owned initial control plane")
    node = json.loads(lab.kubectl("get", "node", control, "-o", "json").stdout)
    internal = [ip_address(item["address"]) for item in node["status"]["addresses"]
                if item["type"] == "InternalIP"]
    if len(internal) != 1 or internal[0].version != 4:
        lab.block("Expected the owned single-stack IPv4 control plane")
    original = effective_flags(lab, control)
    if original.get("kubeconfig") != "/etc/kubernetes/kubelet.conf":
        lab.block("Expected the pinned kubeadm kubelet service wiring")
    node_call(lab, control, "test", "!", "-e", DIRECTORY)
    node_call(lab, control, "test", "!", "-e", DROPIN)
    node_call(lab, control, "install", "-d", "-m", "0700", DIRECTORY, CERTS)
    changed = False
    try:
        put(lab, control, f"{DIRECTORY}/kubeadm.yaml", f"""apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
nodeRegistration:
  name: {control}
localAPIEndpoint:
  advertiseAddress: {internal[0]}
  bindPort: 6443
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
kubernetesVersion: v1.36.1
certificatesDir: /etc/kubernetes/pki
controlPlaneEndpoint: {internal[0]}:6443
certificateValidityPeriod: 150s
""")
        node_call(lab, control, "kubeadm", "init", "phase", "kubeconfig", "kubelet",
                  "--config", f"{DIRECTORY}/kubeadm.yaml", "--kubeconfig-dir", DIRECTORY, timeout=35)
        node_call(lab, control, "chmod", "0600", KUBECONFIG)
        seed = public_identity(lab, control, KUBECONFIG, seed=True)
        subject_ok = set(seed["subject"].split(",")) == {f"CN=system:node:{control}", "O=system:nodes"}
        seed_ttl = (deadline(seed) - datetime.now(timezone.utc)).total_seconds()
        if not subject_ok or not 100 < seed_ttl <= 150:
            lab.block("The seed must be the expected short-lived kubeadm node identity")
        put(lab, control, f"{DIRECTORY}/environment",
            f'KUBELET_EXTRA_ARGS="--kubeconfig={KUBECONFIG} --bootstrap-kubeconfig= --cert-dir={CERTS}"\n')
        changed = True
        put(lab, control, DROPIN, f"[Service]\nEnvironmentFile={DIRECTORY}/environment\n")
        node_call(lab, control, "systemctl", "daemon-reload")
        node_call(lab, control, "systemctl", "restart", "kubelet.service", timeout=40)
        configured = effective_flags(lab, control)
        if configured.get("kubeconfig") != KUBECONFIG or configured.get("cert-dir") != CERTS:
            lab.block("The running kubelet did not use the isolated credential paths")
        if configured["pid"] == original["pid"]:
            lab.block("Expected a new process for the isolated seeded kubelet")
        yield seed, node["metadata"]["uid"]
    except Exception:
        if changed:
            node_call(lab, control, "journalctl", "-u", "kubelet", "-n", "45", "--no-pager", allow_failure=True)
        raise
    finally:
        if changed:
            node_call(lab, control, "rm", "-f", "--", DROPIN)
            node_call(lab, control, "systemctl", "daemon-reload")
            node_call(lab, control, "systemctl", "restart", "kubelet.service", timeout=40)
        # Only the protected, uniquely named case directory is removed.
        node_call(lab, control, "rm", "-rf", "--", DIRECTORY)
    restored = effective_flags(lab, control)
    same_profile = all(restored.get(name) == original.get(name) for name in ("kubeconfig", "cert-dir"))
    lab.check("positive", "Restoration returns the initial control plane to its original kubelet credential paths",
              same_profile, {"original_kubelet_paths_restored": same_profile})


def wait(lab, observe, label, seconds):
    stop = time.monotonic() + seconds
    while time.monotonic() < stop:
        value = observe()
        if value is not None:
            return value
        time.sleep(2)
    lab.block(f"Timed out waiting for {label}")


def observe_seed(lab, control, seed, observe_ttl):
    seeded_expiry = deadline(seed)

    def match():
        # The live gauge is a stronger check than the value configured in the seed.
        ttl = observe_ttl(control)
        return ttl if ttl and 0 < ttl <= 150 and abs(ttl - (seeded_expiry - datetime.now(timezone.utc)).total_seconds()) < 12 else None

    sample = wait(lab, match, "the seeded control-plane credential in the running kubelet", 30)
    active = (deadline(seed) - datetime.now(timezone.utc)).total_seconds() > 0
    lab.check("red", "The active control-plane client is still using the short-lived seed before native replacement",
              active and sample <= 150, {"live_seed_ttl_matches": active and sample <= 150})
    return sample


def prove_replacement(lab, control, state, serials_before, sample, observe_certificates):
    seed, node_uid = state
    expiry = deadline(seed)
    seed_serial = seed["serial"].lower().lstrip("0")

    def activated():
        path = f"{CERTS}/kubelet-client-current.pem"
        exists = lab.command("docker", "exec", control, "test", "-s", path, allow_failure=True).returncode == 0
        if not exists:
            return None
        current = public_identity(lab, control, path)
        new_serial = current["serial"].lower().lstrip("0")
        if new_serial == seed_serial or new_serial in serials_before:
            return None
        _, candidates = observe_certificates(lab, control)
        for candidate in candidates:
            if candidate[2].lower().lstrip("0") == new_serial and candidate[3] and candidate[0] > expiry:
                return current
        return None

    # Installed renewal can be polled alongside the worker comparison. Signed
    # status and the installed public leaf must identify the same new serial.
    remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
    replacement = wait(lab, activated, "the exact approved control-plane replacement", max(4, remaining))
    observed_at = datetime.now(timezone.utc)
    pre_expiry = observed_at < expiry
    so = observed_at.isoformat()
    return {"seed_serial": seed["serial"], "installed_and_issued_serial": replacement["serial"],
            "seed_ttl_seconds": sample, "seed_expiry": expiry.isoformat(), "replacement_observed_at": so,
            "replacement_expiry": deadline(replacement).isoformat(), "pre_expiry": pre_expiry,
            "source_node_uid": node_uid}
