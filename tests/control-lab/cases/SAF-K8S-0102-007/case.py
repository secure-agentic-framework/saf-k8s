"""Check encryption and key separation for a synthetic etcd snapshot artifact."""
import hashlib
import json
import os
import runpy
from pathlib import Path
import shutil
import subprocess
import tempfile

from lab import NAMESPACE


IMAGE = "registry.k8s.io/etcd:3.6.8-0"
RECOVERY_IMAGE = IMAGE + "@sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5"
FIXTURE = "saf-etcd-backup-encryption-fixture"
FIXTURE_KEY = f"/registry/configmaps/{NAMESPACE}/{FIXTURE}"
MARKER = b"synthetic-non-sensitive-etcd-backup-encryption-fixture"
DATA_DIRECTORY = "/var/lib/etcd"
SCOPE = (
    "One synthetic ConfigMap on Kubernetes v1.36.1 kind with etcd v3.6.8. Copy a native "
    "snapshot through the case-owned kind etcd method as a plaintext comparison. Capture the "
    "protected snapshot on verified bounded guest tmpfs with the noswap mount option, stream it "
    "into age without a host plaintext staging file, retain ciphertext only, and recover "
    "into an isolated local path. "
    "The source identity is only a wrong-key proxy: kind live-volume encryption, "
    "production key management, storage-provider encryption, custody, and transport are "
    "not established. Backup integrity and restore assurance are governed by 0102-008."
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def invoke(lab, args, timeout=40):
    """Run key or artifact tools without retaining their output in lab evidence."""
    try:
        return subprocess.run(args, env=lab.env, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("A case-owned backup encryption tool could not complete")


def snapshot(lab, etcd, destination):
    remote = f"{DATA_DIRECTORY}/{lab.cluster}-{destination.name}"
    control_plane = f"{lab.cluster}-control-plane"
    tls = [
        "--endpoints=https://127.0.0.1:2379", "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
        "--cert=/etc/kubernetes/pki/etcd/server.crt", "--key=/etc/kubernetes/pki/etcd/server.key",
    ]
    try:
        lab.kubectl("-n", "kube-system", "exec", etcd, "-c", "etcd", "--",
                    "etcdctl", *tls, "snapshot", "save", remote, timeout=90)
        # kubeadm shares this directory with the kind node. Copy from that node
        # because the etcd workload image has no tar for kubectl cp.
        lab.command("docker", "cp", f"{control_plane}:{remote}", str(destination), timeout=90)
        destination.chmod(0o600)
    finally:
        lab.command("docker", "exec", control_plane, "rm", "-f", remote)


def native_status(lab, mount, filename):
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--network=none", "--mount", mount,
             "--entrypoint=etcdutl", RECOVERY_IMAGE, "--write-out=json", "snapshot", "status",
             f"/backup/{filename}"],
            env=lab.env, capture_output=True, text=True, timeout=40,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    try:
        return int(json.loads(result.stdout)["revision"])
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


def generate_identity(lab, keygen, path):
    result = invoke(lab, [keygen, "-o", str(path)])
    if result.returncode or not path.is_file():
        lab.block("Could not create a fresh synthetic age identity")
    path.chmod(0o600)
    recipient = invoke(lab, [keygen, "-y", str(path)])
    if recipient.returncode:
        lab.block("Could not derive the recipient for a fresh synthetic age identity")
    try:
        lines = recipient.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError:
        lab.block("The age recipient output was not valid ASCII")
    if len(lines) != 1 or not lines[0].startswith("age1"):
        lab.block("The age key tool returned an unexpected recipient format")
    return lines[0]


def run(lab):
    age = shutil.which("age")
    keygen = shutil.which("age-keygen")
    if not age or not keygen:
        lab.block("Install the official age CLI (age and age-keygen) before running this case")

    etcd = f"etcd-{lab.cluster}-control-plane"
    mirror = json.loads(lab.kubectl("-n", "kube-system", "get", f"pod/{etcd}", "-o", "json").stdout)
    container = next(item for item in mirror["spec"]["containers"] if item["name"] == "etcd")
    mounted = {volume["name"] for volume in container["volumeMounts"]
               if volume["mountPath"] == DATA_DIRECTORY}
    shared = {volume["name"] for volume in mirror["spec"]["volumes"]
              if volume.get("hostPath", {}).get("path") == DATA_DIRECTORY}
    if container["image"] != IMAGE or not mounted & shared:
        lab.block("Expected the pinned Kubernetes v1.36.1 etcd profile")

    lab.apply(Path(__file__).with_name("fixture.yaml"))
    with tempfile.TemporaryDirectory(prefix="saf-etcd-backup-encryption-") as temp:
        root = Path(temp).resolve()
        root.chmod(0o700)
        staging = root / "staging"
        staging.mkdir(mode=0o700)
        staging.chmod(0o700)
        mount = f"type=bind,src={staging},dst=/backup,readonly"

        # Fresh synthetic keys model separate source and backup identities. They
        # do not assert that the kind etcd data directory has encryption enabled.
        source_identity = root / "source-proxy.agekey"
        backup_identity = root / "backup.agekey"
        generate_identity(lab, keygen, source_identity)
        backup_recipient = generate_identity(lab, keygen, backup_identity)

        raw = staging / "snapshot.db"
        snapshot(lab, etcd, raw)
        raw.chmod(0o600)
        source_revision = native_status(lab, mount, raw.name)
        has_synthetic_marker = MARKER in raw.read_bytes()
        lab.check("red", "The source snapshot is readable plaintext before backup encryption",
                  source_revision is not None and has_synthetic_marker,
                  {"native_snapshot_readable": source_revision is not None,
                   "synthetic_marker_present": has_synthetic_marker,
                   "live_volume_encryption_claimed": False})

        raw.unlink()
        container_id = next(item["containerID"] for item in mirror["status"]["containerStatuses"]
                            if item["name"] == "etcd")
        tls_args = ["--endpoints=https://127.0.0.1:2379", "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
                    "--cert=/etc/kubernetes/pki/etcd/server.crt", "--key=/etc/kubernetes/pki/etcd/server.key"]
        encrypted = staging / "snapshot.db.age"
        capture = runpy.run_path(str(Path(__file__).with_name("protected_capture.py")))["capture_protected_snapshot"]
        source_digest, source_revision = capture(
            lab, etcd, container_id, tls_args, age, backup_recipient, encrypted)
        raw_encrypted = native_status(lab, mount, encrypted.name)
        ciphertext_contains_marker = MARKER in encrypted.read_bytes()
        lab.check("green", "The stored backup artifact is encrypted and not a native etcd snapshot",
                  raw_encrypted is None and not ciphertext_contains_marker,
                  {"native_snapshot_readable": raw_encrypted is not None,
                   "synthetic_marker_present": ciphertext_contains_marker,
                   "artifact_mode": oct(encrypted.stat().st_mode & 0o777)})

        retention = root / "retention"
        retention.mkdir(mode=0o700)
        retained = retention / encrypted.name
        encrypted.replace(retained)
        retained_entries = list(retention.iterdir())
        lab.check("green", "The retention directory contains only the approved ciphertext artifact",
                  retained_entries == [retained] and retained.stat().st_mode & 0o777 == 0o600
                  and MARKER not in retained.read_bytes(),
                  {"retained_file_count": len(retained_entries), "ciphertext_only": retained_entries == [retained],
                   "artifact_mode": oct(retained.stat().st_mode & 0o777)})
        staging_empty = not any(staging.iterdir())
        lab.check("green", "Local staging files have been removed before recovery",
                  staging_empty and not raw.exists(),
                  {"staging_empty": staging_empty, "plaintext_staging_absent": not raw.exists()})

        restore = root / "isolated-restore"
        restore.mkdir(mode=0o700)
        restore_mount = f"type=bind,src={restore},dst=/backup,readonly"
        unrelated_output = restore / "unrelated-decryption.db"
        wrong_key = invoke(lab, [age, "--decrypt", "--identity", str(source_identity),
                                 "--output", str(unrelated_output), str(retained)], timeout=90)
        wrong_key_rejected = wrong_key.returncode != 0
        if unrelated_output.exists():
            unrelated_output.unlink()
        lab.check("red", "The distinct synthetic source proxy identity cannot decrypt the backup",
                  wrong_key_rejected,
                  {"rejected": wrong_key_rejected, "source_key_is_synthetic_proxy": True})

        restored = restore / "decrypted.db"
        result = invoke(lab, [age, "--decrypt", "--identity", str(backup_identity),
                              "--output", str(restored), str(retained)], timeout=90)
        if result.returncode or not restored.is_file():
            lab.block("The backup identity could not decrypt its encrypted snapshot")
        restored.chmod(0o600)
        restored_revision = native_status(lab, restore_mount, restored.name)
        decrypted_digest = sha256(restored)
        lab.check("positive", "The separate backup identity decrypts an exact native snapshot copy",
                  restored_revision == source_revision and decrypted_digest == source_digest,
                  {"same_sha256": decrypted_digest == source_digest,
                   "native_snapshot_readable": restored_revision is not None,
                   "same_revision": restored_revision == source_revision})

        tampered = restore / "tampered.db.age"
        shutil.copyfile(retained, tampered)
        tampered.chmod(0o600)
        with tampered.open("r+b") as artifact:
            artifact.seek(-1, os.SEEK_END)
            last = artifact.read(1)
            artifact.seek(-1, os.SEEK_END)
            artifact.write(bytes([last[0] ^ 1]))
        tampered_output = restore / "tampered-decryption.db"
        corrupted = invoke(lab, [age, "--decrypt", "--identity", str(backup_identity),
                                 "--output", str(tampered_output), str(tampered)], timeout=90)
        tamper_rejected = corrupted.returncode != 0
        if tampered_output.exists():
            tampered_output.unlink()
        lab.check("red", "Authenticated decryption rejects a modified encrypted backup",
                  tamper_rejected,
                  {"rejected": tamper_rejected, "0102_008_integrity_control": "separate"})
