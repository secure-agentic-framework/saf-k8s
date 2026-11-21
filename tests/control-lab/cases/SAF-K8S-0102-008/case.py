"""Verify a trusted etcd snapshot and run a network-isolated restore."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from lab import NAMESPACE


IMAGE = "registry.k8s.io/etcd:3.6.8-0"
RECOVERY_IMAGE = IMAGE + "@sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5"
FIXTURE = "saf-etcd-integrity-fixture"
FIXTURE_KEY = f"/registry/configmaps/{NAMESPACE}/{FIXTURE}"
MARKER = b"synthetic-non-sensitive-etcd-restore-fixture"
BUMP = 1_000_000
ENDPOINT = "http://127.0.0.1:2379"
DATA_DIRECTORY = "/var/lib/etcd"
SCOPE = (
    "One synthetic ConfigMap on kind v1.36.1 with etcd v3.6.8. Use a detached local "
    "integrity manifest, reject a truncated artifact and a different valid snapshot, "
    "then restore with revision bump into a Docker container with no network. Read only "
    "the exact synthetic marker. Deployed backup custody and controller recovery require "
    "separate evidence."
)


def quiet(lab, args, timeout=25):
    try:
        return subprocess.run(args, env=lab.env, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        lab.block(f"The case-owned {args[0]} operation could not be observed")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for block in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
    result = quiet(lab, ["docker", "run", "--rm", "--network=none", "--mount", mount,
                         "--entrypoint=etcdutl", RECOVERY_IMAGE, "--write-out=json",
                         "snapshot", "status", f"/restore/{filename}"])
    if result.returncode:
        return None
    return int(json.loads(result.stdout)["revision"])


def restore(lab, mount, name, artifact, original_revision):
    node = f"{lab.cluster}-recovery"
    if quiet(lab, ["docker", "container", "inspect", node]).returncode == 0:
        lab.block("The recovery container name is already in use")
    peer = "http://127.0.0.1:2380"
    initial_members = f"{name}={peer}"
    lab.command(
        "docker", "run", "--rm", "--network=none", "--mount", mount,
        "--entrypoint=etcdutl", RECOVERY_IMAGE, "snapshot", "restore", f"/restore/{artifact}",
        "--data-dir=/restore/store", f"--name={name}", f"--initial-cluster={initial_members}",
        f"--initial-advertise-peer-urls={peer}", f"--bump-revision={BUMP}", "--mark-compacted",
        timeout=90,
    )
    try:
        lab.command(
            "docker", "run", "--detach", "--network=none", "--name", node, "--mount", mount,
            "--entrypoint=etcd", RECOVERY_IMAGE, f"--name={name}", "--data-dir=/restore/store",
            f"--listen-peer-urls={peer}", f"--initial-advertise-peer-urls={peer}",
            f"--initial-cluster={initial_members}", f"--listen-client-urls={ENDPOINT}",
            f"--advertise-client-urls={ENDPOINT}",
        )
        base = ["docker", "exec", node, "etcdctl", f"--endpoints={ENDPOINT}",
                "--dial-timeout=1s", "--command-timeout=2s"]
        deadline = time.monotonic() + 25
        while True:
            if quiet(lab, [*base, "endpoint", "health"]).returncode == 0:
                break
            if time.monotonic() >= deadline:
                lab.block("Network-isolated restore did not become healthy")
            time.sleep(0.5)

        result = quiet(lab, [*base, "get", FIXTURE_KEY, "--write-out=json"])
        if result.returncode:
            lab.block("The isolated exact-key recovery query failed")
        observed = json.loads(result.stdout)
        records = observed.get("kvs", [])
        restored = (
            len(records) == 1 and base64.b64decode(records[0]["key"]).decode() == FIXTURE_KEY
            and MARKER in base64.b64decode(records[0]["value"], validate=True)
        )
        lab.check("positive", "Restored etcd returns the unchanged synthetic fixture",
                  restored, restored)
        latest = int(observed["header"]["revision"])
        previous = quiet(lab, [*base, "get", FIXTURE_KEY, f"--rev={original_revision}"])
        bumped = latest >= original_revision + BUMP
        compacted = previous.returncode != 0 and "revision has been compacted" in previous.stderr
        lab.check("positive", "The restored revision advances and the pre-restore revision is compacted",
                  bumped and compacted, {"revision_bumped": bumped, "old_revision_compacted": compacted})
    finally:
        lab.command("docker", "rm", "-f", node)


def run(lab):
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
    with tempfile.TemporaryDirectory(prefix="saf-etcd-integrity-") as temp:
        root = Path(temp).resolve()
        staging = root / "staging"
        staging.mkdir(mode=0o700)
        mount = f"type=bind,src={staging},dst=/restore"
        original = staging / "original.db"
        snapshot(lab, etcd, original)
        # Store the expected digest separately from staging. The restore container
        # receives only the staging mount, outside this trust directory.
        trust = root / "trusted.sha256"
        trust.touch(mode=0o600)
        trust.write_text(sha256(original), encoding="ascii")
        expected = trust.read_text(encoding="ascii")
        revision = native_status(lab, mount, original.name)
        lab.check("green", "The original snapshot matches its trusted digest before staging",
                  revision is not None and sha256(original) == expected,
                  {"matches": sha256(original) == expected, "native_snapshot_readable": revision is not None})

        stored = staging / "verified.db"
        shutil.copyfile(original, stored)
        stored.chmod(0o600)
        damaged = staging / "damaged.db"
        shutil.copyfile(stored, damaged)
        with damaged.open("r+b") as artifact:
            artifact.truncate(damaged.stat().st_size // 2)
        mismatch = sha256(damaged) != expected
        lab.check("red", "Offline truncation fails the trusted digest check before restore",
                  mismatch, {"mismatch": mismatch, "restore_attempted": False})

        lab.kubectl("patch", "configmap", FIXTURE, "--type=merge",
                    "-p", '{"data":{"marker":"alternate-synthetic-snapshot"}}')
        alternate = staging / "alternate.db"
        snapshot(lab, etcd, alternate)
        valid_other = native_status(lab, mount, alternate.name) is not None
        different = sha256(alternate) != expected
        lab.check("red", "A different valid snapshot still fails the trusted digest check",
                  valid_other and different, {"native_snapshot_readable": valid_other,
                                              "digest_mismatch": different, "restore_attempted": False})

        staged_match = sha256(stored) == trust.read_text(encoding="ascii")
        staged_revision = native_status(lab, mount, stored.name)
        lab.check("green", "The staged snapshot passes the trusted reference and native inspection before restore",
                  staged_match and staged_revision == revision,
                  {"matches": staged_match, "same_revision": staged_revision == revision})
        restore(lab, mount, "saf-recovery", stored.name, revision)
