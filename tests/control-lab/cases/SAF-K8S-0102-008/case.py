"""Compare a same-run fixture snapshot reference and run an isolated restore."""
import base64
import hashlib
import json
import os
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
    "One synthetic ConfigMap on kind v1.36.1 with etcd v3.6.8. Use a detached local fixture "
    "digest reference, reject a truncated artifact and a different valid snapshot, "
    "then restore with revision bump into a Docker container with no network. Read only "
    "the exact synthetic value bytes. Deployed backup custody and controller recovery require "
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


def restore(lab, mount, name, artifact, original_revision, expected_value):
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
            len(records) == 1 and base64.b64decode(records[0]["key"], validate=True).decode() == FIXTURE_KEY
            and base64.b64decode(records[0]["value"], validate=True) == expected_value
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


def capture_fixture_value(lab, etcd):
    """Read the exact value bytes for the one case-owned synthetic key."""
    tls = [
        "--endpoints=https://127.0.0.1:2379", "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
        "--cert=/etc/kubernetes/pki/etcd/server.crt", "--key=/etc/kubernetes/pki/etcd/server.key",
    ]
    result = quiet(lab, [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--request-timeout=15s", "-n", "kube-system", "exec", etcd, "-c", "etcd", "--",
        "etcdctl", *tls, "get", FIXTURE_KEY, "--write-out=json",
    ])
    if result.returncode:
        lab.block("The isolated exact-key baseline could not be read")
    records = json.loads(result.stdout).get("kvs", [])
    if (len(records) != 1 or base64.b64decode(records[0].get("key", ""), validate=True).decode()
            != FIXTURE_KEY):
        lab.block("Could not capture exactly the case-owned synthetic etcd key")
    value = base64.b64decode(records[0].get("value", ""), validate=True)
    if MARKER not in value:
        lab.block("The case-owned etcd key does not contain the expected synthetic marker")
    return value


def restore_if_reference_matches(lab, mount, name, artifact, expected_digest, original_revision,
                                 expected_value, restore_calls):
    """Sequential fixture-reference gate for bad and accepted snapshots."""
    if sha256(artifact) != expected_digest:
        return False
    restore_calls.append(artifact.name)
    restore(lab, mount, name, artifact.name, original_revision, expected_value)
    return True


def promote_if_reference_matches(source, destination, expected_digest, promotion_calls):
    """Single-writer atomic promotion after source and copied bytes match."""
    part = destination.with_name(destination.name + ".part")
    if (not source.is_file() or destination.exists() or part.exists()
            or sha256(source) != expected_digest):
        return False
    descriptor = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            with source.open("rb") as input_stream:
                shutil.copyfileobj(input_stream, output)
            output.flush()
        if sha256(part) != expected_digest:
            return False
        # The staging parent is private and this runner is the only writer.
        # os.replace is atomic within this directory under that fixture assumption.
        os.replace(part, destination)
        promotion_calls.append(destination.name)
        return True
    finally:
        part.unlink(missing_ok=True)


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
    expected_value = capture_fixture_value(lab, etcd)
    restore_calls = []
    with tempfile.TemporaryDirectory(prefix="saf-etcd-integrity-") as temp:
        root = Path(temp).resolve()
        capture = root / "capture"
        capture.mkdir(mode=0o700)
        trust_root = root / "trust"
        trust_root.mkdir(mode=0o700)
        staging = root / "staging"
        staging.mkdir(mode=0o700)
        capture_mount = f"type=bind,src={capture},dst=/restore,readonly"
        staging_mount = f"type=bind,src={staging},dst=/restore"
        original = capture / "original.db"
        snapshot(lab, etcd, original)
        # The reference lives outside both capture and staging. This same-run
        # fixture comparison is not an independent production trust anchor.
        trust = trust_root / "fixture-reference.sha256"
        trust.touch(mode=0o600)
        trust.write_text(sha256(original), encoding="ascii")
        expected = trust.read_text(encoding="ascii")
        revision = native_status(lab, capture_mount, original.name)
        source_match = sha256(original) == expected
        lab.check("green", "The captured snapshot matches the detached fixture reference before promotion",
                  revision is not None and source_match,
                  {"matches": source_match, "native_snapshot_readable": revision is not None,
                   "verified_staging_empty": not any(staging.iterdir())})

        stored = staging / "verified.db"
        promotion_calls = []
        damaged = capture / "damaged.db"
        shutil.copyfile(original, damaged)
        with damaged.open("r+b") as artifact:
            artifact.truncate(damaged.stat().st_size // 2)
        mismatch = sha256(damaged) != expected
        damaged_promoted = promote_if_reference_matches(damaged, stored, expected, promotion_calls)
        damaged_restore = restore_if_reference_matches(
            lab, staging_mount, "saf-recovery-damaged", damaged, expected, revision,
            expected_value, restore_calls)
        damaged_not_staged = not any(staging.iterdir()) and not stored.exists()
        lab.check("red", "Offline truncation is rejected before staging promotion or restore",
                  mismatch and not damaged_promoted and damaged_not_staged
                  and not damaged_restore and len(promotion_calls) == 0 and len(restore_calls) == 0,
                  {"mismatch": mismatch, "promoted": damaged_promoted,
                   "staging_empty": damaged_not_staged, "promotion_call_count": len(promotion_calls),
                   "restore_call_count": len(restore_calls)})

        lab.kubectl("patch", "configmap", FIXTURE, "--type=merge",
                    "-p", '{"data":{"marker":"alternate-synthetic-snapshot"}}')
        alternate = capture / "alternate.db"
        snapshot(lab, etcd, alternate)
        valid_other = native_status(lab, capture_mount, alternate.name) is not None
        different = sha256(alternate) != expected
        alternate_promoted = promote_if_reference_matches(alternate, stored, expected, promotion_calls)
        alternate_restore = restore_if_reference_matches(
            lab, staging_mount, "saf-recovery-alternate", alternate, expected, revision,
            expected_value, restore_calls)
        alternate_not_staged = not any(staging.iterdir()) and not stored.exists()
        lab.check("red", "A different valid snapshot is rejected before staging promotion or restore",
                  valid_other and different and not alternate_promoted and alternate_not_staged
                  and not alternate_restore and len(promotion_calls) == 0 and len(restore_calls) == 0,
                  {"native_snapshot_readable": valid_other, "digest_mismatch": different,
                   "promoted": alternate_promoted, "staging_empty": alternate_not_staged,
                   "promotion_call_count": len(promotion_calls),
                   "restore_call_count": len(restore_calls)})

        accepted_promotion = promote_if_reference_matches(original, stored, expected, promotion_calls)
        staged_match = sha256(stored) == trust.read_text(encoding="ascii")
        staged_revision = native_status(lab, staging_mount, stored.name)
        lab.check("green", "Only the exact source snapshot is promoted and reverified before restore",
                  accepted_promotion and promotion_calls == [stored.name]
                  and sorted(path.name for path in staging.iterdir()) == [stored.name]
                  and stored.stat().st_mode & 0o777 == 0o600
                  and staged_match and staged_revision == revision,
                  {"promoted": accepted_promotion, "promotion_call_count": len(promotion_calls),
                   "staging_file_count": len(list(staging.iterdir())),
                   "matches": staged_match, "same_revision": staged_revision == revision,
                   "mode_0600": stored.stat().st_mode & 0o777 == 0o600})
        accepted = restore_if_reference_matches(
            lab, staging_mount, "saf-recovery", stored, expected, revision, expected_value, restore_calls)
        lab.check("positive", "Only the fixture-reference-matching artifact reached the native restore",
                  accepted and restore_calls == [stored.name],
                  {"restore_call_count": len(restore_calls),
                   "fixture_reference_matching_artifact_accepted": accepted})
