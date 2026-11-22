"""Observe etcd history compaction and online defragmentation on disposable etcd."""
from contextlib import contextmanager
import json
import re
import subprocess
import time


IMAGE = "gcr.io/etcd-development/etcd:v3.6.8"
ENDPOINT = "http://127.0.0.1:2379"
AUTO_RETENTION = "8s"
AUTO_WAIT_SECONDS = 40
RAW_EVIDENCE_FILE = "etcd-maintenance.raw.json"
PADDING_KEY = "/saf-k8s-lab/public/transient-padding"
MANUAL_KEYS = {
    "/saf-k8s-lab/public/marker": ("synthetic-marker-v1", "synthetic-marker-v2"),
    "/saf-k8s-lab/public/companion": (None, "synthetic-companion-v1"),
    "/saf-k8s-lab/public/version": (None, "synthetic-version-v1"),
}
AUTO_KEY = "/saf-k8s-lab/public/auto-retention-marker"
SCOPE = (
    "Two disposable single-member etcd v3.6.8 processes, each in Docker network mode none. "
    "The manual case uses three public synthetic marker keys and one bounded deleted padding key, observes "
    "an old exact-key read before compaction, compacts the current revision, verifies that "
    "only the old read is rejected, and measures reclaimed database bytes after one online defrag. "
    "A second process checks periodic auto-compaction with a real 8-second retention window. "
    "No Kubernetes API or production data is used. Multi-member sequencing, real workload "
    "availability, sizing, and production retention selection are outside scope."
)


def etcdctl(lab, container, *args, allow_failure=False, timeout=15):
    return lab.command("docker", "exec", container, "etcdctl", f"--endpoints={ENDPOINT}",
                       "--dial-timeout=2s", "--command-timeout=8s", *args,
                       allow_failure=allow_failure, timeout=timeout)


@contextmanager
def etcd_member(lab, container, *, retention=None):
    existing = lab.command("docker", "container", "inspect", container, allow_failure=True)
    if existing.returncode == 0:
        lab.block(f"Refusing to reuse existing container {container}")
    args = ["docker", "run", "--detach", "--rm", "--network=none", "--name", container,
            "--entrypoint=etcd", IMAGE, "--name=saf-maintenance", "--data-dir=/etcd-data",
            "--listen-peer-urls=http://127.0.0.1:2380",
            "--initial-advertise-peer-urls=http://127.0.0.1:2380",
            "--initial-cluster=saf-maintenance=http://127.0.0.1:2380",
            "--initial-cluster-state=new",
            f"--listen-client-urls={ENDPOINT}", f"--advertise-client-urls={ENDPOINT}"]
    if retention:
        args.extend(["--auto-compaction-mode=periodic",
                     f"--auto-compaction-retention={retention}"])
    try:
        lab.command(*args, timeout=45)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            health = etcdctl(lab, container, "endpoint", "health", allow_failure=True)
            if health.returncode == 0:
                break
            time.sleep(0.5)
        else:
            lab.block(f"Disposable etcd {container} did not become healthy")
        version = lab.command("docker", "exec", container, "etcd", "--version", timeout=10).stdout
        if not re.search(r"etcd Version: 3\.6\.8\b", version):
            lab.block(f"Expected etcd 3.6.8 in {container}; observed version output did not match")
        yield version.strip()
    finally:
        stop_etcd(lab, container)


def status(lab, container):
    result = etcdctl(lab, container, "endpoint", "status", "--write-out=json")
    rows = json.loads(result.stdout)
    if len(rows) != 1 or rows[0].get("Status", {}).get("errors"):
        lab.block(f"Expected one healthy status observation from {container}")
    observed = rows[0]["Status"]
    required = ("header", "dbSize", "dbSizeInUse")
    if any(key not in observed for key in required):
        lab.block(f"{container} status lacks expected revision or database byte fields")
    return observed


def exact_value(lab, container, key, *, revision=None, allow_failure=False):
    args = ["get", key, "--print-value-only"]
    if revision is not None:
        args.append(f"--rev={revision}")
    return etcdctl(lab, container, *args, allow_failure=allow_failure)


def stop_etcd(lab, container):
    result = lab.command("docker", "rm", "--force", container,
                         allow_failure=True, timeout=30)
    if result.returncode:
        lab.block(f"Could not remove disposable etcd container {container}")


def record_raw_evidence(lab, name, observations):
    """Persist run-varying measurements separately from stable check observations."""
    path = lab.evidence / RAW_EVIDENCE_FILE
    records = json.loads(path.read_text()) if path.exists() else {}
    records[name] = observations
    path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")


def manual_compaction_and_defrag(lab, container):
    with etcd_member(lab, container) as version:
        old_revision = None
        for key, (old, latest) in MANUAL_KEYS.items():
            if old is not None:
                etcdctl(lab, container, "put", key, old)
                old_revision = int(status(lab, container)["header"]["revision"])
            etcdctl(lab, container, "put", key, latest)

        # A single 128 KiB value creates a controlled reclaimable allocation.
        padding = subprocess.run(
            ["docker", "exec", "-i", container, "etcdctl", f"--endpoints={ENDPOINT}",
             "--command-timeout=8s", "put", PADDING_KEY],
            env=lab.env, input=b"x" * (128 * 1024), capture_output=True, timeout=15,
        )
        if padding.returncode or padding.stdout.strip() != b"OK":
            lab.block("Could not write the bounded synthetic padding value")
        etcdctl(lab, container, "del", PADDING_KEY)
        # Move the compaction point past the deletion's revision.
        last_key = "/saf-k8s-lab/public/version"
        etcdctl(lab, container, "put", last_key, MANUAL_KEYS[last_key][1])

        before = status(lab, container)
        if old_revision is None:
            lab.block("The manual fixture did not create an old marker revision")
        old_key = "/saf-k8s-lab/public/marker"
        historical = exact_value(lab, container, old_key, revision=old_revision)
        red_ok = historical.stdout.rstrip("\n") == "synthetic-marker-v1"
        lab.check(
            "red", "Before maintenance, the exact synthetic key is readable at its old revision",
            red_ok, {"key": old_key, "revision": old_revision,
                     "observed_old_value": historical.stdout.rstrip("\n") if red_ok else "mismatch"},
        )

        current_revision = int(before["header"]["revision"])
        compact = etcdctl(lab, container, "compact", str(current_revision), "--physical")
        old_after = exact_value(lab, container, old_key, revision=old_revision, allow_failure=True)
        compacted_error = old_after.returncode != 0 and (
            "required revision has been compacted" in old_after.stderr.lower()
            or "revision has been compacted" in old_after.stderr.lower()
        )
        latest_reads = {
            key: exact_value(lab, container, key).stdout.rstrip("\n") == latest
            for key, (_, latest) in MANUAL_KEYS.items()
        }
        green_ok = compact.returncode == 0 and compacted_error and all(latest_reads.values())
        lab.check(
            "green", "Compaction rejects the old exact-key read while all latest marker reads work",
            green_ok, {"compacted_revision": current_revision,
                       "old_revision_rejected_as_compacted": compacted_error,
                       "latest_exact_key_reads": latest_reads},
        )

        after_compaction = status(lab, container)
        bytes_before = {"allocated": int(after_compaction["dbSize"]),
                        "in_use": int(after_compaction["dbSizeInUse"])}
        defrag = etcdctl(lab, container, "defrag")
        after_defrag = status(lab, container)
        bytes_after = {"allocated": int(after_defrag["dbSize"]),
                       "in_use": int(after_defrag["dbSizeInUse"])}
        intact = {
            key: exact_value(lab, container, key).stdout.rstrip("\n") == latest
            for key, (_, latest) in MANUAL_KEYS.items()
        }
        metrics_ok = (bytes_before["allocated"] >= bytes_before["in_use"] > 0
                      and bytes_after["allocated"] >= bytes_after["in_use"] > 0)
        bytes_reclaimed = bytes_after["allocated"] < bytes_before["allocated"]
        record_raw_evidence(
            lab,
            "manual_defrag_database_bytes",
            {"allocated_and_in_use_bytes_before_defrag": bytes_before,
             "allocated_and_in_use_bytes_after_defrag": bytes_after},
        )
        lab.check(
            "positive", "Defrag reclaims backend allocation while all latest marker values remain readable",
            defrag.returncode == 0 and all(intact.values()) and metrics_ok and bytes_reclaimed,
            {"version": version, "raw_evidence_file": RAW_EVIDENCE_FILE,
             "latest_exact_key_reads": intact,
             "allocated_ge_in_use": metrics_ok,
             "backend_bytes_reclaimed": bytes_reclaimed},
        )


def automatic_expiry(lab, container):
    with etcd_member(lab, container, retention=AUTO_RETENTION) as version:
        etcdctl(lab, container, "put", AUTO_KEY, "synthetic-auto-marker-v1")
        old_revision = int(status(lab, container)["header"]["revision"])
        etcdctl(lab, container, "put", AUTO_KEY, "synthetic-auto-marker-v2")
        latest_before = exact_value(lab, container, AUTO_KEY).stdout.rstrip("\n")
        before = exact_value(lab, container, AUTO_KEY, revision=old_revision, allow_failure=True)
        before_readable = before.returncode == 0 and before.stdout.rstrip("\n") == "synthetic-auto-marker-v1"
        lab.check("positive", "Periodic retention starts with the exact prior marker revision readable",
                  before_readable and latest_before == "synthetic-auto-marker-v2",
                  {"key": AUTO_KEY, "old_revision": old_revision,
                   "old_value_readable": before_readable,
                   "latest_value_is_current": latest_before == "synthetic-auto-marker-v2"})

        deadline = time.monotonic() + AUTO_WAIT_SECONDS
        expired_at = None
        last = before
        while time.monotonic() < deadline:
            time.sleep(0.5)
            last = exact_value(lab, container, AUTO_KEY, revision=old_revision, allow_failure=True)
            if last.returncode != 0 and (
                "required revision has been compacted" in last.stderr.lower()
                or "revision has been compacted" in last.stderr.lower()
            ):
                expired_at = time.monotonic()
                break
        latest = exact_value(lab, container, AUTO_KEY)
        latest_ok = latest.returncode == 0 and latest.stdout.rstrip("\n") == "synthetic-auto-marker-v2"
        compacted = expired_at is not None
        elapsed = (round(expired_at - (deadline - AUTO_WAIT_SECONDS), 3)
                   if expired_at else None)
        within_original_wait = elapsed is not None and elapsed <= AUTO_WAIT_SECONDS
        record_raw_evidence(
            lab,
            "periodic_compaction_expiry_timing",
            {"retention": AUTO_RETENTION,
             "maximum_wait_seconds": AUTO_WAIT_SECONDS,
             "elapsed_until_expiry_seconds": elapsed},
        )
        lab.check(
            "green", "The bounded periodic retention window automatically expires the old revision",
            compacted and within_original_wait and latest_ok,
            {"version": version, "retention": AUTO_RETENTION,
             "maximum_wait_seconds": AUTO_WAIT_SECONDS,
             "raw_evidence_file": RAW_EVIDENCE_FILE,
             "old_revision": old_revision, "old_revision_compacted": compacted,
             "expiry_observed_within_maximum_wait": within_original_wait,
             "latest_exact_key_read_available": latest_ok},
        )


def run(lab):
    suffix = lab.cluster.removeprefix("saf-lab-")
    manual_compaction_and_defrag(lab, f"saf-etcd-maint-{suffix}")
    automatic_expiry(lab, f"saf-etcd-auto-{suffix}")
