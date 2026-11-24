"""Python 3.9 runner for the disposable etcd maintenance Jobs."""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

NAMESPACE = "saf-etcd-fixture"
MEMBERS = ("etcd-0", "etcd-1", "etcd-2")
ENDPOINTS = tuple("http://%s.etcd.%s.svc.cluster.local:2379" % (m, NAMESPACE) for m in MEMBERS)
ETCDCTL = os.environ.get("ETCDCTL", "/tools/etcdctl")
AUTO_KEY = "/saf-k8s-lab/public/auto-retention-marker"
MARKER = "/saf-k8s-lab/public/marker"
COMPANION = "/saf-k8s-lab/public/companion"
VERSION = "/saf-k8s-lab/public/version"
PADDING_KEYS = ("/saf-k8s-lab/public/transient-padding-a", "/saf-k8s-lab/public/transient-padding-b")
OLD_VALUE = "synthetic-marker-v1"
NEW_VALUE = "synthetic-marker-v2"


def ctl(endpoint, *args, timeout=15, check=True):
    command = [ETCDCTL, "--endpoints=" + endpoint, "--dial-timeout=2s", "--command-timeout=8s"] + list(args)
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("etcdctl %s failed: %s" % (" ".join(args), result.stderr.strip()))
    return result


def exact(endpoint, key, revision=None, check=True):
    args = ["get", key, "--print-value-only"]
    if revision is not None:
        args.append("--rev=%s" % revision)
    return ctl(endpoint, *args, check=check)


def status(endpoint):
    result = ctl(endpoint, "endpoint", "status", "--write-out=json")
    rows = json.loads(result.stdout)
    if len(rows) != 1 or rows[0].get("Status", {}).get("errors"):
        raise RuntimeError("expected one error-free etcd endpoint status row")
    return rows[0]["Status"]


def version_check():
    result = subprocess.run([ETCDCTL, "version"], capture_output=True, text=True, timeout=10)
    if result.returncode or "3.6.8" not in result.stdout:
        raise RuntimeError("mounted etcdctl did not report the expected etcd v3.6.8 version")
    return result.stdout.strip()


def interlock(inject_bad_endpoint=None):
    members = []
    for member, endpoint in zip(MEMBERS, ENDPOINTS):
        health = ctl(endpoint, "endpoint", "health", timeout=12, check=False)
        actual_health = health.returncode == 0
        status_result = ctl(endpoint, "endpoint", "status", "--write-out=json", timeout=12, check=False)
        row = {}
        if status_result.returncode == 0:
            rows = json.loads(status_result.stdout)
            if len(rows) == 1:
                row = rows[0].get("Status", {})
        header = row.get("header", {})
        forced = endpoint == inject_bad_endpoint
        members.append({"member": member, "endpoint": endpoint,
                        "healthy": actual_health and bool(row) and not forced,
                        "actual_endpoint_health_passed": actual_health,
                        "forced_bad_endpoint_health": forced,
                        "member_id": str(header.get("member_id", "")),
                        "cluster_id": str(header.get("cluster_id", "")),
                        "leader": str(row.get("leader", "")),
                        "server_version": str(row.get("version", ""))})
    healthy = [m for m in members if m["healthy"]]
    ids = {m["member_id"] for m in healthy if m["member_id"]}
    clusters = {m["cluster_id"] for m in healthy if m["cluster_id"]}
    leaders = {m["leader"] for m in healthy if m["leader"] and m["leader"] != "0"}
    ok = (len(healthy) == 3 and len(healthy) >= 2 and len(ids) == 3 and len(clusters) == 1
          and len(leaders) == 1 and next(iter(leaders), "") in ids
          and all(m.get("server_version") == "3.6.8" for m in healthy))
    return ok, {"healthy_endpoints": len(healthy), "quorum": len(healthy) >= 2,
                "members": len(ids), "cluster_count": len(clusters), "leader_count": len(leaders),
                "members_seen": members}


def write_padding():
    # Two 64 KiB values keep argv below OS per-argument limits while preserving the prior 128 KiB bound.
    payload = "x" * (64 * 1024)
    for key in PADDING_KEYS:
        ctl(ENDPOINTS[0], "put", key, payload, timeout=20)
    for key in PADDING_KEYS:
        ctl(ENDPOINTS[0], "del", key)


def auto_compaction():
    ctl(ENDPOINTS[0], "put", AUTO_KEY, "synthetic-auto-marker-v1")
    old_revision = int(status(ENDPOINTS[0])["header"]["revision"])
    ctl(ENDPOINTS[1], "put", AUTO_KEY, "synthetic-auto-marker-v2")
    old = exact(ENDPOINTS[2], AUTO_KEY, old_revision, check=False)
    old_readable = old.returncode == 0 and old.stdout.rstrip("\n") == "synthetic-auto-marker-v1"
    if not old_readable:
        raise RuntimeError("old synthetic marker revision was not readable before expiry")
    deadline = time.monotonic() + 45
    compacted = False
    while time.monotonic() < deadline:
        probe = exact(ENDPOINTS[1], AUTO_KEY, old_revision, check=False)
        if probe.returncode and ("required revision has been compacted" in probe.stderr.lower()
                                 or "revision has been compacted" in probe.stderr.lower()):
            compacted = True
            break
        time.sleep(0.5)
    latest = exact(ENDPOINTS[2], AUTO_KEY, check=False)
    latest_ok = latest.returncode == 0 and latest.stdout.rstrip("\n") == "synthetic-auto-marker-v2"
    return {"old_revision_readable_before_expiry": old_readable, "old_revision_compacted": compacted,
            "latest_value_preserved": latest_ok, "old_revision": old_revision,
            "retention": "10s", "maximum_wait_seconds": 45}


def manual_compaction():
    ctl(ENDPOINTS[0], "put", MARKER, OLD_VALUE)
    old_revision = int(status(ENDPOINTS[0])["header"]["revision"])
    ctl(ENDPOINTS[1], "put", MARKER, NEW_VALUE)
    ctl(ENDPOINTS[2], "put", COMPANION, "synthetic-companion-v1")
    ctl(ENDPOINTS[0], "put", VERSION, "synthetic-version-v1")
    write_padding()
    ctl(ENDPOINTS[1], "put", VERSION, "synthetic-version-v1")
    before_compact = status(ENDPOINTS[0])
    old_before = exact(ENDPOINTS[2], MARKER, old_revision, check=False)
    old_readable = old_before.returncode == 0 and old_before.stdout.rstrip("\n") == OLD_VALUE
    current_revision = int(before_compact["header"]["revision"])
    ctl(ENDPOINTS[0], "compact", str(current_revision), "--physical", timeout=30)
    old_after = exact(ENDPOINTS[2], MARKER, old_revision, check=False)
    old_rejected = old_after.returncode != 0 and (
        "required revision has been compacted" in old_after.stderr.lower()
        or "revision has been compacted" in old_after.stderr.lower())
    latest = {MARKER: exact(ENDPOINTS[2], MARKER).stdout.rstrip("\n") == NEW_VALUE,
              COMPANION: exact(ENDPOINTS[1], COMPANION).stdout.rstrip("\n") == "synthetic-companion-v1",
              VERSION: exact(ENDPOINTS[0], VERSION).stdout.rstrip("\n") == "synthetic-version-v1"}
    before_defrag = status(ENDPOINTS[0])
    return {"old_revision": old_revision, "compacted_revision": current_revision,
            "old_revision_readable_before_compaction": old_readable,
            "old_revision_rejected_as_compacted": old_rejected, "latest_reads": latest,
            "allocated_before_defrag": int(before_defrag["dbSize"]),
            "in_use_before_defrag": int(before_defrag["dbSizeInUse"])}


def maintain_members(inject_bad_endpoint=None):
    """The same fail-closed function runs the positive and forced-failure paths."""
    actions = []
    command_attempts = []
    for index, (member, endpoint) in enumerate(zip(MEMBERS, ENDPOINTS)):
        ok, pre = interlock(inject_bad_endpoint=inject_bad_endpoint)
        if not ok:
            actions.append({"member": member, "action": "defrag", "issued": False,
                            "reason": "pre-maintenance endpoint-health/membership/leader interlock failed",
                            "pre_interlock": pre})
            break
        # Record this event immediately before invoking the real member-local etcdctl defrag.
        attempt = {"member": member, "endpoint": endpoint, "action": "defrag"}
        command_attempts.append(attempt)
        print("MAINTENANCE_COMMAND_ATTEMPT " + json.dumps(attempt, sort_keys=True), flush=True)
        result = ctl(endpoint, "defrag", timeout=55)
        ok_after, post = interlock()
        read_member = MEMBERS[(index + 1) % len(MEMBERS)]
        remote_value = exact(ENDPOINTS[(index + 1) % len(ENDPOINTS)], MARKER).stdout.rstrip("\n")
        actions.append({"member": member, "action": "defrag", "issued": True,
                        "finished": result.returncode == 0, "pre_interlock": pre,
                        "post_interlock": post, "benign_marker_read_from": read_member,
                        "benign_marker_preserved": remote_value == NEW_VALUE,
                        "interlocks_passed": ok_after})
        if not result.returncode == 0 or not ok_after or remote_value != NEW_VALUE:
            raise RuntimeError("defrag, post-action cluster health, or remote marker verification failed")
    return actions, command_attempts


def negative_comparison():
    marker = "/saf-k8s-lab/public/negative-marker"
    ctl(ENDPOINTS[0], "put", marker, "synthetic-negative-v1")
    value = ""
    actions, attempts = maintain_members(inject_bad_endpoint=ENDPOINTS[2])
    read = exact(ENDPOINTS[1], marker)
    value = read.stdout.rstrip("\n")
    forced = any(m.get("forced_bad_endpoint_health") and not m.get("healthy")
                 for m in actions[0].get("pre_interlock", {}).get("members_seen", []))
    return {"interlock_passed": False, "forced_bad_endpoint_health": forced,
            "attempted_maintenance_commands": len(attempts), "actions": actions,
            "marker_read_from_other_member": value == "synthetic-negative-v1",
            "marker_value": value, "result": "passed" if forced and not attempts and value == "synthetic-negative-v1" else "failed"}


def scheduled_maintenance():
    started = datetime.now(timezone.utc)
    result = {"scheduled": True, "started_utc": started.isoformat(),
              "controller_scheduled_timestamp": os.environ.get("SCHEDULED_TIMESTAMP", ""),
              "members_owned": list(MEMBERS), "actions": []}
    version = version_check()
    result["etcdctl_version"] = version
    auto = auto_compaction()
    if not auto["old_revision_compacted"] or not auto["latest_value_preserved"]:
        raise RuntimeError("periodic auto-compaction assertion failed")
    manual = manual_compaction()
    result["auto_compaction"] = auto
    result["manual_compaction"] = manual
    if not manual["old_revision_readable_before_compaction"] or not manual["old_revision_rejected_as_compacted"] or not all(manual["latest_reads"].values()):
        raise RuntimeError("manual compaction assertions failed")
    before_size = manual["allocated_before_defrag"]
    actions, attempts = maintain_members()
    after_status = status(ENDPOINTS[0])
    after_size = int(after_status["dbSize"])
    all_markers = {
        MARKER: exact(ENDPOINTS[1], MARKER).stdout.rstrip("\n") == NEW_VALUE,
        COMPANION: exact(ENDPOINTS[2], COMPANION).stdout.rstrip("\n") == "synthetic-companion-v1",
        VERSION: exact(ENDPOINTS[0], VERSION).stdout.rstrip("\n") == "synthetic-version-v1",
        AUTO_KEY: exact(ENDPOINTS[1], AUTO_KEY).stdout.rstrip("\n") == "synthetic-auto-marker-v2",
    }
    result.update({"actions": actions, "attempted_maintenance_commands": len(attempts),
                   "allocated_bytes_before_defrag": before_size, "allocated_bytes_after_defrag": after_size,
                   "allocated_bytes_reclaimed": after_size < before_size,
                   "all_latest_markers_readable": all(all_markers.values()),
                   "latest_marker_reads": all_markers, "result": "passed"})
    if not result["allocated_bytes_reclaimed"] or not result["all_latest_markers_readable"]:
        raise RuntimeError("defrag byte-reclaim or latest marker assertion failed")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("auto-compaction", "negative", "scheduled"), required=True)
    mode = parser.parse_args().mode
    record = {"mode": mode, "result": "failed"}
    try:
        record["etcdctl_version"] = version_check()
        if mode == "auto-compaction":
            record.update(auto_compaction())
            record["result"] = "passed" if record["old_revision_readable_before_expiry"] and record["old_revision_compacted"] and record["latest_value_preserved"] else "failed"
        elif mode == "negative":
            record.update(negative_comparison())
        else:
            record = scheduled_maintenance()
        if record.get("result") != "passed":
            raise RuntimeError("fixture result predicates did not pass")
    except Exception as error:
        record["result"] = "failed"
        record["error"] = str(error)
        print("ERROR " + str(error), file=sys.stderr)
    print("RUN_EVIDENCE " + json.dumps(record, sort_keys=True))
    return 0 if record.get("result") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
