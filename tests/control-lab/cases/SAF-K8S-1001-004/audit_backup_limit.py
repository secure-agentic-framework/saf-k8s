"""Verify bounded kube-apiserver audit backup-count pruning with inert writes."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import time

NAMESPACE = "saf-test"
MAXSIZE_MIB = 1
MAXSIZE_BYTES = MAXSIZE_MIB * 1024 * 1024
MAXBACKUP = 2
MAXAGE_DAYS = 7
VALUE_BYTES = 400 * 1024
ACTIVE_NAME = "audit.jsonl"
ROTATED_NAME = re.compile(r"^audit-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}\.jsonl$")
MARKERS = tuple(f"saf-audit-backup-{index:02d}" for index in range(1, 5))
ROTATION_WAIT_SECONDS = 12


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _event_for_marker(event, marker):
    ref = event.get("objectRef", {})
    return (ref.get("resource") == "configmaps" and ref.get("namespace") == NAMESPACE
            and ref.get("name") == marker and event.get("verb") == "create")


def _read_records(audit_dir, markers=MARKERS):
    audit_path = audit_dir / ACTIVE_NAME
    paths = sorted((path for path in audit_dir.iterdir() if path.is_file()),
                   key=lambda path: path.name)
    rotated = [path for path in paths if ROTATED_NAME.fullmatch(path.name)]
    records = []
    for path in paths:
        try:
            lines = path.read_bytes().splitlines()
        except FileNotFoundError:
            continue  # A rotation or asynchronous prune changed this snapshot.
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            for marker in markers:
                if _event_for_marker(event, marker):
                    request_value = event.get("requestObject", {}).get("data", {}).get("fixture", "")
                    response_value = event.get("responseObject", {}).get("data", {}).get("fixture", "")
                    records.append({
                        "marker": marker,
                        "audit_id": event.get("auditID"),
                        "file": path.name,
                        "line_bytes": len(line) + 1,
                        "line_sha256": _sha256(line),
                        "stage": event.get("stage"),
                        "level": event.get("level"),
                        "response_code": event.get("responseStatus", {}).get("code"),
                        "request_value_bytes": len(request_value.encode("utf-8")) if isinstance(request_value, str) else -1,
                        "response_value_bytes": len(response_value.encode("utf-8")) if isinstance(response_value, str) else -1,
                        "full_request_response_present": request_value == "x" * VALUE_BYTES
                        and response_value == "x" * VALUE_BYTES,
                    })
    return audit_path, paths, rotated, records


def run(lab, temporary):
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1 for backup-limit fixture, got {version}")
    # Reuse the exact isolated file-backend profile created by audit_rotation.py.
    # The earlier two-marker assertion has already been captured; these four
    # additional inert writes exercise only count-based backup pruning.
    audit_dir = temporary / "rotation-audit"
    policy_path = temporary / "audit-policy-rotation.yaml"
    config_path = temporary / "kind-audit-rotation.yaml"
    create_results = []
    first_marker_observation = None
    for marker in MARKERS:
        manifest = temporary / f"{marker}.json"
        obj = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": marker, "namespace": NAMESPACE},
            "data": {"fixture": "x" * VALUE_BYTES, "marker": marker},
        }
        manifest.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
        result = lab.kubectl("create", "-f", str(manifest), timeout=45)
        create_results.append({"marker": marker, "return_code": result.returncode})
        if marker == MARKERS[0]:
            checkpoint_deadline = time.monotonic() + ROTATION_WAIT_SECONDS
            while time.monotonic() < checkpoint_deadline:
                _path, _paths, _rotated, checkpoint_records = _read_records(audit_dir)
                matched = [record for record in checkpoint_records
                           if record["marker"] == MARKERS[0]]
                if len(matched) == 1:
                    first_marker_observation = matched[0]
                    break
                time.sleep(0.25)

    deadline = time.monotonic() + ROTATION_WAIT_SECONDS
    paths, rotated, records = [], [], []
    while time.monotonic() < deadline:
        _audit_path, paths, rotated, records = _read_records(audit_dir)
        occurrences = {marker: sum(record["marker"] == marker for record in records)
                       for marker in MARKERS}
        if (len(rotated) == MAXBACKUP and len(paths) == MAXBACKUP + 1
                and occurrences == {MARKERS[0]: 0, MARKERS[1]: 1, MARKERS[2]: 1, MARKERS[3]: 1}):
            break
        time.sleep(0.25)

    audit_path, paths, rotated, records = _read_records(audit_dir)
    records.sort(key=lambda item: MARKERS.index(item["marker"]))
    occurrences = {marker: sum(record["marker"] == marker for record in records)
                   for marker in MARKERS}
    retained = MARKERS[1:]
    retained_once = all(occurrences[marker] == 1 for marker in retained)
    first_marker_seen_before_pruning = (first_marker_observation is not None
                                       and first_marker_observation["full_request_response_present"]
                                       and first_marker_observation["stage"] == "ResponseComplete"
                                       and first_marker_observation["level"] == "RequestResponse")
    first_marker_id_not_retained = (bool((first_marker_observation or {}).get("audit_id"))
                                    and (first_marker_observation or {}).get("audit_id")
                                    not in {record["audit_id"] for record in records})
    oldest_pruned = (first_marker_seen_before_pruning and occurrences[MARKERS[0]] == 0
                     and first_marker_id_not_retained)
    unique_ids = (len([record["audit_id"] for record in records]) == 3
                  and all(record["audit_id"] for record in records)
                  and len({record["audit_id"] for record in records}) == 3)
    exact_events = len(records) == 3 and all(
        record["marker"] in retained and record["stage"] == "ResponseComplete"
        and record["level"] == "RequestResponse" and record["response_code"] == 201
        and record["full_request_response_present"] for record in records)
    all_event_line_bytes = ([first_marker_observation["line_bytes"]]
                            if first_marker_observation is not None else [])
    all_event_line_bytes.extend(record["line_bytes"] for record in records)
    all_events_subthreshold_sized = len(all_event_line_bytes) == 4 and all(
        MAXSIZE_BYTES // 2 < size < MAXSIZE_BYTES for size in all_event_line_bytes)
    exact_files = (audit_path.is_file() and len(rotated) == MAXBACKUP
                   and len(paths) == MAXBACKUP + 1
                   and all(path.name == ACTIVE_NAME or ROTATED_NAME.fullmatch(path.name)
                           for path in paths))
    # Retained record placement must show rotation, with the newest event in active.
    newest_active = len(records) == 3 and next(
        (record for record in records if record["marker"] == MARKERS[3]), {}).get("file") == ACTIVE_NAME
    file_observations = [{"name": path.name, "bytes": path.stat().st_size,
                          "sha256": _sha256(path.read_bytes())} for path in paths]
    aggregate_bytes = sum(item["bytes"] for item in file_observations)
    bounded_files = (len(paths) <= MAXBACKUP + 1 and aggregate_bytes <= 5 * MAXSIZE_BYTES)
    result = {
        "fixture_only": True,
        "configured_maxsize_mib": MAXSIZE_MIB,
        "configured_maxbackup": MAXBACKUP,
        "configured_maxage_days": MAXAGE_DAYS,
        "configuration_sha256": _sha256(config_path.read_bytes()),
        "policy_sha256": _sha256(policy_path.read_bytes()),
        "value_bytes_per_configmap": VALUE_BYTES,
        "create_results": create_results,
        "first_marker_seen_before_pruning": first_marker_seen_before_pruning,
        "first_marker_initial_location": (first_marker_observation or {}).get("file"),
        "first_marker_initial_audit_id": (first_marker_observation or {}).get("audit_id"),
        "first_marker_initial_line_sha256": (first_marker_observation or {}).get("line_sha256"),
        "first_marker_id_absent_after_pruning": first_marker_id_not_retained,
        "active_filename": ACTIVE_NAME,
        "rotated_filenames": [path.name for path in rotated],
        "exact_backup_cap_and_active": exact_files,
        "oldest_marker_pruned_by_count_limit": oldest_pruned,
        "newest_three_markers_retained_once": retained_once,
        "three_distinct_audit_ids": unique_ids,
        "retained_events_full_fidelity": exact_events,
        "all_four_event_lines_subthreshold_but_rotation_sized": all_events_subthreshold_sized,
        "newest_marker_in_active_file": newest_active,
        "occurrences": occurrences,
        "aggregate_file_bytes": aggregate_bytes,
        "bounded_files": bounded_files,
        "files": file_observations,
        "retained_events": records,
    }
    (lab.evidence / "audit-backup-limit-observation.raw.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n")
    return {
        "four_writes_succeeded": len(create_results) == 4 and all(
            result["return_code"] == 0 for result in create_results),
        "oldest_marker_observed_before_pruning": first_marker_seen_before_pruning,
        "exactly_two_backups_plus_active": exact_files,
        "oldest_marker_pruned_by_backup_limit": oldest_pruned,
        "newest_three_full_fidelity_markers_retained_once": retained_once and unique_ids and exact_events,
        "all_four_records_subthreshold_and_large_enough_to_rotate": all_events_subthreshold_sized,
        "newest_event_in_active_file": newest_active,
        "bounded_output": bounded_files,
    }


def exercise_age_limit(lab, temporary):
    audit_dir = temporary / "rotation-audit"
    _active, paths, backups, prior = _read_records(audit_dir)
    if len(backups) != MAXBACKUP or len(paths) != MAXBACKUP + 1:
        lab.block("Expected the exact backup-count snapshot before the age contrast")
    oldest_retained = next((row for row in prior if row["marker"] == MARKERS[1]), {})
    aged_source = audit_dir / oldest_retained.get("file", "")
    if aged_source not in backups:
        lab.block("The first retained fixture marker was not in a rotated log")

    # Keep the count below the threshold, so count pruning cannot explain
    # the old file disappearing. All files belong to this disposable case.
    kept = temporary / "backup-count-snapshot"
    kept.mkdir()
    for backup in backups:
        if backup != aged_source:
            backup.rename(kept / backup.name)
    old_time = datetime.now(timezone.utc) - timedelta(days=MAXAGE_DAYS + 1)
    old_stamp = old_time.strftime("%Y-%m-%dT%H-%M-%S.%f")[:-3]
    old_path = audit_dir / f"audit-{old_stamp}.jsonl"
    aged_source.rename(old_path)
    _active, _, pre_files, pre_records = _read_records(audit_dir)
    present_old = any(row["file"] == old_path.name and row["audit_id"] == oldest_retained["audit_id"]
                      for row in pre_records)
    recent_mtime = time.time() - old_path.stat().st_mtime < (MAXAGE_DAYS - 1) * 86400
    count_below_limit = len(pre_files) == 1 and len(pre_files) + 1 <= MAXBACKUP

    marker = "saf-audit-age-trigger"
    manifest = temporary / f"{marker}.json"
    manifest.write_text(json.dumps({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": marker, "namespace": NAMESPACE},
        "data": {"fixture": "x" * VALUE_BYTES},
    }, separators=(",", ":")) + "\n")
    lab.kubectl("create", "-f", str(manifest), timeout=45)
    deadline = time.monotonic() + ROTATION_WAIT_SECONDS
    while time.monotonic() < deadline:
        _active, _, after_files, records = _read_records(audit_dir, (*MARKERS, marker))
        if not old_path.exists() and len(after_files) == 1:
            break
        time.sleep(0.25)

    _active, _, after_files, records = _read_records(audit_dir, (*MARKERS, marker))
    current = [row for row in records if row["marker"] == marker]
    previous = [row for row in records if row["marker"] == MARKERS[3]]
    flags = {
        "known_old_file_present_before_rotation": present_old,
        "old_filename_and_recent_modification_time": recent_mtime,
        "rotation_would_not_exceed_backup_count": count_below_limit,
        "old_named_backup_absent": not old_path.exists(),
        "one_recent_rotation_present": len(after_files) == 1 and len(previous) == 1
            and previous[0]["file"] == after_files[0].name and previous[0]["full_request_response_present"],
        "new_marker_in_active_with_full_fidelity": len(current) == 1 and current[0]["file"] == ACTIVE_NAME
            and current[0]["full_request_response_present"] and current[0]["response_code"] == 201,
    }
    (lab.evidence / "audit-backup-age-observation.raw.json").write_text(json.dumps({
        "older_backup_name": old_path.name, "source_audit_id": oldest_retained["audit_id"],
        "expected_age_days": MAXAGE_DAYS, "rotated_names_after": [file.name for file in after_files],
        "recent_marker_records": [*previous, *current], "observations": flags,
    }, indent=2, sort_keys=True) + "\n")
    return flags
