#!/usr/bin/env python3
"""Read-only classifier for versioned Pod user-namespace kubelet preflight JSON.

No host files or services are read. --self-test uses fixed inert JSON fixtures.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

MAX_UID = 2**32 - 1
USERNS_UNIT = 65536
PATCHED_TARGETS = {"v1.35.11", "v1.36.7", "v1.37.3"}


def hold(reason: str, **details: object) -> dict[str, object]:
    return {"decision": "HOLD", "reason": reason, **details}


def uint(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_UID


def parse_getsubids(output: object) -> tuple[int, int] | None:
    # Match parseGetSubIdsOutput: one line, exactly four fields, and uint32
    # decimal start/count. The command invocation itself supplies the account.
    if not isinstance(output, str):
        return None
    lines = output.strip("\n").split("\n")
    if len(lines) != 1:
        return None
    fields = lines[0].split()
    if len(fields) != 4 or not fields[2].isdigit() or not fields[3].isdigit():
        return None
    start, count = int(fields[2]), int(fields[3])
    if start > MAX_UID or count > MAX_UID:
        return None
    return start, count


def effective_range(record: dict[str, object], ids_per_pod: int) -> tuple[int, int] | dict[str, object]:
    source = record.get("range_source")
    account_present = record.get("kubelet_account_present")
    helper_present = record.get("getsubids_present")
    if not isinstance(account_present, bool) or not isinstance(helper_present, bool):
        return hold("kubelet account or getsubids presence is unknown")
    if source == "getsubids":
        if not account_present or not helper_present:
            return hold("getsubids source conflicts with account/helper presence")
        provenance = record.get("helper_provenance")
        if not isinstance(provenance, dict) or not all(
                isinstance(provenance.get(k), str) and provenance[k].strip()
                for k in ("resolved_path", "package_or_build", "uid_command", "gid_command")):
            return hold("resolved helper provenance and both command identities are required")
        if provenance["uid_command"] != "getsubids kubelet" or provenance["gid_command"] != "getsubids -g kubelet":
            return hold("helper commands do not match kubelet UID/GID lookup")
        uid_out, gid_out = record.get("getsubids_uid_output"), record.get("getsubids_gid_output")
        if not isinstance(uid_out, str) or not isinstance(gid_out, str) or uid_out != gid_out:
            return hold("raw getsubids UID and GID output is missing or differs")
        parsed = parse_getsubids(uid_out)
        if parsed is None:
            return hold("getsubids output is not exactly one parseable four-field line")
        return parsed
    if source == "target_default_fallback":
        if record.get("target_fallback_confirmed") is not True:
            return hold("fallback behavior is not confirmed for this exact target")
        if helper_present and account_present:
            return hold("helper-present kubelet account must use getsubids output, not default fallback")
        reason = record.get("fallback_reason")
        if account_present and helper_present is False and reason != "helper_absent":
            return hold("fallback reason does not establish helper absence")
        if account_present is False and reason != "account_absent":
            return hold("fallback reason does not establish account absence")
        # defaultKubeletMappings: [idsPerPod, 2^32 - idsPerPod - idsPerPod)
        return ids_per_pod, 2**32 - 2 * ids_per_pod
    return hold("effective mapping source is unknown")


def evaluate(record: object) -> dict[str, object]:
    if not isinstance(record, dict):
        return hold("input must be a JSON object")
    source_version, target = record.get("source_kubelet_version"), record.get("target_kubelet_version")
    if not isinstance(source_version, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", source_version):
        return hold("source kubelet version is missing or malformed")
    if not isinstance(target, str) or target not in PATCHED_TARGETS:
        return hold("no reviewed range guidance for exact target version", target=target)
    if record.get("userns_in_use") is False:
        return {"decision": "NOT_APPLICABLE", "reason": "user namespaces are not in this node-pool scope",
                "target_kubelet_version": target, "change_performed": False}
    if record.get("userns_in_use") is not True:
        return hold("user-namespace applicability is unknown")
    if record.get("observation_mode") not in ("read_only", "synthetic_fixture"):
        return hold("input provenance is not an approved read-only observation or fixture")

    ids = record.get("ids_per_pod")
    max_pods = record.get("max_pods")
    if not uint(ids) or ids == 0 or ids % USERNS_UNIT:
        return hold("idsPerPod must be a positive multiple of 65536")
    if not uint(max_pods) or max_pods == 0 or max_pods > MAX_UID:
        return hold("effective kubelet maxPods is missing or invalid")
    assert isinstance(ids, int) and isinstance(max_pods, int)
    mapping = effective_range(record, ids)
    if isinstance(mapping, dict):
        return mapping
    start, count = mapping
    if count == 0 or start % ids or start < ids:
        return hold("mapping start/count violates nonzero aligned subordinate range constraints", start=start, count=count)
    # kubelet rejects start+count > MaxUint32. Equality excludes the invalid ID.
    if start + count > MAX_UID:
        return hold("mapping reaches/passes invalid UID boundary", start=start, count=count)
    if count % ids:
        return hold("mapping length is not a multiple of idsPerPod", start=start, count=count)
    if count // ids < max_pods:
        return hold("mapping capacity is below effective maxPods", slots=count // ids, max_pods=max_pods)

    inventory = record.get("persisted_mapping_inventory")
    if not isinstance(inventory, dict) or inventory.get("complete_read_only_inventory") is not True:
        return hold("complete read-only inventory of persisted Pod mapping files is required")
    entries = inventory.get("pods")
    if not isinstance(entries, list):
        return hold("persisted Pod inventory is missing")
    seen: set[int] = set()
    pod_uids: set[str] = set()
    for i, pod in enumerate(entries):
        if not isinstance(pod, dict) or not isinstance(pod.get("uid"), str) or not pod["uid"]:
            return hold("persisted Pod inventory entry is malformed", index=i)
        if pod["uid"] in pod_uids:
            return hold("persisted Pod inventory repeats a Pod UID", index=i)
        pod_uids.add(pod["uid"])
        mappings = pod.get("userns")
        if mappings is None:
            continue
        if not isinstance(mappings, dict):
            return hold("persisted mapping file is not a JSON mapping object", index=i)
        uids, gids = mappings.get("uidMappings"), mappings.get("gidMappings")
        if not isinstance(uids, list) or len(uids) != 1 or not isinstance(gids, list) or gids != uids:
            return hold("persisted UID/GID mapping arrays are not exactly one identical mapping", index=i)
        item = uids[0]
        if (not isinstance(item, dict) or not isinstance(item.get("containerId"), int)
                or isinstance(item.get("containerId"), bool) or item.get("containerId") != 0):
            return hold("persisted mapping does not map container ID zero", index=i)
        host, length = item.get("hostId"), item.get("length")
        if not uint(host) or length != ids or not isinstance(length, int) or isinstance(length, bool):
            return hold("persisted mapping length/host ID is invalid", index=i)
        if host % ids or host < start or host + ids > start + count:
            return hold("persisted mapping is misaligned or outside the target range", index=i, host_id=host)
        if host in seen:
            return hold("persisted Pod mapping allocation is duplicated", index=i, host_id=host)
        seen.add(host)

    if record.get("failed_create_pod_sandbox_event") is not False:
        return hold("FailedCreatePodSandBox event state is true or unknown",
                    failed_create_pod_sandbox_event=record.get("failed_create_pod_sandbox_event"))
    return {"decision": "ELIGIBLE_FOR_SEPARATE_CHANGE_APPROVAL",
            "reason": "target range arithmetic and complete persisted mapping inventory pass this read-only preflight",
            "target_kubelet_version": target, "range_source": record.get("range_source"),
            "ids_per_pod": ids, "effective_range": {"start": start, "count": count},
            "persisted_userns_pods": len(seen), "change_performed": False}


def self_test(fixtures_dir: Path) -> int:
    failures = 0
    paths = sorted(fixtures_dir.glob("*.json"))
    for path in paths:
        fixture = json.loads(path.read_text())
        expected = fixture.pop("expected_decision")
        result = evaluate(fixture)
        passed = result["decision"] == expected
        print(json.dumps({"fixture": path.name, "expected": expected, "actual": result["decision"],
                          "self_test": "PASS" if passed else "FAIL", "result": result}, sort_keys=True))
        failures += not passed
    if not paths:
        print("no fixtures found", file=sys.stderr)
        return 2
    return int(failures != 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="sanitized JSON built from approved read-only observations")
    parser.add_argument("--self-test", action="store_true", help="evaluate only fixed synthetic JSON fixtures")
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).parent / "fixtures")
    args = parser.parse_args()
    if args.self_test:
        return self_test(args.fixtures)
    if args.input is None:
        parser.error("provide --input or --self-test")
    try:
        record = json.loads(args.input.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"decision": "HOLD", "reason": f"cannot read valid JSON input: {exc}"}))
        return 2
    result = evaluate(record)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["decision"] == "ELIGIBLE_FOR_SEPARATE_CHANGE_APPROVAL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
