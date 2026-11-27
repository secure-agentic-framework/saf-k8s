"""Bind each reviewed historical T4 reading to an immutable hold record."""

import hashlib
import json
import re
from pathlib import Path


SOURCE_COMMIT = "23a8b7a4be1fec186b4138fc30e12ab0964e33b9"
SOURCE_SHA256 = "907e0801f74229eb074bb04c8fc70681ab181cd908281076b5f123af436f0b68"
RECEIPT_HASHES = {
    ("run-1", "idle"): "2e739e08bcedea3e99d1af2d84b4cd6902f2dee1210d57de0c8e461735e37217",
    ("run-1", "allocated"): "5add18a7db9124948b71a51d4dc7e9a051e11e487371ae42edf9c5c66c6ddbdd",
    ("run-2", "idle"): "ff84433f9a6497f43d75a136885f0c440e5cc209bd57658b097becc8259ce3d3",
    ("run-2", "allocated"): "b14b2f972e4bba8c37c1d05c0ff4ee48dd3b5ba12ebe4bc84ee584a4cd98b628",
}
NAMESPACE = "saf-test"
OWNER = "fixture-response-reviewer"
MESSAGE = "Fixture escalation requires corroborated evidence and an authorized reviewer"
HOLD_NAME = "fixture-decision-t4-historical-hold"
ESCALATION_NAME = "fixture-decision-t4-historical-escalation"
COMPARATOR = "fixture-response-comparator"
THRESHOLD_MIB = 100


def _load_evidence():
    source_bytes = (Path(__file__).with_name("t4-reference-result.json")).read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    if source_hash != SOURCE_SHA256:
        raise RuntimeError("Pinned public T4 summary digest mismatch")
    source = json.loads(source_bytes)
    if (source.get("schema") != "saf-k8s-dcgm-t4-reference-v1"
            or source.get("control") != "SAF-K8S-1002-003"
            or source.get("status") != "passed"
            or len(source.get("runs", [])) != 2):
        raise RuntimeError("Pinned T4 summary is not the reviewed two-run reference")
    candidates = []
    for run in source["runs"]:
        run_name = run.get("run")
        workload_ref = run.get("workload_uid_sha256")
        if run_name not in ("run-1", "run-2") or not re.fullmatch(r"[0-9a-f]{64}", str(workload_ref)):
            raise RuntimeError("Reference summary lacks expected pseudonymous workload identity")
        observation = run.get("observation", {})
        selected = {}
        for phase, expected in (("idle", 0), ("allocated", 232)):
            record = observation.get(phase, {})
            if record.get("receipt_sha256") != RECEIPT_HASHES[(run_name, phase)]:
                raise RuntimeError("T4 receipt digest is not the independently reviewed value")
            rows = [item for item in record.get("samples", [])
                    if item.get("metric") == "DCGM_FI_DEV_FB_USED"]
            if len(rows) != 1:
                raise RuntimeError("Reference must contain exactly one selected framebuffer sample")
            row = rows[0]
            if not (row.get("direct_value") == expected and row.get("prometheus_value") == expected
                    and row.get("absolute_delta") == 0 and row.get("unit") == "MiB"
                    and row.get("uid_binding") == "direct_pod_uid_label"
                    and isinstance(row.get("sample_skew_seconds"), (float, int))
                    and 0 <= row["sample_skew_seconds"] <= 10):
                raise RuntimeError("T4 sample does not match the published direct/Prometheus join")
            interval = record.get("interval", {})
            if not (isinstance(interval.get("start_utc"), str)
                    and isinstance(interval.get("end_utc"), str)):
                raise RuntimeError("Historical capture interval is absent")
            selected[phase] = {"value_mib": expected, "receipt_sha256": record["receipt_sha256"],
                               "capture_interval": interval,
                               "sample_skew_seconds": row["sample_skew_seconds"]}
        if selected["idle"]["value_mib"] != 0 or selected["allocated"]["value_mib"] <= THRESHOLD_MIB:
            raise RuntimeError("The retained pair does not bound the historical review threshold")
        candidates.append({"run_ref": run_name, "workload_ref": workload_ref,
                           "idle": selected["idle"], "allocated": selected["allocated"]})
    if len({row["workload_ref"] for row in candidates}) != 2:
        raise RuntimeError("The two historical workloads must have distinct pseudonymous references")
    return {"source_commit": SOURCE_COMMIT, "source_summary_sha256": source_hash,
            "hardware_class": "NVIDIA Tesla T4", "metric": "DCGM_FI_DEV_FB_USED", "unit": "MiB",
            "threshold_mib": THRESHOLD_MIB, "source_age_class": "historical",
            "known_good_fixture_allocation": True, "freshness_evaluated": False,
            "runs": candidates}


def _hold_object(evidence, selected):
    sample = selected["allocated"]
    run_name = selected["run_ref"]
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": f"{HOLD_NAME}-{run_name}", "labels": {"fixture.example/evidence-class": "historical-t4"}},
            "immutable": True,
            "data": {
                "disposition": "hold",
                "signal": "high",
                "workload": "approved",
                "corroboration": "missing",
                "source_kind": "historical_receipt",
                "source_commit": evidence["source_commit"],
                "source_summary_sha256": evidence["source_summary_sha256"],
                "source_capture_ref": f"{run_name}-allocated",
                "source_receipt_sha256": sample["receipt_sha256"],
                "workload_ref": selected["workload_ref"],
                "metric": evidence["metric"],
                "observed_mib": str(sample["value_mib"]),
                "threshold_mib": str(evidence["threshold_mib"]),
                "capture_age": evidence["source_age_class"],
                "capture_start_utc": sample["capture_interval"]["start_utc"],
                "capture_end_utc": sample["capture_interval"]["end_utc"],
                "known_good_fixture_allocation": "true",
                "independent_corroboration": "missing",
            }}


def _submit(lab, body):
    return lab.kubectl("--as", OWNER, "create", "-f", "-", "-o", "json", "--dry-run=server",
                       payload=json.dumps(body), allow_failure=True)


def _denied_by_review_policy(result):
    stderr = result.stderr or ""
    return (result.returncode != 0 and "fixture-incident-review" in stderr
            and MESSAGE in stderr)


def _deployment_state(lab):
    response = json.loads(lab.kubectl("get", "deployment", COMPARATOR, "-o", "json").stdout)
    meta = response.get("metadata", {})
    spec = response.get("spec", {})
    status = response.get("status", {})
    return {"uid": meta.get("uid", ""), "replicas": spec.get("replicas"),
            "ready_replicas": status.get("readyReplicas", 0)}


def verify_hold(lab, evidence, capture):
    hold = _hold_object(evidence, capture)
    hold_name = hold["metadata"]["name"]
    created = lab.kubectl("--as", OWNER, "create", "-f", "-", "-o", "json",
                          payload=json.dumps(hold), allow_failure=True)
    readback = {}
    if created.returncode == 0:
        readback = json.loads(lab.kubectl("get", "configmap", hold_name, "-o", "json").stdout)
    metadata = readback.get("metadata", {})
    uid = metadata.get("uid")
    bound = (readback.get("immutable") is True and bool(uid)
             and metadata.get("name") == hold_name and metadata.get("namespace") == NAMESPACE
             and readback.get("data") == hold["data"])

    escalation = json.loads(json.dumps(hold))
    escalation["metadata"]["name"] = f"{ESCALATION_NAME}-{capture['run_ref']}"
    escalation["data"]["disposition"] = "escalate"
    denied = _denied_by_review_policy(_submit(lab, escalation))
    return {
        "capture_ref": capture["run_ref"],
        "hold_uid_sha256": hashlib.sha256(uid.encode()).hexdigest() if uid else None,
        "hold_immutable_and_bound": bound,
        "reviewer_escalation_denied_by_exact_policy": denied,
    }


def run(lab):
    evidence = _load_evidence()
    before = _deployment_state(lab)
    if not before["uid"] or before["replicas"] != 1 or before["ready_replicas"] != 1:
        lab.block("The existing fixture comparator is not available before the historical hold review")

    decisions = [verify_hold(lab, evidence, capture) for capture in evidence["runs"]]
    hold_bound = all(record["hold_immutable_and_bound"] for record in decisions)
    denied = all(record["reviewer_escalation_denied_by_exact_policy"] for record in decisions)
    unchanged = _deployment_state(lab) == before
    raw = {**evidence, "scope": "Immutable holds and native admission denials for known-good historical T4 captures.",
           "decisions": decisions,
           "comparator_uid_sha256": hashlib.sha256(before["uid"].encode()).hexdigest(),
           "comparator_same_uid_and_available_after": unchanged,
           "disruptive_action_requested": False,
           "incident_or_misuse_claimed": False}
    (lab.evidence / "historical-t4-triage-hold.raw.json").write_text(json.dumps(raw, sort_keys=True, indent=2) + "\n")
    lab.check("historical-hold", "Both known-good historical T4 readings remain bound holds without corroboration",
              hold_bound and denied and unchanged, {"historical_captures": len(decisions),
                       "pinned_historical_sources_bound": hold_bound,
                       "case_reviewer_escalations_denied_by_policy": denied,
                       "existing_comparator_unchanged": unchanged,
                       "freshness_evaluated": False,
                       "disruptive_action_requested": False,
                       "incident_or_misuse_claimed": False,
                       "raw_evidence": "historical-t4-triage-hold.raw.json"})
