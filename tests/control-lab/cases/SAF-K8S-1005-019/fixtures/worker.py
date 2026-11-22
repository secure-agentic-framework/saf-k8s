"""Offline evaluator for invented disclosure policy and intake records."""
from datetime import datetime, timezone
import json


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def missing_fields(policy):
    if not isinstance(policy, dict):
        return ["policy_missing"]
    missing = []
    publication = policy.get("publication", {})
    scope = policy.get("scope", {})
    authorization = policy.get("authorization", {})
    channels = policy.get("intake_channels", {})
    targets = policy.get("response_targets", {})
    if publication.get("status") != "published" or not publication.get("uri"):
        missing.append("published_policy_location")
    if not scope.get("in_scope_classes") or not scope.get("out_of_scope_classes"):
        missing.append("scope_boundaries")
    if not authorization.get("allowed_activity") or not authorization.get("prohibited_activity"):
        missing.append("authorized_activity_boundaries")
    if authorization.get("out_of_scope_handling") != "referral_only_no_testing_authorized":
        missing.append("out_of_scope_handling")
    for name in ("internal", "external"):
        channel = channels.get(name, {})
        if not channel.get("channel_id") or not channel.get("contact"):
            missing.append(name + "_intake_channel")
    if channels.get("external", {}).get("anonymous_allowed") is not True:
        missing.append("anonymous_external_intake")
    if policy.get("reporter_contact") != "optional":
        missing.append("optional_reporter_contact")
    if not policy.get("report_fields_requested"):
        missing.append("report_information_request")
    for severity in ("critical", "high", "medium", "low"):
        target = targets.get(severity, {})
        if not isinstance(target.get("acknowledgment_minutes"), int) or not isinstance(target.get("triage_minutes"), int):
            missing.append("response_target_" + severity)
    return missing


def evaluate_report(record, policy, now):
    channels = policy["intake_channels"]
    channel_key = {"internal-employee": "internal", "external-researcher": "external"}.get(record["reporter_class"])
    channel = channels.get(channel_key) or {}
    channel_match = channel.get("channel_id") == record["channel_id"]
    external_anonymous = record["reporter_class"] == "external-researcher" and record["anonymous"]
    in_scope = record["component_class"] in policy["scope"]["in_scope_classes"]
    target = policy["response_targets"][record["severity"]]
    received = parse_time(record["received_at"])
    acknowledged = parse_time(record["acknowledged_at"])
    triaged = parse_time(record["triaged_at"])
    ack_minutes = (acknowledged - received).total_seconds() / 60
    triage_minutes = (triaged - received).total_seconds() / 60
    if not channel_match:
        status = "channel_mismatch"
    elif record["anonymous"] and channel.get("anonymous_allowed") is not True:
        status = "anonymous_channel_not_permitted"
    elif not in_scope:
        status = policy["authorization"]["out_of_scope_handling"]
    elif acknowledged > now or triaged > now:
        status = "future_event_rejected"
    elif ack_minutes < 0 or triage_minutes < 0:
        status = "negative_elapsed_time_rejected"
    elif ack_minutes > target["acknowledgment_minutes"]:
        status = "acknowledgment_sla_missed"
    elif triage_minutes > target["triage_minutes"]:
        status = "triage_sla_missed"
    else:
        status = "accepted_on_time"
    return {
        "synthetic_report_id": record["synthetic_report_id"],
        "channel_match": channel_match,
        "in_scope": in_scope,
        "anonymous_external_accepted": external_anonymous and status == "accepted_on_time",
        "acknowledgment_within_target": 0 <= ack_minutes <= target["acknowledgment_minutes"],
        "triage_within_target": 0 <= triage_minutes <= target["triage_minutes"],
        "status": status,
    }


def main():
    with open("/case/policy.json", encoding="utf-8") as stream:
        policy = json.load(stream)
    with open("/case/reports.json", encoding="utf-8") as stream:
        report_doc = json.load(stream)
    now = parse_time(report_doc["fake_clock_now"])
    outcomes = [evaluate_report(item, policy, now) for item in report_doc["records"]]
    by_id = {item["synthetic_report_id"]: item for item in outcomes}
    accepted = [item["synthetic_report_id"] for item in outcomes if item["status"] == "accepted_on_time"]
    late = [item["synthetic_report_id"] for item in outcomes
            if item["status"] in ("acknowledgment_sla_missed", "triage_sla_missed")]
    ready_missing = missing_fields(policy)
    absent = missing_fields(None)
    severity_sample_ids = {
        "SYN-REPORT-INTERNAL-001", "SYN-REPORT-EXTERNAL-ANON-001",
        "SYN-REPORT-MEDIUM-001", "SYN-REPORT-LOW-001",
    }
    on_time_samples = [item for item in accepted if item in severity_sample_ids]
    result = {
        "fixture_only": True,
        "fake_clock_now": report_doc["fake_clock_now"],
        "missing_policy": {"ready": not absent, "reasons": absent},
        "overdue": by_id["SYN-REPORT-HIGH-LATE-001"],
        "readiness": {
            "ready": not ready_missing and set(on_time_samples) == severity_sample_ids,
            "missing_fields": ready_missing,
            "on_time_report_ids": on_time_samples,
            "late_report_ids": late,
            "severity_tiers": sorted(policy["response_targets"]),
        },
        "routing": {
            "accepted_report_ids": [item for item in accepted if item != "SYN-REPORT-OUT-OF-SCOPE-001"],
            "anonymous_external_accepted": by_id["SYN-REPORT-EXTERNAL-ANON-001"]["anonymous_external_accepted"],
            "out_of_scope_handled": by_id["SYN-REPORT-OUT-OF-SCOPE-001"]["status"],
            "wrong_channel": by_id["SYN-REPORT-WRONG-CHANNEL-001"]["status"],
        },
        "records": outcomes,
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
