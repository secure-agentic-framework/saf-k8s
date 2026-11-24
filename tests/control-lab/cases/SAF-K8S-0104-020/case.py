"""Evaluate a pinned upstream support schedule and inventory the live lab."""
from datetime import date
import json
from pathlib import Path
import re


SCOPE = (
    "Kubernetes upstream patch-series support from the 2026-09-15 published snapshot. "
    "The case checks support boundaries and evaluates live server and kubelet versions. "
    "A synthetic provider schedule exercises separate API server and worker support windows, extended "
    "entitlement, stale data, and conservative handling of unlisted builds."
)
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
FIXTURE = json.loads(Path(__file__).with_name("fixtures.json").read_text())


def support_status(enabled, version, at_date):
    if not enabled:
        return "disabled"
    normalized = version.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", normalized):
        return "unverified"
    major, minor, patch = normalized.split(".")
    release = FIXTURE["releases"].get(f"{major}.{minor}")
    if not release or int(patch) > int(release["latest_patch_at_snapshot"].split(".")[-1]):
        return "unverified"

    day = date.fromisoformat(at_date)
    if not date.fromisoformat(release["minor_ga"]) <= day < date.fromisoformat(release["end_of_life"]):
        return "outside_window"
    maintenance = release["maintenance_start"]
    return "limited_maintenance" if maintenance and day >= date.fromisoformat(maintenance) else "supported"


def prepare_kind(lab, temporary):
    profile = temporary / "kind.yaml"
    profile.write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n- role: worker\n")
    return profile


def provider_status(schedule, role, build, evaluate_on, entitlements):
    try:
        age_days = (evaluate_on - date.fromisoformat(schedule["verified_on"])).days
        if not schedule["source_id"] or not 0 <= age_days <= schedule["freshness_days"]:
            return "unverified"
        release = schedule["roles"].get(role, {}).get(build)
        if not release:
            return "unverified"
        start, standard_end, final_end = (
            date.fromisoformat(release[field]) for field in ("start", "standard_end", "final_end")
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return "unverified"
    if not start < standard_end <= final_end:
        return "unverified"
    if start <= evaluate_on < standard_end:
        return "standard"
    if standard_end <= evaluate_on < final_end and role in entitlements:
        return "extended"
    return "outside_window"


def provider_examples(lab):
    managed = FIXTURE["synthetic_provider"]
    server = "v1.35.8-fixture.2"
    worker = "v1.35.8-fixture.6"
    assessment_day = date(2026, 11, 15)
    control = provider_status(managed, "control_plane", server, assessment_day, {"control_plane"})
    worker_ended = provider_status(managed, "worker", worker, assessment_day, {"control_plane"})
    lab.check("red", "A still-supported control plane cannot mask an out-of-window managed worker",
              control == "extended" and worker_ended == "outside_window",
              {"control_plane": control, "worker": worker_ended})

    worker_available = provider_status(managed, "worker", worker, assessment_day, {"control_plane", "worker"})
    worker_entitlement_expired = provider_status(managed, "worker", worker, date(2026, 11, 17), {"worker"})
    lab.check("green", "Extended support is separate by component and its end date is exclusive",
              worker_available == "extended" and worker_entitlement_expired == "outside_window",
              {"entitled_worker": worker_available, "worker_on_end_date": worker_entitlement_expired})
    unknown = provider_status(managed, "worker", "v1.36.1", assessment_day, {"worker"})
    naive = support_status(True, "v1.36.1", assessment_day.isoformat())
    stale = provider_status(managed, "control_plane", server, date(2026, 11, 30), {"control_plane"})
    lab.check("positive", "Unknown provider builds and stale schedules cannot fall back to upstream support",
              unknown == stale == "unverified" and naive == "supported",
              {"unknown_provider_build": unknown, "stale_provider_schedule": stale,
               "hypothetical_unqualified_upstream_lookup": naive})

    incomplete = {key: val for key, val in managed.items() if key != "verified_on"}
    malformed = {**managed, "roles": {"worker": {worker: {
        "start": "2026-11-16", "standard_end": "2026-11-14", "final_end": "2026-11-17",
    }}}}
    rejected = {
        "missing_verified_at": provider_status(incomplete, "worker", worker, assessment_day, {"worker"}),
        "inverted_dates": provider_status(malformed, "worker", worker, assessment_day, {"worker"}),
    }
    lab.check("green", "Incomplete schedules and invalid lifecycle dates remain unverified",
              set(rejected.values()) == {"unverified"}, rejected)



def run(lab):
    sample = (
        ("red", False, "1.34.12", "2026-10-27", "disabled"),
        ("green", True, "1.34.0", "2025-08-26", "outside_window"),
        ("green", True, "1.34.0", "2025-08-27", "supported"),
        ("green", True, "1.34.11", "2026-08-27", "limited_maintenance"),
        ("green", True, "1.34.12", "2026-10-26", "limited_maintenance"),
        ("green", True, "1.34.12", "2026-10-27", "outside_window"),
        ("green", True, "1.35.1", "2026-09-15", "supported"),
        ("green", True, "1.33.13", "2026-09-15", "outside_window"),
        ("green", True, "1.36.99", "2026-09-15", "unverified"),
    )
    for phase, enabled, version, evaluation_date, expected in sample:
        observed = support_status(enabled, version, evaluation_date)
        lab.check(phase, f"Upstream support decision for {version} on {evaluation_date}",
                  expected == observed, {"policy_enabled": enabled, "status": observed})

    as_of = FIXTURE["snapshot_date"]
    server = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    roles = {"control_plane" if "node-role.kubernetes.io/control-plane" in node["metadata"]["labels"]
             else "worker": node["status"]["nodeInfo"]["kubeletVersion"] for node in nodes}
    kubelets = sorted(roles.values())
    statuses = [support_status(True, version, as_of) for version in [server, *kubelets]]
    active = {"supported", "limited_maintenance"}
    lab.check("positive", "Live API server and kubelets fall in the snapshot's active support window",
              len(nodes) == 2 and set(roles) == {"control_plane", "worker"}
              and all(status in active for status in statuses),
              {"reference_date": as_of, "api_server": server, "kubelets_by_role": roles, "statuses": statuses})
    provider_examples(lab)
