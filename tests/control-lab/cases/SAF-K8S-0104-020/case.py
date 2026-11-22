"""Evaluate a pinned upstream support schedule and inventory the live lab."""
from datetime import date
import json
from pathlib import Path
import re


SCOPE = (
    "Kubernetes upstream patch-series support from the 2026-09-15 published snapshot. "
    "The case checks support boundaries and evaluates live server and kubelet versions. "
    "Provider schedules, present-day patch posture and completed upgrades require separate evidence."
)
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
    kubelets = sorted(node["status"]["nodeInfo"]["kubeletVersion"] for node in nodes)
    statuses = [support_status(True, version, as_of) for version in [server, *kubelets]]
    active = {"supported", "limited_maintenance"}
    lab.check("positive", "Live API server and kubelets fall in the snapshot's active support window",
              bool(kubelets) and all(status in active for status in statuses),
              {"reference_date": as_of, "api_server": server, "kubelets": kubelets, "statuses": statuses})
