"""Read-only API deprecation example plus offline release corroboration."""
import copy
import json
from pathlib import Path
import re


ROOT = Path(__file__).parent
LIFECYCLE = json.loads((ROOT / "release-lifecycle.json").read_text())
INVENTORY = json.loads((ROOT / "impact-inventory.json").read_text())
MIGRATION = json.loads((ROOT / "migration-evidence.json").read_text())
LEGACY = json.loads((ROOT / "legacy-ingress.json").read_text())
MIGRATED = json.loads((ROOT / "migrated-ingress.json").read_text())
RELEASES = json.loads((ROOT / "release-evidence.json").read_text())
EXPECTED_SERVER = "v1.36.1"
SCOPE = (
    "Read-only Kubernetes v1.36.1 API version/discovery inspection plus offline, "
    "version-pinned Kubernetes Ingress v1.22 deprecation and release-corroboration "
    "fixtures. Release evaluation reads only checked-in normalized upstream "
    "observations and synthetic counterfactuals. It makes no external requests. "
    "It does not establish recurring feed polling, inventory completeness, "
    "production migration validation, or organizational alert triage."
)


def version_tuple(value):
    """Return numeric major/minor/patch; prerelease and malformed versions fail closed."""
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def same_minor(left, right):
    a, b = version_tuple(left), version_tuple(right)
    return bool(a and b and a[:2] == b[:2])


def channel_for_minor(minor, markers):
    """Prefer the per-minor stable marker; never substitute global stable."""
    if not isinstance(minor, int):
        return None
    row = markers.get(f"stable-1.{minor}")
    return row.get("text") if isinstance(row, dict) else None


def evaluate_release(target_minor, evidence):
    """Require matching per-minor marker, published stable record, and same-minor compare."""
    markers = evidence.get("channel_markers", {})
    candidate = channel_for_minor(target_minor, markers)
    parsed = version_tuple(candidate)
    if not parsed:
        return {"closed": False, "reason": "missing-or-invalid-minor-channel-marker", "candidate": candidate}
    if parsed[1] != target_minor:
        return {"closed": False, "reason": "channel-minor-mismatch", "candidate": candidate}

    release = evidence.get("project_releases", {}).get(candidate)
    if not isinstance(release, dict):
        return {"closed": False, "reason": "missing-project-release-record", "candidate": candidate}
    if release.get("tag") != candidate:
        return {"closed": False, "reason": "channel-release-tag-conflict", "candidate": candidate}
    if release.get("draft") is not False or release.get("prerelease") is not False:
        return {"closed": False, "reason": "release-not-published-stable", "candidate": candidate}
    if not release.get("published_at"):
        return {"closed": False, "reason": "missing-published-timestamp", "candidate": candidate}

    comparison = release.get("comparison")
    previous = version_tuple(release.get("previous_tag"))
    if not isinstance(comparison, dict) or not previous:
        return {"closed": False, "reason": "missing-authoritative-tag-comparison", "candidate": candidate}
    if previous[1] != target_minor or not same_minor(candidate, release.get("previous_tag")):
        return {"closed": False, "reason": "crossed-minor-baseline", "candidate": candidate}
    if (not all(re.fullmatch(r"[0-9a-f]{40}", release.get(key) or "")
                for key in ("previous_commit", "tag_commit"))
            or parsed <= previous
            or comparison.get("status") != "ahead"
            or comparison.get("base_tag") != release.get("previous_tag")
            or comparison.get("head_tag") != candidate
            or comparison.get("base_commit") != release.get("previous_commit")
            or comparison.get("head_commit") != release.get("tag_commit")
            or not release.get("comparison_url")):
        return {"closed": False, "reason": "tag-comparison-conflict", "candidate": candidate}
    return {
        "closed": True,
        "reason": "channel-project-release-and-tag-comparison-agree",
        "candidate": candidate,
        "channel": f"stable-1.{target_minor}",
        "tag": release["tag"],
        "tag_commit": release["tag_commit"],
        "comparison_url": release["comparison_url"],
    }


def release_counterfactuals(actual):
    """Create labeled, in-memory bad evidence; none of these are upstream claims."""
    conflict = copy.deepcopy(actual)
    conflict["project_releases"]["v1.37.2"]["tag"] = "v1.37.1"

    missing = copy.deepcopy(actual)
    del missing["project_releases"]["v1.37.2"]["comparison"]

    prerelease = copy.deepcopy(actual)
    prerelease["project_releases"]["v1.37.2"]["prerelease"] = True

    draft = copy.deepcopy(actual)
    draft["project_releases"]["v1.37.2"]["draft"] = True

    crossed = copy.deepcopy(actual)
    row = crossed["project_releases"]["v1.37.2"]
    row["previous_tag"] = "v1.36.6"
    row["previous_commit"] = crossed["project_releases"]["v1.36.6"]["tag_commit"]
    row["comparison"] = {
        "status": "ahead", "base_tag": "v1.36.6",
        "base_commit": row["previous_commit"], "head_tag": "v1.37.2",
        "head_commit": row["tag_commit"],
    }
    return {
        "channel-conflict": conflict,
        "missing-comparison": missing,
        "prerelease": prerelease,
        "draft": draft,
        "crossed-minor-baseline": crossed,
    }


def has_migration_evidence(item):
    service = MIGRATED.get("spec", {}).get("defaultBackend", {}).get("service", {})
    legacy_service = LEGACY.get("spec", {}).get("backend", {})
    return (
        MIGRATION.get("inventory_id") == item.get("inventory_id")
        and MIGRATION.get("review_status") == "validated-fixture"
        and MIGRATION.get("replacement_api_version") == LIFECYCLE["replacement_api_version"]
        and MIGRATION.get("source_manifest") == item.get("manifest_fixture")
        and MIGRATION.get("replacement_manifest") == "migrated-ingress.json"
        and MIGRATION.get("tested_against_release") == LIFECYCLE["removed_in_release"]
        and MIGRATION.get("runtime_behavior_validated") is False
        and MIGRATION.get("production_approval") is False
        and MIGRATED.get("apiVersion") == LIFECYCLE["replacement_api_version"]
        and MIGRATED.get("kind") == item.get("kind")
        and service.get("name") == "synthetic-inference"
        and service.get("port", {}).get("number") == 8080
        and "backend" not in MIGRATED.get("spec", {})
        and legacy_service.get("serviceName") == service.get("name")
        and legacy_service.get("servicePort") == service.get("port", {}).get("number")
    )


def upgrade_gate_clear(alert, migration_valid):
    return bool(alert and migration_valid)


def version_specific_impact(api_version, affected_api_versions, candidate_release, removal_release):
    candidate, removal = version_tuple(candidate_release), version_tuple(removal_release)
    return bool(api_version in affected_api_versions and candidate and removal and candidate >= removal)


def live_discovery(lab):
    version = json.loads(lab.kubectl("get", "--raw=/version").stdout)
    apis = json.loads(lab.kubectl("get", "--raw=/apis").stdout)
    groups = {}
    group_versions = set()
    for group in apis.get("groups", []):
        name = group.get("name")
        versions = {row.get("version") for row in group.get("versions", []) if row.get("version")}
        if name and versions:
            groups[name] = versions
        group_versions.update(row.get("groupVersion") for row in group.get("versions", []) if row.get("groupVersion"))
    return version, groups, group_versions


def run(lab):
    if (LIFECYCLE.get("fixture_id") != "kubernetes-ingress-api-lifecycle-v1"
            or LIFECYCLE.get("deprecated_by_release") != "v1.19.0"
            or LIFECYCLE.get("replacement_available_since") != "v1.19.0"
            or LIFECYCLE.get("removed_in_release") != "v1.22.0"
            or LIFECYCLE.get("release_channel_evidence", {}).get("source_release") != "v1.19.0"
            or LIFECYCLE.get("removal_evidence", {}).get("source_release") != "v1.22.0"
            or LIFECYCLE.get("replacement_api_version") != "networking.k8s.io/v1"):
        lab.block("The version-pinned upstream API lifecycle fixture is inconsistent")
    if (LEGACY.get("apiVersion") not in LIFECYCLE.get("deprecated_api_versions", [])
            or LEGACY.get("kind") != "Ingress"):
        lab.block("The legacy manifest fixture does not match the lifecycle record")
    item = next((row for row in INVENTORY.get("items", [])
                 if row.get("manifest_fixture") == "legacy-ingress.json"), None)
    if not item or item.get("api_version") != LEGACY.get("apiVersion"):
        lab.block("The synthetic inventory does not identify its legacy manifest")

    # Deterministic release-corroboration tests use only the pinned local snapshot.
    actual = evaluate_release(37, RELEASES)
    landing = RELEASES.get("changelog_observations", {}).get("v1.37.2", {})
    landing_stale = landing.get("release_landing", {}).get("latest_heading") == "v1.37.1"
    tagged_stale = landing.get("tagged", {}).get("latest_heading") == "v1.37.1"
    lab.check(
        "positive",
        "Pinned stable-1.37 marker, published project release and authoritative same-minor tag comparison agree despite lagging release listing and tagged changelog",
        bool(actual.get("closed") and landing_stale and tagged_stale),
        {"target_minor": 37, "candidate": actual.get("candidate"),
         "channel": actual.get("channel"), "tag_commit": actual.get("tag_commit"),
         "tagged_changelog_latest": landing.get("tagged", {}).get("latest_heading"),
         "landing_latest": landing.get("release_landing", {}).get("latest_heading"),
          "linked_changelog_latest": landing.get("linked_changelog", {}).get("latest_heading"),
         "reason": actual.get("reason")},
    )

    # A supported 1.36 target follows stable-1.36 even while global stable is 1.37.
    minor_36 = evaluate_release(36, RELEASES)
    lab.check(
        "positive",
        "Per-minor stable channel takes precedence over the newer global stable marker for a v1.36 target",
        bool(minor_36.get("closed") and minor_36.get("candidate") == "v1.36.6"
             and RELEASES["channel_markers"]["stable"]["text"] == "v1.37.2"),
        {"target_minor": 36, "selected_candidate": minor_36.get("candidate"),
         "global_stable": RELEASES["channel_markers"]["stable"]["text"],
         "channel": minor_36.get("channel"), "reason": minor_36.get("reason")},
    )

    removal = RELEASES["impact_fixture"]["removed_in"]
    impact_before = version_specific_impact(
        RELEASES["impact_fixture"]["api_version"],
        [RELEASES["impact_fixture"]["api_version"]], "v1.21.0", removal)
    impact_at = version_specific_impact(
        RELEASES["impact_fixture"]["api_version"],
        [RELEASES["impact_fixture"]["api_version"]], "v1.22.0", removal)
    lab.check(
        "positive",
        "The Ingress impact is version-specific: target v1.21 is before removal and v1.22 crosses the removal boundary",
        not impact_before and impact_at,
        {"api_version": RELEASES["impact_fixture"]["api_version"],
         "before_target": "v1.21.0", "before_target_impacted": impact_before,
         "removal_release": removal, "at_target": "v1.22.0",
         "at_target_impacted": impact_at,
         "provenance": RELEASES["impact_fixture"]["provenance"]},
    )

    expected_reasons = {
        "channel-conflict": "channel-release-tag-conflict",
        "missing-comparison": "missing-authoritative-tag-comparison",
        "prerelease": "release-not-published-stable",
        "draft": "release-not-published-stable",
        "crossed-minor-baseline": "crossed-minor-baseline",
    }
    counterfactual_results = {
        name: evaluate_release(37, evidence)
        for name, evidence in release_counterfactuals(RELEASES).items()
    }
    all_counterfactuals_rejected = all(
        not counterfactual_results[name].get("closed")
        and counterfactual_results[name].get("reason") == reason
        for name, reason in expected_reasons.items()
    )
    lab.check(
        "negative",
        "Synthetic channel conflict, missing comparison, prerelease, draft and crossed-minor counterfactuals fail closed",
        all_counterfactuals_rejected,
        {"cases": {name: {"closed": result.get("closed"), "reason": result.get("reason"),
                           "provenance": "synthetic in-memory counterfactual, not published metadata"}
                    for name, result in counterfactual_results.items()}},
    )

    version, groups, group_versions = live_discovery(lab)
    git_version = version.get("gitVersion")
    if git_version != EXPECTED_SERVER:
        lab.block(f"Expected read-only discovery against Kubernetes {EXPECTED_SERVER}, got {git_version!r}")
    networking_versions = groups.get("networking.k8s.io", set())
    legacy_group_served = "networking.k8s.io/v1beta1" in group_versions
    resource_list = json.loads(lab.kubectl("get", "--raw=/apis/networking.k8s.io/v1").stdout)
    stable_served = ("v1" in networking_versions
                     and resource_list.get("groupVersion") == "networking.k8s.io/v1"
                     and any(row.get("name") == "ingresses" and row.get("kind") == "Ingress"
                             and row.get("namespaced") is True for row in resource_list["resources"]))
    lab.check(
        "positive",
        "Live API discovery reports networking.k8s.io/v1 and does not report the removed networking.k8s.io/v1beta1 group version",
        stable_served and not legacy_group_served,
        {"server_version": git_version,
         "networking_k8s_io_versions": sorted(networking_versions),
         "stable_namespaced_ingress_served": stable_served,
         "networking_k8s_io_v1beta1_served": legacy_group_served},
    )

    target = version_tuple(LIFECYCLE["removed_in_release"])
    impacted = item.get("api_version") in LIFECYCLE["deprecated_api_versions"]
    assessment_version = "v1.21.0"
    assessment = version_tuple(assessment_version)
    alert = impacted and assessment and target and assessment < target
    lab.check(
        "red",
        "The synthetic pre-upgrade inventory raises an impact alert for the deprecated API",
        bool(alert),
        {"inventory_id": item["inventory_id"], "component": item["component"],
         "api_version": item["api_version"], "upgrade_assessment_version": assessment_version,
         "removed_in_release": LIFECYCLE["removed_in_release"],
         "alert": bool(alert), "live_cluster_version_used_for_alert": False},
    )
    migration_valid = has_migration_evidence(item)
    blocked_without_migration = not upgrade_gate_clear(bool(alert), False)
    lab.check(
        "red",
        "An affected pre-upgrade inventory remains blocked when migration evidence is absent",
        blocked_without_migration,
        {"inventory_id": item["inventory_id"], "impact_alert": bool(alert),
         "migration_evidence_present": False,
         "upgrade_gate_clear": not blocked_without_migration},
    )
    gate_clear = upgrade_gate_clear(bool(alert), bool(migration_valid))
    lab.check(
        "green",
        "The documented stable replacement and scoped migration record clear this synthetic impact-gate example",
        gate_clear,
        {"inventory_id": item["inventory_id"],
         "replacement_api_version": MIGRATED.get("apiVersion"),
         "migration_record": MIGRATION.get("review_record"),
         "migration_fixture_valid": bool(migration_valid),
         "runtime_behavior_validated": MIGRATION.get("runtime_behavior_validated"),
         "production_approval": MIGRATION.get("production_approval"),
         "gate_clear_for_fixture": bool(gate_clear)},
    )
