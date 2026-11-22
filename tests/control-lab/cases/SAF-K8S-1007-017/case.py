"""Demonstrate a local API-deprecation impact gate with read-only discovery."""
import json
from pathlib import Path
import re


ROOT = Path(__file__).parent
LIFECYCLE = json.loads((ROOT / "release-lifecycle.json").read_text())
INVENTORY = json.loads((ROOT / "impact-inventory.json").read_text())
MIGRATION = json.loads((ROOT / "migration-evidence.json").read_text())
LEGACY = json.loads((ROOT / "legacy-ingress.json").read_text())
MIGRATED = json.loads((ROOT / "migrated-ingress.json").read_text())
EXPECTED_SERVER = "v1.36.1"
SCOPE = (
    "Read-only Kubernetes v1.36.1 API version/discovery inspection plus offline, "
    "version-pinned Kubernetes Ingress v1.22 deprecation fixtures. Computes an "
    "impact alert for one synthetic legacy manifest and evaluates the corresponding "
    "synthetic migration record. It creates no Kubernetes objects and makes no "
    "external requests. It does not establish release-feed polling, real cluster "
    "inventory completeness, production migration validation, or organization alert "
    "triage and distribution."
)


def version_tuple(value):
    match = re.fullmatch(r"v(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


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


def live_discovery(lab):
    version = json.loads(lab.kubectl("get", "--raw=/version").stdout)
    apis = json.loads(lab.kubectl("get", "--raw=/apis").stdout)
    groups = {}
    group_versions = set()
    for group in apis.get("groups", []):
        name = group.get("name")
        versions = {
            row.get("version") for row in group.get("versions", [])
            if row.get("version")
        }
        if name and versions:
            groups[name] = versions
        group_versions.update(
            row.get("groupVersion") for row in group.get("versions", [])
            if row.get("groupVersion")
        )
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
    # This synthetic before-upgrade assessment is pinned to v1.21.0, the final
    # minor before removal, so the alert is still actionable before upgrade.
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
