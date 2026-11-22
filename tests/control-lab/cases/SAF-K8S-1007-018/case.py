"""Check removed-API discovery, ownership tracking, and a safe migration gate."""
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CONTROL_ID = "SAF-K8S-1007-018"
NAMESPACE = "saf-test"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
OLD_API = "extensions/v1beta1"
NEW_API = "apps/v1"
DEPLOYMENT_NAME = "saf-1007-018-mock-inference"
NOTICE_NAME = "saf-1007-018-migration-notice"
OWNER = "urn:example:saf:role:platform-engineering"
MIGRATION_ID = "urn:example:saf:migration:1007-018:deployment-001"
CASE_LABEL = "saf-lab.example/control"
FIXTURE_LABEL = "saf-lab.example/fixture"
SCOPE = (
    "One disposable Kind v1.36.1 cluster and two case-owned synthetic Deployment manifests. "
    "The case discovers served APIs from the live target, detects the documented removed API, "
    "blocks an incomplete owner/migration record, persists a mock notification with a named "
    "synthetic owner and completion state, then server-side dry-runs only the mapped apps/v1 "
    "replacement. It does not scan real cluster workloads, operators, Helm sources, CRDs, "
    "generated charts or CI repositories; prove organization-wide ownership or notification "
    "delivery; or authorize a production upgrade."
)


def _load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _labels():
    return {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}


def _owned(obj):
    labels = obj.get("metadata", {}).get("labels", {})
    return labels.get(CASE_LABEL) == CONTROL_ID and labels.get(FIXTURE_LABEL) == "true"


def _migration_gate(record, discovered_apis):
    """Fail closed unless ownership, completed tracking and the exact API mapping agree."""
    mapping = record.get("mapping", {})
    return (
        record.get("migration_id") == MIGRATION_ID
        and record.get("owner") == OWNER
        and record.get("status") == "completed"
        and record.get("completion_ref") == "urn:example:saf:change:synthetic-001"
        and mapping.get("from") == OLD_API
        and mapping.get("kind") == "Deployment"
        and mapping.get("to") == NEW_API
        and f"{NEW_API}" in discovered_apis
    )


def _api_result(lab, manifest):
    return lab.kubectl(
        "apply", "--server-side", "--dry-run=server",
        "--field-manager=saf-1007-018-review", "-f", "-", "-o", "json",
        payload=json.dumps(manifest, sort_keys=True), allow_failure=True,
    )


def run(lab):
    removed = _load("removed-deployment.json")
    migrated = _load("migrated-deployment.json")
    if not (_owned(removed) and _owned(migrated)):
        lab.block("API fixtures are not both marked as case-owned synthetic manifests")
    if removed.get("apiVersion") != OLD_API or migrated.get("apiVersion") != NEW_API:
        lab.block("Fixture API versions do not match the documented migration pair")
    if (migrated.get("spec", {}).get("selector", {}).get("matchLabels")
            != migrated.get("spec", {}).get("template", {}).get("metadata", {}).get("labels")):
        lab.block("The modern Deployment selector does not match its pod-template labels")

    # This is server discovery from the disposable target, not a hard-coded version claim.
    versions_result = lab.kubectl("api-versions")
    discovered = {line.strip() for line in versions_result.stdout.splitlines() if line.strip()}
    resources_result = lab.kubectl("api-resources", "--api-group=apps", "-o", "wide")
    live_discovery = {
        "api_versions": sorted(discovered),
        "apps_api_resources": resources_result.stdout.splitlines(),
    }
    (lab.evidence / "api-versions.raw.txt").write_text(
        versions_result.stdout, encoding="utf-8"
    )
    (lab.evidence / "apps-api-resources.raw.txt").write_text(
        resources_result.stdout, encoding="utf-8"
    )
    (lab.evidence / "api-discovery.raw.json").write_text(
        json.dumps(live_discovery, indent=2) + "\n", encoding="utf-8"
    )
    if NEW_API not in discovered:
        lab.block("Live API discovery did not report the documented modern Deployment API")

    # Red observation: an ownerless, untracked finding cannot authorize upgrade, and the
    # kubectl rejects the removed kind using live API discovery.
    unresolved = {
        "migration_id": MIGRATION_ID,
        "source_manifest": "removed-deployment.json",
        "owner": None,
        "status": "unassigned",
        "mapping": {"from": OLD_API, "kind": "Deployment", "to": NEW_API},
    }
    legacy_result = _api_result(lab, removed)
    legacy_text = legacy_result.stdout + legacy_result.stderr
    legacy_rejected = (
        OLD_API not in discovered and legacy_result.returncode != 0
        and "no matches for kind" in legacy_text.lower()
        and OLD_API in legacy_text and "Deployment" in legacy_text
    )
    lab.check(
        "red",
        "An unresolved owner/migration blocks the gate and target discovery lacks the removed Deployment API",
        not _migration_gate(unresolved, discovered) and legacy_rejected,
        {"upgrade_gate": "blocked", "legacy_server_side_dry_run_exit": legacy_result.returncode,
         "legacy_api_absent_from_discovery": OLD_API not in discovered},
    )
    (lab.evidence / "removed-api-rejection.raw.txt").write_text(
        legacy_text, encoding="utf-8"
    )

    # A wrong replacement mapping is blocked even if it names an API group that exists.
    wrong_mapping = {
        **unresolved,
        "owner": OWNER,
        "status": "completed",
        "completion_ref": "urn:example:saf:change:synthetic-001",
        "mapping": {"from": OLD_API, "kind": "Deployment", "to": "apps/v1beta1"},
    }
    lab.check(
        "red", "A completed record with an unmapped replacement remains blocked",
        not _migration_gate(wrong_mapping, discovered),
        {"wrong_replacement": wrong_mapping["mapping"]["to"], "upgrade_gate": "blocked"},
    )

    notice = {
        "schema": "saf-lab.example/api-migration-notice/v1",
        "fixture_only": True,
        "migration_id": MIGRATION_ID,
        "control_id": CONTROL_ID,
        "source_manifest": "removed-deployment.json",
        "finding": {"kind": "Deployment", "api_version": OLD_API,
                    "removed_in": "1.16", "target_api_discovered": False},
        "owner": OWNER,
        "supporting_owner": "urn:example:saf:role:ai-ml-engineering",
        "status": "completed",
        "mapping": {"from": OLD_API, "kind": "Deployment", "to": NEW_API},
        "completion_ref": "urn:example:saf:change:synthetic-001",
        "completion_note": "Synthetic fixture changed apiVersion and added required apps/v1 selector.",
        "notification_destination": "urn:example:saf:inbox:fixture-only",
        "notification_delivery": "mock-persisted-in-cluster",
        "secrets_included": False,
    }
    if not _migration_gate(notice, discovered):
        lab.block("The completed synthetic migration notice does not satisfy the fail-closed gate")
    configmap = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": NOTICE_NAME, "namespace": NAMESPACE, "labels": _labels()},
        "immutable": True,
        "data": {"notice.json": json.dumps(notice, sort_keys=True)},
    }
    created_notice = lab.create(configmap)
    persisted = json.loads(lab.kubectl(
        "get", "configmap", NOTICE_NAME, "-o", "json"
    ).stdout)
    persisted_notice = json.loads(persisted.get("data", {}).get("notice.json", "{}"))
    notice_persisted = (
        _owned(persisted)
        and persisted.get("metadata", {}).get("uid") == created_notice.get("metadata", {}).get("uid")
        and persisted.get("immutable") is True
        and persisted_notice == notice
        and persisted_notice.get("owner") == OWNER
        and persisted_notice.get("status") == "completed"
    )
    (lab.evidence / "migration-notification.raw.json").write_text(
        json.dumps({"object": persisted, "notice": persisted_notice}, indent=2) + "\n",
        encoding="utf-8",
    )
    lab.check(
        "green", "A mock notification and completed migration persist with synthetic ownership",
        notice_persisted,
        {"configmap_uid_matches_create": persisted.get("metadata", {}).get("uid")
         == created_notice.get("metadata", {}).get("uid"),
         "owner": persisted_notice.get("owner"), "status": persisted_notice.get("status"),
         "mock_destination": persisted_notice.get("notification_destination")},
    )

    modern_result = _api_result(lab, migrated)
    modern_raw = modern_result.stdout + modern_result.stderr
    modern_ok = modern_result.returncode == 0
    if modern_ok:
        modern_response = json.loads(modern_result.stdout)
        modern_ok = (
            modern_response.get("apiVersion") == NEW_API
            and modern_response.get("kind") == "Deployment"
            and modern_response.get("metadata", {}).get("name") == DEPLOYMENT_NAME
        )
    (lab.evidence / "modern-server-dry-run.raw.txt").write_text(modern_raw, encoding="utf-8")
    absent = lab.kubectl(
        "get", "deployment", DEPLOYMENT_NAME, "--ignore-not-found", "-o", "name"
    )
    not_persisted = not absent.stdout.strip()
    lab.check(
        "positive", "Only the completed exact mapping passes server-side dry-run without persistence",
        _migration_gate(persisted_notice, discovered) and modern_ok and not_persisted,
        {"mapped_api": NEW_API, "server_side_dry_run_exit": modern_result.returncode,
         "dry_run_object_not_persisted": not_persisted,
         "old_api_absent_from_discovery": OLD_API not in discovered},
    )
