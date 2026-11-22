"""Exercise synthetic recovery priorities and a closed-loop plan improvement."""
import copy
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
FIXTURE_PATH = HERE / "fixtures" / "recovery-exercise.json"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
NAMESPACE = "saf-test"
CONTROL_ID = "SAF-K8S-1005-014"
CASE_LABEL = "saf-k8s-control"
FIXTURE_LABEL = "fixture-only"
RECORD_NAME = "saf1005014-exercise-record"
PLAYBOOK_NAME = "saf1005014-recovery-playbook"
RESOURCE_NAMES = {
    "runtime-config": "saf1005014-runtime-config",
    "inference-state": "saf1005014-inference-state",
    "training-cache": "saf1005014-training-cache",
}
EXPECTED_PRIORITIES = {"runtime-config": 0, "inference-state": 1, "training-cache": 3}
EXPECTED_DEPENDENCIES = {
    "runtime-config": [],
    "inference-state": ["runtime-config"],
    "training-cache": ["runtime-config"],
}
EXPECTED_ORDER = ["runtime-config", "inference-state", "training-cache"]
MUTABLE_NAMES = set(RESOURCE_NAMES.values())
SCOPE = (
    "One disposable Kind v1.36.1 cluster, one inert synthetic exercise record, one mock recovery "
    "playbook, and three case-owned ConfigMaps. Checks a reviewed dependency-aware restoration "
    "order and a tracked lesson linked to a revised playbook, then restores only exact fixture "
    "ConfigMap payloads in saf-test. No production workload, external target, feed, or incident "
    "data is used. This does not establish an organization's business-impact criteria, complete "
    "recovery readiness, production recovery outcomes, or sustained improvement governance."
)


def load_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _labels():
    return {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}


def _resource(name, data):
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
        "data": data,
    }


def _record_resource(record):
    return _resource(RECORD_NAME, {"record.json": json.dumps(record, sort_keys=True)})


def _playbook_resource(playbook):
    return _resource(PLAYBOOK_NAME, {"playbook.json": json.dumps(playbook, sort_keys=True)})


def _record(value):
    return value.get("exercise_record", value)


def _assets(fixture):
    return _record(fixture)["recovery_plan"]["assets"]


def _recovery_order(assets):
    """Return dependency-first order, using business priority among ready assets."""
    by_id = {asset["id"]: asset for asset in assets}
    if len(by_id) != len(assets):
        raise ValueError("duplicate recovery asset id")
    if any(set(asset["depends_on"]) - set(by_id) for asset in assets):
        raise ValueError("recovery plan contains an unlisted dependency")
    remaining = set(by_id)
    restored = set()
    order = []
    while remaining:
        ready = [asset for asset in assets
                 if asset["id"] in remaining and set(asset["depends_on"]).issubset(restored)]
        if not ready:
            raise ValueError("recovery plan contains a dependency cycle")
        ready.sort(key=lambda asset: (asset["business_priority"], asset["id"]))
        selected = ready[0]
        order.append(selected["id"])
        remaining.remove(selected["id"])
        restored.add(selected["id"])
    return order


def _validate_plan(fixture):
    fixture = _record(fixture)
    plan = fixture["recovery_plan"]
    assets = _assets(fixture)
    expected_names = set(RESOURCE_NAMES)
    ids_match = {asset["id"] for asset in assets} == expected_names
    names_match = all(asset.get("configmap") == RESOURCE_NAMES.get(asset.get("id"))
                      for asset in assets)
    priorities_valid = all(
        asset.get("business_priority") == EXPECTED_PRIORITIES.get(asset.get("id"))
        and bool(asset.get("criticality_basis")) for asset in assets
    )
    dependencies_valid = {
        asset["id"]: asset.get("depends_on") for asset in assets
    } == EXPECTED_DEPENDENCIES if ids_match else False
    declared = plan.get("reviewed_order", [])
    computed = _recovery_order(assets) if ids_match else []
    return {
        "valid": (fixture.get("fixture_only") is True and ids_match and names_match
                  and priorities_valid and dependencies_valid and declared == computed == EXPECTED_ORDER
                  and bool(plan.get("review", {}).get("status") == "approved")
                  and bool(plan.get("review", {}).get("reviewer"))),
        "declared_order": declared,
        "computed_order": computed,
        "asset_ids_match_allowlist": ids_match,
        "configmap_names_match_allowlist": names_match,
        "priorities_have_basis": priorities_valid,
        "dependencies_match_exact_fixture_graph": dependencies_valid,
    }


def _validate_improvement(record, playbook):
    lesson = record.get("lessons_learned", {})
    action = lesson.get("improvement_action", {})
    ref = lesson.get("playbook_revision", {})
    return {
        "valid": (
            record.get("fixture_only") is True
            and lesson.get("finding_id") == "SYNTH-FINDING-1005-014-01"
            and bool(lesson.get("finding"))
            and action.get("status") == "implemented"
            and action.get("owner") == "urn:example:saf:role:platform-engineering"
            and bool(action.get("due")) and bool(action.get("verification_ref"))
            and bool(action.get("action_id"))
            and ref.get("version") == playbook.get("version") == "mock-recovery-v2"
            and ref.get("improvement_id") == action.get("action_id") == playbook.get("source_improvement")
            and playbook.get("source_finding") == lesson.get("finding_id")
            and playbook.get("source_improvement") == action.get("action_id")
            and playbook.get("review_status") == "approved"
            and playbook.get("reviewer") == "urn:example:saf:role:independent-reviewer"
            and playbook.get("recovery_order") == record.get("recovery_plan", {}).get("reviewed_order")
        ),
        "finding_id": lesson.get("finding_id"),
        "action_id": action.get("action_id"),
        "action_status": action.get("status"),
        "playbook_version": ref.get("version"),
        "playbook_improvement_id": playbook.get("source_improvement"),
        "playbook_finding_id": playbook.get("source_finding"),
    }


def _get(lab, name):
    result = lab.kubectl("get", "configmap", name, "-o", "json", "--ignore-not-found")
    return json.loads(result.stdout) if result.stdout.strip() else None


def _create_exact(lab, resource):
    name = resource["metadata"]["name"]
    if name not in MUTABLE_NAMES | {RECORD_NAME, PLAYBOOK_NAME}:
        lab.block("Refusing to create a ConfigMap outside this case's exact name allowlist")
    if _get(lab, name) is not None:
        lab.block("Refusing to overwrite a pre-existing ConfigMap in the case namespace")
    lab.create(resource)


def _delete_fixture(lab, name):
    if name not in MUTABLE_NAMES:
        lab.block("Refusing to delete a ConfigMap outside this case's restoration allowlist")
    current = _get(lab, name)
    metadata = (current or {}).get("metadata", {})
    if (current is None or metadata.get("namespace") != NAMESPACE
            or metadata.get("labels", {}).get(CASE_LABEL) != CONTROL_ID
            or metadata.get("labels", {}).get(FIXTURE_LABEL) != "true"):
        lab.block("Refusing to delete a ConfigMap without exact case ownership metadata")
    lab.kubectl("delete", "configmap", name, "--wait=true")


def _write_evidence(lab, evidence):
    (lab.evidence / "recovery-review.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(lab):
    fixture = load_fixture()
    record = fixture["exercise_record"]
    playbook = fixture["preparedness_playbook"]

    red_record = copy.deepcopy(record)
    red_record["recovery_plan"]["reviewed_order"] = [
        "training-cache", "runtime-config", "inference-state"
    ]
    red_record["lessons_learned"]["improvement_action"]["status"] = "open"
    red_playbook = copy.deepcopy(playbook)
    red_playbook["version"] = "mock-recovery-v1"
    red_playbook["source_improvement"] = ""
    red_review = _validate_plan(red_record)
    red_improvement = _validate_improvement(red_record, red_playbook)
    lab.check(
        "red",
        "Unreviewed restoration order and an unclosed improvement link fail review",
        not red_review["valid"] and not red_improvement["valid"],
        {"plan_review": red_review, "improvement_review": red_improvement},
    )

    plan_review = _validate_plan(record)
    improvement_review = _validate_improvement(record, playbook)
    lab.check(
        "green",
        "Reviewed order respects exact dependencies and business priority, and the tracked action updates its playbook",
        plan_review["valid"] and improvement_review["valid"],
        {"plan_review": plan_review, "improvement_review": improvement_review},
    )

    record_resource = _record_resource(record)
    playbook_resource = _playbook_resource(playbook)
    _create_exact(lab, record_resource)
    _create_exact(lab, _playbook_resource(red_playbook))
    prior_playbook_object = _get(lab, PLAYBOOK_NAME)
    prior = json.loads(prior_playbook_object["data"]["playbook.json"])
    misplaced = copy.deepcopy(playbook)
    misplaced["source_improvement"] = "unrelated-fixture-improvement"
    lab.check("red", "The earlier playbook and an unrelated improvement reference leave the finding open",
              not _validate_improvement(record, prior)["valid"]
              and not _validate_improvement(record, misplaced)["valid"],
              {"old_version": prior["version"], "wrong_improvement_link_rejected": True})
    lab.kubectl("patch", "configmap", PLAYBOOK_NAME, "--type=merge",
                "-p", json.dumps({"data": playbook_resource["data"]}))

    asset_by_id = {asset["id"]: asset for asset in _assets(fixture)}
    expected_resources = {}
    initial_objects = {}
    for asset_id, name in RESOURCE_NAMES.items():
        payload = fixture["configmaps"][asset_id]
        expected = _resource(name, payload)
        expected_resources[asset_id] = expected
        _create_exact(lab, expected)
        observed = _get(lab, name)
        initial_objects[asset_id] = {
            "name": name,
            "uid": observed["metadata"]["uid"],
            "data": observed.get("data", {}),
            "labels": observed.get("metadata", {}).get("labels", {}),
        }

    # Read the inert records back through the Kubernetes API before acting on them.
    observed_record_object = _get(lab, RECORD_NAME)
    observed_playbook_object = _get(lab, PLAYBOOK_NAME)
    observed_record = json.loads(observed_record_object["data"]["record.json"])
    observed_playbook = json.loads(observed_playbook_object["data"]["playbook.json"])
    api_plan_review = _validate_plan(observed_record)
    api_improvement_review = _validate_improvement(observed_record, observed_playbook)
    playbook_updated = (observed_playbook_object["metadata"]["uid"] == prior_playbook_object["metadata"]["uid"]
                        and observed_playbook_object["metadata"]["resourceVersion"]
                        != prior_playbook_object["metadata"]["resourceVersion"])
    api_owned = all(
        obj is not None
        and obj.get("metadata", {}).get("namespace") == NAMESPACE
        and obj.get("metadata", {}).get("labels") == _labels()
        for obj in (observed_record_object, observed_playbook_object)
    )
    if not (api_owned and playbook_updated and api_plan_review["valid"] and api_improvement_review["valid"]):
        lab.block("The API-read exercise record or improved playbook failed ownership or content review")

    expected_order = api_plan_review["computed_order"]
    for asset_id in expected_order:
        _delete_fixture(lab, RESOURCE_NAMES[asset_id])

    restored = []
    for asset_id in expected_order:
        asset = asset_by_id[asset_id]
        dependencies = list(asset["depends_on"])
        dependencies_present = all(
            _get(lab, RESOURCE_NAMES[dependency]) is not None for dependency in dependencies
        )
        if not dependencies_present:
            lab.block(f"A required fixture-owned dependency is absent before restoring {asset_id}")
        _create_exact(lab, expected_resources[asset_id])
        observed = _get(lab, RESOURCE_NAMES[asset_id])
        matches = (
            observed is not None
            and observed.get("data") == expected_resources[asset_id]["data"]
            and observed.get("metadata", {}).get("labels") == _labels()
            and observed.get("metadata", {}).get("namespace") == NAMESPACE
            and observed["metadata"]["uid"] != initial_objects[asset_id]["uid"]
        )
        restored.append({
            "asset_id": asset_id,
            "configmap": RESOURCE_NAMES[asset_id],
            "business_priority": asset["business_priority"],
            "depends_on": dependencies,
            "dependencies_present_before_restore": dependencies_present,
            "restored_payload_matches_fixture": matches,
            "restored_uid": observed.get("metadata", {}).get("uid") if observed else None,
            "data": observed.get("data", {}) if observed else {},
            "labels": observed.get("metadata", {}).get("labels", {}) if observed else {},
        })

    actual_order = [row["asset_id"] for row in restored]
    order_valid = actual_order == expected_order == record["recovery_plan"]["reviewed_order"]
    all_exact = len(restored) == len(RESOURCE_NAMES) and all(
        row["restored_payload_matches_fixture"] and row["dependencies_present_before_restore"]
        for row in restored
    )
    evidence = {
        "fixture_only": True,
        "fixture": fixture,
        "red_review": {"plan": red_review, "improvement": red_improvement},
        "source_record_review": {"plan": plan_review, "improvement": improvement_review},
        "api_read_review": {
            "record_object": observed_record_object,
            "prior_playbook_object": prior_playbook_object,
            "playbook_object": observed_playbook_object,
            "plan": api_plan_review,
            "improvement": api_improvement_review,
            "ownership_labels_valid": api_owned,
        },
        "initial_configmaps": initial_objects,
        "restoration": {"expected_order": expected_order, "actual_order": actual_order,
                        "ordered_observations": restored},
    }
    _write_evidence(lab, evidence)
    lab.check(
        "positive",
        "API-observed restoration follows the approved order and recreates exact fixture-owned ConfigMaps",
        order_valid and all_exact and api_improvement_review["valid"],
        {"expected_order": expected_order, "actual_order": actual_order,
         "all_restored_payloads_match": all_exact,
         "improvement_reflected_in_api_playbook": api_improvement_review["valid"],
         "native_playbook_revision_observed": playbook_updated},
    )
