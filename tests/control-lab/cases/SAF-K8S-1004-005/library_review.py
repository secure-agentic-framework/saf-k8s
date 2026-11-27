"""Authoritative fixture library revisions and scoped admission for synthetic review records."""
import hashlib
import json
import time

NS = "saf-aml-library"
POLICY = "saf-aml-library-binding"
LIBRARY = "approved-pattern-library"
RECORD = "synthetic-review"
ROUTING_POLICY = "saf-aml-detection-route-binding"
ROUTING_ROSTER = "approved-synthetic-detection-route"
ROUTING_MESSAGE = "SAF AML fixture requires the approved detection and triage route"
CURATOR = "curator"
OBSERVER = "observer"
TAXONOMY = "NIST AI 100-2e2025"
POLICY_MESSAGE = "SAF AML fixture requires the current library and bounded review fields"


def _create(lab, resource):
    lab.kubectl("-n", NS, "create", "-f", "-", payload=json.dumps(resource))


def _role(lab, actor, rules):
    group = "rbac.authorization.k8s.io"
    _create(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": actor, "namespace": NS}, "automountServiceAccountToken": False})
    _create(lab, {"apiVersion": group + "/v1", "kind": "Role",
                "metadata": {"name": actor, "namespace": NS}, "rules": rules})
    _create(lab, {"apiVersion": group + "/v1", "kind": "RoleBinding",
                "metadata": {"name": actor, "namespace": NS},
                "roleRef": {"apiGroup": group, "kind": "Role", "name": actor},
                "subjects": [{"kind": "ServiceAccount", "name": actor, "namespace": NS}]})


def _as(actor):
    return "--as=system:serviceaccount:" + NS + ":" + actor


def _read(lab, name, actor=None):
    principal = [_as(actor)] if actor else []
    return json.loads(lab.kubectl("-n", NS, *principal, "get", "configmap", name,
                                 "-o", "json").stdout)


def _patch(lab, data, actor, *, dry_run=False):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("-n", NS, _as(actor), "patch", "configmap", RECORD, "--type=merge",
                       "-p", json.dumps({"data": data}), "-o", "json", *flags,
                       allow_failure=True)


def _wait_for(lab, predicate, error):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        response = predicate()
        if response is not None:
            return response
        time.sleep(0.5)
    lab.block(error)


def _policy(lab, *, name=POLICY, parameter=LIBRARY, message=POLICY_MESSAGE,
            fields=("taxonomy", "libraryRevision", "evidenceDigest")):
    api_version = "admissionregistration.k8s.io/v1"
    expression = (
        "params != null && has(params.data) && has(object.data)"
        f" && {json.dumps(fields)}.all(k,"
        " k in object.data && k in params.data && object.data[k] == params.data[k])"
        " && 'reviewState' in object.data && object.data.reviewState == 'pending-human-review'"
        " && 'attackClass' in object.data && object.data.attackClass == 'unassigned'"
        " && 'incidentEstablished' in object.data && object.data.incidentEstablished == 'false'"
    )
    _create(lab, {"apiVersion": api_version, "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": name},
                "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": {
                             "namespaceSelector": {"matchLabels": {"saf.example/aml-library": "owned"}},
                             "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                "operations": ["UPDATE"], "resources": ["configmaps"]}]},
                         "matchConditions": [{"name": "owned-review", "expression":
                                              "request.namespace == '" + NS + "' && object.metadata.name == '" + RECORD + "'"}],
                         "validations": [{"expression": expression, "message": message}]}})
    _create(lab, {"apiVersion": api_version, "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": name},
                "spec": {"policyName": name, "validationActions": ["Deny"],
                         "paramRef": {"name": parameter, "namespace": NS,
                                      "parameterNotFoundAction": "Deny"}}})


def _policy_denied(response, message=POLICY_MESSAGE):
    return response.returncode != 0 and message in response.stderr


def _resource_version(row):
    return row["metadata"]["resourceVersion"]


def run(lab, record, verdict):
    if (verdict.get("review_state") != "pending_human_review"
            or record.get("actual_incident") is not False or record.get("candidate_attack_class") is not None):
        lab.block("The original bounded review did not produce a synthetic pending candidate")
    source_digest = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    library = {"taxonomy": TAXONOMY, "libraryRevision": "synthetic-v1", "evidenceDigest": source_digest}
    pending = dict(library, reviewState="pending-human-review", attackClass="unassigned", incidentEstablished="false")
    _create(lab, {"apiVersion": "v1", "kind": "Namespace",
                "metadata": {"name": NS, "labels": {"saf.example/aml-library": "owned"}}})
    for name, data in ((LIBRARY, library), (RECORD, pending)):
        _create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": name, "namespace": NS}, "data": data})
    exact_names = {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [LIBRARY, RECORD]}
    roster_read = dict(exact_names, resourceNames=[ROUTING_ROSTER], verbs=["get"])
    _role(lab, CURATOR, [dict(exact_names, verbs=["get", "patch"]), roster_read])
    _role(lab, OBSERVER, [dict(exact_names, verbs=["get"]), roster_read])

    stale = dict(pending, libraryRevision="obsolete")
    overclaim = dict(pending, attackClass="unsupported-synthetic-class", incidentEstablished="true")
    before = _read(lab, RECORD)
    def observe_baseline():
        response = _patch(lab, stale, CURATOR, dry_run=True)
        return response if response.returncode == 0 else None

    gap = _wait_for(lab, observe_baseline, "The pre-policy curator baseline did not reach dry-run admission")
    dry_run_object = json.loads(gap.stdout)
    lab.check("red", "Before the guard, the scoped curator can dry-run a stale library reference",
              dry_run_object["data"] == stale and _read(lab, RECORD)["data"] == pending,
              {"stale_request_reaches_admission": dry_run_object["data"] == stale,
               "live_record_stays_pending": _read(lab, RECORD)["data"] == pending})

    _policy(lab)
    def observe_activation():
        response = _patch(lab, stale, CURATOR, dry_run=True)
        return response if _policy_denied(response) else None
    denied_stale = _wait_for(lab, observe_activation, "The exact native review policy did not reject the stale dry run")
    denied_overclaim = _patch(lab, overclaim, CURATOR, dry_run=True)
    denied_evidence = _patch(lab, dict(pending, evidenceDigest="0" * 64), CURATOR, dry_run=True)
    denied_observer = _patch(lab, pending, OBSERVER)
    unchanged = _read(lab, RECORD)
    observer_read = _read(lab, RECORD, OBSERVER)
    rbac_denied = (denied_observer.returncode != 0 and "(Forbidden)" in denied_observer.stderr
                   and _as(OBSERVER).split("=", 1)[1] in denied_observer.stderr)
    lab.check("green", "Native admission refuses stale or overstated reviews and the observer cannot write",
              _policy_denied(denied_stale) and _policy_denied(denied_overclaim) and rbac_denied
              and _policy_denied(denied_evidence)
              and observer_read["metadata"]["uid"] == before["metadata"]["uid"] and unchanged == before,
              {"stale_denied": _policy_denied(denied_stale),
               "overclaim_denied": _policy_denied(denied_overclaim), "observer_write_denied": rbac_denied,
               "wrong_evidence_digest_denied": _policy_denied(denied_evidence),
               "observer_exact_read_allowed": observer_read["metadata"]["uid"] == before["metadata"]["uid"],
               "no_mutation": unchanged == before})

    previous_library = _read(lab, LIBRARY)
    next_library = dict(library, libraryRevision="synthetic-v2")
    changed_library = json.loads(lab.kubectl("-n", NS, _as(CURATOR), "patch", "configmap", LIBRARY,
                                            "--type=merge", "-p", json.dumps({"data": next_library}),
                                            "-o", "json").stdout)
    candidate = dict(pending, libraryRevision=next_library["libraryRevision"])
    def observe_revision():
        response = _patch(lab, pending, CURATOR, dry_run=True)
        return response if _policy_denied(response) else None
    after_revision = _wait_for(lab, observe_revision, "The review guard did not observe the new library revision")
    accepted = _patch(lab, candidate, CURATOR)
    if accepted.returncode != 0:
        lab.block("The current bounded curator submission was not admitted")
    accepted_object = json.loads(accepted.stdout)
    observed = _read(lab, RECORD, OBSERVER)
    exact_revision = (changed_library["data"] == next_library
                      and changed_library["metadata"]["uid"] == previous_library["metadata"]["uid"]
                      and _resource_version(changed_library) != _resource_version(previous_library))
    exact_record = (observed["data"] == candidate and observed["metadata"]["uid"] == before["metadata"]["uid"]
                    and _resource_version(observed) == _resource_version(accepted_object)
                    and _resource_version(observed) != _resource_version(before))
    lab.check("positive", "The scoped curator advances the exact pending record to the current library revision",
              exact_revision and _policy_denied(after_revision) and exact_record,
              {"same_library_uid_new_revision": exact_revision,
               "previously_current_revision_denied": _policy_denied(after_revision),
               "same_record_uid_current_pending_data": exact_record})
    (lab.evidence / "taxonomy-library-revision.raw.json").write_text(json.dumps({
        "fixture_only": True, "record_id": record["record_id"], "evidence_digest": source_digest,
        "library_before": previous_library, "library_after": changed_library,
        "review_before": before, "observer_after": observed, "review_api_write": accepted_object,
        "denials": {"stale": _policy_denied(denied_stale), "overclaim": _policy_denied(denied_overclaim),
                    "observer_write": rbac_denied, "previous_revision": _policy_denied(after_revision),
                    "wrong_evidence_digest": _policy_denied(denied_evidence)},
    }, indent=2, sort_keys=True) + "\n")


    _exercise_detection_route(lab, candidate, observed)


def _exercise_detection_route(lab, candidate, before):
    route = {
        "libraryRevision": candidate["libraryRevision"],
        "patternKey": "synthetic-pattern-01",
        "detectorRef": "fixture-detection-0042",
        "riskQueue": "pending-fixture-risk-review",
        "controlRef": "SAF-K8S-1001-012",
    }
    _create(lab, {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
                 "metadata": {"name": ROUTING_ROSTER, "namespace": NS}, "data": route})
    wrong = dict(route, detectorRef="unlisted-fixture-detector")
    spread = _patch(lab, wrong, CURATOR, dry_run=True)
    lab.check("red", "Before the detection-route binding an unlisted reference reaches dry-run admission",
              spread.returncode == 0 and json.loads(spread.stdout)["data"]["detectorRef"] == wrong["detectorRef"]
              and _read(lab, RECORD) == before,
              {"unlisted_reference_dry_run_admitted": spread.returncode == 0,
               "original_exact_pending_record_retained": _read(lab, RECORD) == before})

    _policy(lab, name=ROUTING_POLICY, parameter=ROUTING_ROSTER, message=ROUTING_MESSAGE,
            fields=tuple(route))

    def observe_denial():
        response = _patch(lab, wrong, CURATOR, dry_run=True)
        return response if _policy_denied(response, ROUTING_MESSAGE) else None

    wrong_ref = _wait_for(lab, observe_denial, "The detection-route policy did not refuse the unlisted reference")
    wrong_queue = _patch(lab, dict(route, riskQueue="unlisted-fixture-queue"), CURATOR, dry_run=True)
    roster_update = lab.kubectl(
        "-n", NS, _as(CURATOR), "patch", "configmap", ROUTING_ROSTER, "--type=merge",
        "-p", json.dumps({"data": wrong}), "--dry-run=server", allow_failure=True)
    previous = _read(lab, RECORD, OBSERVER)
    accepted = _patch(lab, route, CURATOR)
    if accepted.returncode:
        lab.block("The curator could not persist the exact listed synthetic route")
    accepted_row = json.loads(accepted.stdout)
    observed = _read(lab, RECORD, OBSERVER)
    roster = _read(lab, ROUTING_ROSTER, OBSERVER)
    observations = {
        "unlisted_detector_denied": _policy_denied(wrong_ref, ROUTING_MESSAGE),
        "unlisted_risk_queue_denied": _policy_denied(wrong_queue, ROUTING_MESSAGE),
        "route_roster_immutable_and_exact": roster.get("immutable") is True and roster["data"] == route,
        "curator_denied_roster_mutation": roster_update.returncode != 0 and "(Forbidden)" in roster_update.stderr,
        "pending_record_and_original_evidence_bound": observed["data"] == {**candidate, **route},
        "same_record_uid_before_and_after": observed["metadata"]["uid"] == before["metadata"]["uid"],
        "only_exact_valid_update_persisted": previous == before and
            _resource_version(accepted_row) == _resource_version(observed) != _resource_version(before),
    }
    (lab.evidence / "taxonomy-detection-route.raw.json").write_text(json.dumps({
        "roster": roster, "previous_review": previous, "routed_review": observed,
        "observations": observations}, indent=2, sort_keys=True) + "\n")
    lab.check("green", "An exact library detection route is persisted while unlisted references are refused",
              all(observations.values()), observations)
