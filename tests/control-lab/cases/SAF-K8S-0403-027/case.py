"""Exercise incident intake, separation of duties and live access containment."""
import json
import time

NS = "saf-test"
MARKER = "SAF_PUBLIC_SYNTHETIC_INCIDENT_MARKER_0403"
CLEAN = "public approved read control"
EXPOSED = "fixture-exposed-artifact"
UNAFFECTED = "fixture-approved-artifact"
FINDING = "fixture-finding"
INCIDENT = "fixture-incident"
ESCALATION = "fixture-escalation"
RBAC = "rbac.authorization.k8s.io/v1"
SCOPE = (
    "The case handles an unmistakably public fixture finding through scoped Kubernetes "
    "RBAC, an owned intake record, triage, escalation, and removal of an actual authorization "
    "grant. The exercised incident record is cluster-backed. Real organizational escalation "
    "delivery, provider incident intake, and credential invalidation remain separate."
)


def account(actor):
    return f"system:serviceaccount:{NS}:{actor}"


def resource(lab, kind, name, **body):
    api = RBAC if kind in ("Role", "RoleBinding") else "v1"
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **body})


def grant(lab, name, actor, rules):
    resource(lab, "Role", name, rules=rules)
    resource(lab, "RoleBinding", name,
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
             subjects=[{"kind": "ServiceAccount", "namespace": NS, "name": actor}])


def rule(names, verbs, kind="configmaps", group=""):
    return {"apiGroups": [group], "resources": [kind], "resourceNames": names, "verbs": verbs}


def as_actor(lab, actor, *args):
    return lab.kubectl("--as=" + account(actor), *args, allow_failure=True)


def data(lab, actor, name):
    result = as_actor(lab, actor, "get", "configmap", name, "-o", "json")
    return json.loads(result.stdout)["data"] if result.returncode == 0 else None


def patch(lab, actor, name, **value):
    return as_actor(lab, actor, "patch", "configmap", name, "--type=merge", "-p",
                    json.dumps({"data": value}), "-o", "name")


def forbid(result):
    return result.returncode != 0 and "(Forbidden)" in result.stderr


def must(lab, result, action):
    if result.returncode != 0:
        lab.block(f"Fixture operation failed: {action}")


def run(lab):
    for actor in ("detector", "responder", "reader"):
        resource(lab, "ServiceAccount", actor)
    for name, doc in (
        (EXPOSED, {"content": MARKER}), (UNAFFECTED, {"content": CLEAN}),
        (FINDING, {"state": "empty"}), (INCIDENT, {"state": "new"}), (ESCALATION, {"state": "unrouted"}),
    ):
        resource(lab, "ConfigMap", name, data=doc)
    grant(lab, "affected-read", "reader", [rule([EXPOSED], ["get"])])
    grant(lab, "unaffected-read", "reader", [rule([UNAFFECTED], ["get"])])
    grant(lab, "detector-intake", "detector", [rule([EXPOSED, UNAFFECTED], ["get"]), rule([FINDING], ["get", "patch"])])
    grant(lab, "response-authority", "responder", [
        rule([EXPOSED, FINDING, INCIDENT, ESCALATION], ["get"]),
        rule([INCIDENT, ESCALATION], ["patch"]),
        rule(["affected-read"], ["delete"], "rolebindings", "rbac.authorization.k8s.io"),
    ])
    marked = data(lab, "detector", EXPOSED)["content"] == MARKER
    clean = MARKER not in data(lab, "detector", UNAFFECTED)["content"]
    found_at = time.monotonic()
    must(lab, patch(lab, "detector", FINDING, state="reported", source=EXPOSED, finding="owned-marker"),
         "submit owned finding")
    denied = forbid(as_actor(lab, "detector", "delete", "rolebinding", "affected-read", "--wait=false"))
    refused_escalation = forbid(patch(lab, "detector", ESCALATION, state="routed"))
    precondition = {
        "exposure_present": data(lab, "reader", EXPOSED) == {"content": MARKER},
        "matching_finding_present": marked and data(lab, "responder", FINDING)["state"] == "reported",
        "detector_cannot_contain": denied,
        "detector_cannot_route_escalation": refused_escalation,
    }
    lab.check("red", "Intake alone leaves the published fixture accessible and the detector cannot change response state",
              all(precondition.values()), precondition)

    finding = data(lab, "responder", FINDING)
    confirmed = (finding["source"] == EXPOSED and finding["finding"] == "owned-marker"
                 and data(lab, "responder", EXPOSED)["content"] == MARKER)
    if not confirmed:
        lab.block("The responder could not substantiate the test finding")
    must(lab, patch(lab, "responder", INCIDENT, state="triaged", owner=account("responder"),
                    severity="fixture-high", finding=FINDING), "record triage")
    must(lab, patch(lab, "responder", ESCALATION, state="routed", case=INCIDENT,
                    destination="fixture-on-call"), "route owned escalation")
    must(lab, as_actor(lab, "responder", "delete", "rolebinding", "affected-read", "--wait=false"), "withdraw affected grant")
    deadline = found_at + 30
    after = False
    while time.monotonic() < deadline:
        after = forbid(as_actor(lab, "reader", "get", "configmap", EXPOSED, "-o", "name"))
        if after:
            break
        time.sleep(.4)
    elapsed = round(time.monotonic() - found_at, 3)
    must(lab, patch(lab, "responder", INCIDENT, state="contained" if after else "unresolved",
                    action="removed-affected-read", decision="forbidden" if after else "not-confirmed"),
         "record observed post-containment authorization")
    incident = data(lab, "responder", INCIDENT)
    escalation = data(lab, "responder", ESCALATION)
    outcome = {
        "independent_confirmation": confirmed,
        "actual_read_denied_within_fixture_target": after and elapsed <= 30,
        "contained_state_and_owner_retained": incident["state"] == "contained"
        and incident["owner"] == account("responder") and incident["finding"] == FINDING,
        "escalation_route_retained": escalation["state"] == "routed" and escalation["case"] == INCIDENT
        and escalation["destination"] == "fixture-on-call",
    }
    lab.check("green", "An authorized responder confirms, escalates and observes real containment before recording it",
              all(outcome.values()), outcome)
    boundary = {
        "authorized_artifact_read_preserved": data(lab, "reader", UNAFFECTED) == {"content": CLEAN},
        "benign_content_not_flagged": clean,
        "case_review_content_retained": data(lab, "responder", EXPOSED) == {"content": MARKER},
    }
    lab.check("positive", "Containment preserves the unaffected read and authorized incident review",
              all(boundary.values()), boundary)
    (lab.evidence / "incident-containment-observations.json").write_text(json.dumps({
        "intake": precondition, "containment": outcome, "boundary": boundary,
        "elapsed_seconds": elapsed, "fixture_target_seconds": 30,
    }, indent=2) + "\n")
