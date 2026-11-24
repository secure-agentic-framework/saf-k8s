"""Observe live fixture inventory and exercise exact runtime exposure exceptions."""
from datetime import datetime, timedelta, timezone
import json

from fixtures import container, pod

SCOPE = ("One read-only fixture inventory correlates an inert advisory to a real running Pod UID "
         "and runtime image ID. The exact exception policy and independent report approval are "
         "exercised in one owned namespace. Continuous monitoring and rollout remain deployment evidence.")
NS = "saf-test"
TARGET = "fixture-ai-runtime"
NEIGHBOR = "fixture-normal-runtime"
REPORT = "fixture-runtime-exposure"
OBSERVER = "fixture-runtime-observer"
OWNER = "fixture-runtime-owner"
APPROVER = "fixture-runtime-approver"
ADVISORY = "TEST-SAF-RUNTIME-0001"
RBAC = "rbac.authorization.k8s.io/v1"


def get(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def as_role(name):
    return f"--as=system:serviceaccount:{NS}:{name}"


def create_role(lab, actor, verbs, resource, name=None):
    rule = {"apiGroups": [""], "resources": [resource], "verbs": verbs}
    if name is not None:
        rule["resourceNames"] = [name]
    lab.create({"apiVersion": RBAC, "kind": "Role", "metadata": {"name": actor}, "rules": [rule]})
    lab.create({"apiVersion": RBAC, "kind": "RoleBinding", "metadata": {"name": actor},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": actor},
                "subjects": [{"kind": "ServiceAccount", "namespace": NS, "name": actor}]})


def status(row):
    spec = row["spec"]
    running = next((s for s in row["status"].get("containerStatuses", [])
                    if s["name"] == "fixture" and "running" in s.get("state", {})), None)
    if running is None or not running.get("imageID") or not running.get("containerID"):
        return None
    return {"pod": row["metadata"]["name"], "pod_uid": row["metadata"]["uid"],
            "namespace": row["metadata"]["namespace"], "node": spec["nodeName"],
            "image_id": running["imageID"], "container_id": running["containerID"],
            "declared_image": spec["containers"][0]["image"]}


def finding(subject, evidence):
    if (subject["pod_uid"], subject["image_id"]) != (evidence["pod_uid"], evidence["image_id"]):
        return None
    return {"advisory": evidence["advisory"], "severity": evidence["severity"],
            "package": evidence["package"], "subject": subject}


def exception_decision(record, exposed, now):
    if record["owner"] != OWNER or record["approver"] != APPROVER or not record["reason"]:
        return "approval-refused"
    expected = {"pod_uid": exposed["subject"]["pod_uid"], "image_id": exposed["subject"]["image_id"],
                "namespace": exposed["subject"]["namespace"], "advisory": exposed["advisory"]}
    if any(record[key] != value for key, value in expected.items()):
        return "scope-mismatch"
    try:
        start, end = (datetime.fromisoformat(record[key]) for key in ("start", "end"))
        if start.utcoffset() is None or end.utcoffset() is None or end <= start:
            return "invalid-window"
    except (TypeError, ValueError):
        return "invalid-window"
    if end - start > timedelta(days=7):
        return "expiry-too-long"
    if not start <= now < end:
        return "outside-window"
    return "accepted-visible"


def denied(result, permission):
    return result.returncode != 0 and "Forbidden" in result.stderr and permission in result.stderr


def run(lab):
    for name in (TARGET, NEIGHBOR):
        lab.create(pod(name, [container("fixture")], automountServiceAccountToken=False))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{TARGET}", f"pod/{NEIGHBOR}",
                "--timeout=100s", timeout=110)
    for name in (OBSERVER, OWNER, APPROVER):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name},
                    "automountServiceAccountToken": False})

    baseline = lab.kubectl(as_role(OBSERVER), "get", "pods", allow_failure=True)
    before = get(lab, "get", "pod", TARGET)
    no_report = lab.kubectl("get", "configmap", REPORT, allow_failure=True)
    red = {"running_target": status(before) is not None,
           "inventory_unavailable_to_unbound_observer": denied(baseline, "cannot list"),
           "report_absent": no_report.returncode != 0 and "NotFound" in no_report.stderr}
    lab.check("red", "An active workload has no exposure report or scoped observation path",
              all(red.values()), red)

    create_role(lab, OBSERVER, ["list"], "pods")
    listing = get(lab, as_role(OBSERVER), "get", "pods")
    inventory = {row["metadata"]["name"]: status(row) for row in listing["items"]
                 if row["metadata"]["name"] in (TARGET, NEIGHBOR)}
    if any(inventory.get(name) is None for name in (TARGET, NEIGHBOR)):
        lab.block("A live fixture container with a runtime image ID is missing")
    target, neighbor = inventory[TARGET], inventory[NEIGHBOR]
    evidence = {"advisory": ADVISORY, "severity": "HIGH", "package": "fixture-ai-dependency",
                "pod_uid": target["pod_uid"], "image_id": target["image_id"], "synthetic": True}
    exposed = finding(target, evidence)
    if exposed is None:
        lab.block("Exact runtime fixture is missing from the exposure assessment")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    record = {"owner": OWNER, "approver": APPROVER, "namespace": NS,
              "pod_uid": target["pod_uid"], "image_id": target["image_id"], "advisory": ADVISORY,
              "start": (now - timedelta(minutes=1)).isoformat(),
              "end": (now + timedelta(minutes=15)).isoformat(),
              "reason": "Temporary fixture remediation window"}
    cases = {"approved": {}, "self-approved": {"approver": OWNER}, "wrong-subject": {
        "pod_uid": neighbor["pod_uid"]}, "wrong-image": {"image_id": "sha256:" + "0" * 64},
        "expired": {"end": now.isoformat()},
        "overlong": {"end": (now + timedelta(days=8)).isoformat()},
        "premature": {"start": (now + timedelta(minutes=2)).isoformat()}}
    decisions = {key: exception_decision({**record, **changes}, exposed, now)
                 for key, changes in cases.items()}
    exposed["exception"] = decisions["approved"]
    report = {"evidence": evidence, "inventory": inventory, "exposures": [exposed],
              "exception": record, "decisions": decisions, "evaluated_at": now.isoformat()}

    create_role(lab, OWNER, ["get"], "configmaps", REPORT)
    create_role(lab, APPROVER, ["get", "patch"], "configmaps", REPORT)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": REPORT},
                "data": {"report.json": json.dumps(report, sort_keys=True, separators=(",", ":"))}})
    approval_patch = json.dumps({"metadata": {"annotations": {"saf.fixture/reviewed-by": APPROVER}}})
    owner_attempt = lab.kubectl(as_role(OWNER), "patch", "configmap", REPORT, "--type=merge",
                                "--patch", approval_patch, allow_failure=True)
    after_owner = get(lab, "get", "configmap", REPORT)
    approver_result = lab.kubectl(as_role(APPROVER), "patch", "configmap", REPORT, "--type=merge",
                                  "--patch", approval_patch, "-o", "name")
    observed = get(lab, "get", "configmap", REPORT)
    monitor_secret = lab.kubectl(as_role(OBSERVER), "get", "secrets", allow_failure=True)
    expected = {"approved": "accepted-visible", "self-approved": "approval-refused",
                "wrong-subject": "scope-mismatch", "wrong-image": "scope-mismatch",
                "expired": "outside-window", "overlong": "expiry-too-long", "premature": "outside-window"}
    green = {"live_subject_matches": target["pod_uid"] == before["metadata"]["uid"],
             "different_image_has_no_match": finding(target, {**evidence, "image_id": "invalid"}) is None,
             "only_observed_fixture_alerted": json.loads(observed["data"]["report.json"]) == report,
             "all_exception_decisions_match": decisions == expected,
             "self_approval_refused_by_api": denied(owner_attempt, "cannot patch") and
             "saf.fixture/reviewed-by" not in after_owner["metadata"].get("annotations", {}),
             "approved_actor_recorded": approver_result.stdout.strip() == f"configmap/{REPORT}" and
             observed["metadata"]["annotations"]["saf.fixture/reviewed-by"] == APPROVER,
             "monitor_cannot_read_secrets": denied(monitor_secret, "cannot list")}
    lab.check("green", "Exact runtime exposure stays visible while scoped exception rules apply",
              all(green.values()), green)
    current = status(get(lab, "get", "pod", NEIGHBOR))
    positive = {"ordinary_fixture_remains_running": current == neighbor,
                "different_pod_is_unalerted": target["pod_uid"] != neighbor["pod_uid"] and
                finding(neighbor, evidence) is None,
                "review_did_not_remove_alert": json.loads(observed["data"]["report.json"])["exposures"]
                == [exposed]}
    lab.check("positive", "The ordinary fixture stays available and the accepted alert stays visible",
              all(positive.values()), positive)

    raw = {"report": report, "cluster_uid": get(lab, "get", "namespace", "kube-system")["metadata"]["uid"],
           "report_uid": observed["metadata"]["uid"],
           "receipt_versions": [after_owner["metadata"]["resourceVersion"],
                                observed["metadata"]["resourceVersion"]]}
    normalized = {"control": "SAF-K8S-0601-019", "baseline": red, "observed": green,
                  "positive": positive, "advisory": ADVISORY, "decisions": decisions}
    for name, value in (("runtime-exposure-observations.json", raw),
                        ("runtime-exposure-normalized.json", normalized)):
        (lab.evidence / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
