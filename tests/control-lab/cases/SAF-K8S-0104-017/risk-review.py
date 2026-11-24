"""Exercise attributable approval and re-review for one owned exception record."""

import json
import time


NS = "saf-test"
NAME = "fixture-risk-reviewed-exception"
POLICY = "fixture-cis-risk-owner"
APPLICANT = "fixture-cis-requester"
OWNER = "fixture-cis-risk-owner"
DENIED = "only the designated fixture risk owner can approve or renew this exception"
SCOPE_DENIED = "an approved exception cannot be renewed with changed finding scope"
REVIEW_DENIED = "renewal requires a subsequent review and a new due date"
SCOPE = ("cluster_scope", "benchmark", "benchmark_version", "kubernetes_version",
         "benchmark_profile", "recommendation_id")


def subject(name):
    return f"system:serviceaccount:{NS}:{name}"


def install_rbac(lab):
    for name in (APPLICANT, OWNER):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name}})
    api = "rbac.authorization.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "Role", "metadata": {"name": POLICY},
                "rules": [
                    {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]},
                    {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [NAME],
                     "verbs": ["get", "patch"]},
                ]})
    lab.create({"apiVersion": api, "kind": "RoleBinding", "metadata": {"name": POLICY},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": POLICY},
                "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": NS}
                             for name in (APPLICANT, OWNER)]})


def install_authorization(lab):
    api = "admissionregistration.k8s.io/v1"
    lab.create({
        "apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [
                {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                 "resources": ["configmaps"]},
            ]},
            "matchConditions": [{"name": "owned-record",
                                 "expression": f"object.metadata.name == '{NAME}'"}],
            "validations": [
                {"expression": f"request.userInfo.username == '{subject(OWNER)}' && has(object.data) "
                               "&& 'approved_by' in object.data "
                               "&& object.data.approved_by == request.userInfo.username",
                 "message": DENIED, "reason": "Forbidden"},
                {"expression": "request.operation == 'CREATE' || (" + " && ".join(
                    f"'{field}' in object.data && oldObject.data['{field}'] == object.data['{field}']"
                    for field in SCOPE) + ")",
                 "message": SCOPE_DENIED, "reason": "Forbidden"},
                {"expression": "has(object.data) && 'reviewed_at' in object.data "
                               "&& 'review_revision' in object.data && 'review_due' in object.data "
                               "&& timestamp(object.data.review_due) > timestamp(object.data.reviewed_at) && "
                               "(request.operation == 'CREATE' ? object.data.review_revision == '1' : "
                               "int(object.data.review_revision) == int(oldObject.data.review_revision) + 1 && "
                               "timestamp(object.data.reviewed_at) <= timestamp(oldObject.data.review_due) && "
                               "timestamp(object.data.review_due) > timestamp(oldObject.data.review_due) && "
                               "timestamp(object.data.reviewed_at) > timestamp(oldObject.data.reviewed_at))",
                 "message": REVIEW_DENIED, "reason": "Forbidden"},
            ],
        },
    })
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                         "matchResources": {"namespaceSelector": {
                             "matchLabels": {"saf-k8s.example/cis-exception-policy": "enabled"},
                         }}}})


def create(lab, data, actor, *, dry_run):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("create", "--as", subject(actor), "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(data), allow_failure=True)


def renew(lab, patch, actor, *, dry_run):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("patch", "configmap", NAME, "--as", subject(actor), "--type=merge",
                       "--patch", json.dumps({"data": patch}), "-o", "json", *flags, allow_failure=True)


def denied(result, reason):
    return result.returncode != 0 and POLICY in result.stderr and reason in result.stderr


def run(lab, template):
    install_rbac(lab)
    initial = {**template["data"], "benchmark_profile": "owned-lab-fixture", "approved_by": subject(OWNER),
               "reviewed_at": "2026-11-21T00:00:00Z", "review_revision": "1"}
    resource = {**template, "metadata": {**template["metadata"], "name": NAME}, "data": initial}

    # Both subjects can submit the same request under RBAC so the counterfactual tests admission.
    before = create(lab, resource, APPLICANT, dry_run=True)
    deadline = time.monotonic() + 20
    while before.returncode != 0 and time.monotonic() < deadline:
        time.sleep(0.5)
        before = create(lab, resource, APPLICANT, dry_run=True)
    lab.check("red", "The requester can submit the forged approval before the risk-owner rule",
              before.returncode == 0, {"approval_forgery_admitted_in_baseline": before.returncode == 0})

    install_authorization(lab)
    response = create(lab, resource, APPLICANT, dry_run=True)
    deadline = time.monotonic() + 20
    while not denied(response, DENIED) and time.monotonic() < deadline:
        time.sleep(0.5)
        response = create(lab, resource, APPLICANT, dry_run=True)
    blocked = denied(response, DENIED)
    lab.check("green", "The same requester cannot approve an exception in the risk owner's name",
              blocked, {"approval_forgery_denied_by_expected_policy": blocked})

    approved = create(lab, resource, OWNER, dry_run=False)
    if approved.returncode != 0:
        lab.block("The designated risk-owner subject could not approve the owned exception")
    created = json.loads(approved.stdout)
    matches = created["data"] == initial and bool(created["metadata"]["uid"])
    lab.check("positive", "The designated risk owner creates the scoped approval",
              matches, {"approved_by_expected_subject": matches})

    updated = {"reviewed_at": "2026-12-21T00:00:00Z", "review_revision": "2",
               "review_due": "2027-01-21T00:00:00Z"}
    rejects_requester = denied(renew(lab, updated, APPLICANT, dry_run=True), DENIED)
    rejects_scope = denied(renew(lab, {**updated, "recommendation_id": "different"},
                                 OWNER, dry_run=True), SCOPE_DENIED)
    rejects_no_review = denied(renew(lab, {"review_due": updated["review_due"]}, OWNER, dry_run=True),
                               REVIEW_DENIED)
    rejects_late = denied(renew(lab, {**updated, "reviewed_at": "2026-12-22T00:00:00Z"},
                            OWNER, dry_run=True), REVIEW_DENIED)
    rejected = {"requester": rejects_requester, "changed_scope": rejects_scope,
                "extension_without_review": rejects_no_review, "missed_review_deadline": rejects_late}
    lab.check("green", "Renewal denies the wrong actor, changed scope, absent review and a missed deadline",
              all(rejected.values()), rejected)

    renewed = renew(lab, updated, OWNER, dry_run=False)
    if renewed.returncode != 0:
        lab.block("The designated risk owner could not renew the valid reviewed exception")
    current = json.loads(lab.kubectl("get", "configmap", NAME, "-o", "json").stdout)
    evidence = {
        "same_record": current["metadata"]["uid"] == created["metadata"]["uid"],
        "same_scope": all(current["data"][field] == initial[field] for field in SCOPE),
        "expected_renewal": current["data"] == {**initial, **updated},
    }
    lab.check("positive", "An attributable re-review renews the same exact finding scope",
              all(evidence.values()), evidence)
