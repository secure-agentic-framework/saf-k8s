"""Exercise governed source allowlisting through Kubernetes Jobs and RBAC."""
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
APPROVER = "security-engineering-reviewer"
CRITERIA_ID = "model-source-review-v1"
EVIDENCE = "case-owned:SAF-K8S-0905-052:synthetic-review-record"
CID = "sha256:" + "a" * 64

CRITERIA = {
    "criteria_id": CRITERIA_ID,
    "criteria": [
        "Source identifier is exact and scoped to one repository, publisher, or registry namespace.",
        "Publisher identity and provenance evidence are documented for this source.",
        "Permitted use and licensing basis are documented and accepted.",
        "A named Security Engineering approver records the decision and evidence reference.",
    ],
    "approver": APPROVER,
    "evidence_ref": EVIDENCE,
    "publisher_evidence": "case-owned:fixture-team-identity",
    "license_basis": "case-owned:synthetic-fixture-use",
}

RECORDS = [
    {"kind": "repository", "source": "https://models.example.invalid/saf-fixture/model-a",
     "publisher": "saf-fixture-team", "cid": ""},
    {"kind": "publisher", "source": "saf-fixture-team",
     "publisher": "saf-fixture-team", "cid": ""},
    {"kind": "registry-namespace", "source": "registry.example.invalid/saf-fixture",
     "publisher": "saf-fixture-team", "cid": CID},
]

APPROVED = [{**row, "criteria_id": CRITERIA_ID, "criteria": CRITERIA["criteria"],
             "approval_status": "approved", "approver": APPROVER, "evidence": EVIDENCE,
             "publisher_evidence": CRITERIA["publisher_evidence"], "license_basis": CRITERIA["license_basis"]}
            for row in RECORDS]
INCOMPLETE = {"kind": "repository", "source": RECORDS[0]["source"],
              "publisher": RECORDS[0]["publisher"], "cid": ""}
UNAPPROVED = {**APPROVED[0], "approval_status": "pending"}

SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster exercises inert repository, publisher, and "
    "registry-namespace/CID approval records. Immutable ConfigMap proposals are read by a restricted "
    "review Job. An isolated publisher Job can patch only the named allowlist ConfigMap; a separate "
    "unprivileged Job is denied. Red, green, and positive observations use the same in-cluster API path. "
    "This tests fixture policy evaluation, Kubernetes authorization, and persistence only; it does not "
    "establish that the named approver is a real person or that the documented evidence is true."
)


def _create(lab, obj):
    lab.create(obj)


def _policy_resources(lab):
    _create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": "source-approval-criteria"}, "immutable": True,
                  "data": {"criteria.json": json.dumps(CRITERIA, sort_keys=True)}})
    _create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": "source-review-worker"}, "immutable": True,
                  "data": {"worker.py": (HERE / "worker.py").read_text()}})
    _create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": "approved-model-sources"},
                  "data": {"records.json": "[]"}})
    for name, record in (("proposal-incomplete", INCOMPLETE), ("proposal-unapproved", UNAPPROVED),
                         ("proposal-repository", APPROVED[0]), ("proposal-publisher", APPROVED[1]),
                         ("proposal-registry", APPROVED[2])):
        _create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                      "metadata": {"name": name}, "immutable": True,
                      "data": {"record.json": json.dumps(record, sort_keys=True)}})
    for account in ("source-reviewer", "source-publisher", "source-unprivileged"):
        _create(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                      "metadata": {"name": account, "namespace": NAMESPACE}})
    read_role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                 "metadata": {"name": "source-review-read", "namespace": NAMESPACE},
                 "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                            "resourceNames": ["source-approval-criteria", "proposal-incomplete",
                                              "proposal-unapproved", "proposal-repository",
                                              "proposal-publisher", "proposal-registry"],
                            "verbs": ["get"]}]}
    _create(lab, read_role)
    _create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                  "metadata": {"name": "source-review-read", "namespace": NAMESPACE},
                  "subjects": [{"kind": "ServiceAccount", "name": "source-reviewer",
                                "namespace": NAMESPACE}],
                  "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                              "name": "source-review-read"}})
    publisher_role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                      "metadata": {"name": "source-allowlist-publish", "namespace": NAMESPACE},
                      "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                                 "resourceNames": ["source-approval-criteria", "proposal-incomplete",
                                                   "proposal-unapproved", "proposal-repository",
                                                   "proposal-publisher", "proposal-registry"],
                                 "verbs": ["get"]},
                                {"apiGroups": [""], "resources": ["configmaps"],
                                 "resourceNames": ["approved-model-sources"], "verbs": ["get", "patch"]}]}
    _create(lab, publisher_role)
    _create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                  "metadata": {"name": "source-allowlist-publish", "namespace": NAMESPACE},
                  "subjects": [{"kind": "ServiceAccount", "name": "source-publisher",
                                "namespace": NAMESPACE}],
                  "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                              "name": "source-allowlist-publish"}})


def _job(lab, name, account, mode, proposal):
    _create(lab, {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                  "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60,
                           "template": {"metadata": {"labels": {"app": name}}, "spec": {
                               "restartPolicy": "Never", "serviceAccountName": account,
                               "automountServiceAccountToken": True,
                               "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                   "seccompProfile": {"type": "RuntimeDefault"}},
                               "containers": [{"name": "worker", "image": PYTHON,
                                               "imagePullPolicy": "IfNotPresent",
                                               "command": ["python", "-B", "/worker/worker.py", mode, proposal],
                                               "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                             "limits": {"cpu": "100m", "memory": "64Mi"}},
                                               "securityContext": {"allowPrivilegeEscalation": False,
                                                                   "readOnlyRootFilesystem": True,
                                                                   "capabilities": {"drop": ["ALL"]}},
                                               "volumeMounts": [{"name": "worker", "mountPath": "/worker",
                                                                 "readOnly": True}]}],
                               "volumes": [{"name": "worker", "configMap": {
                                   "name": "source-review-worker", "defaultMode": 292}}]}}}})
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        states = {x["type"] for x in job.get("status", {}).get("conditions", []) if x["status"] == "True"}
        if "Failed" in states:
            lab.kubectl("logs", "job/" + name, allow_failure=True)
            lab.block("Job failed outside the expected policy result: " + name)
        if "Complete" in states:
            return lab.kubectl("logs", "job/" + name).stdout.strip()
        time.sleep(0.5)
    lab.block("Job timed out: " + name)


def _stored(lab):
    obj = lab.kubectl("get", "configmap/approved-model-sources", "-o", "json").stdout
    return json.loads(json.loads(obj)["data"]["records.json"])


def run(lab):
    _policy_resources(lab)

    immutable_probe = lab.kubectl(
        "patch", "configmap/proposal-repository", "--type=merge",
        "-p", json.dumps({"data": {"record.json": "{}"}}), allow_failure=True)
    immutable_error = (immutable_probe.stderr + immutable_probe.stdout).lower()
    immutable = immutable_probe.returncode != 0 and "immutable" in immutable_error
    lab.check("green", "Kubernetes refuses mutation of the immutable source proposal",
              immutable, {"proposal_mutation_rejected": immutable})

    red_log = _job(lab, "source-red", "source-publisher", "publish-inactive", "proposal-incomplete")
    red_rows = _stored(lab)
    red_ok = ("PUBLISHED criteria=inactive" in red_log and red_rows == [INCOMPLETE])
    lab.check("red", "With criteria enforcement inactive, the publisher accepts and persists the same well-formed but incomplete source record",
              red_ok, {"inactive_policy_accepted": red_ok, "persisted_records": len(red_rows)})
    lab.kubectl("patch", "configmap/approved-model-sources", "--type=merge", "-p",
                json.dumps({"data": {"records.json": "[]"}}))

    incomplete_log = _job(lab, "source-incomplete", "source-publisher", "publish", "proposal-incomplete")
    unapproved_log = _job(lab, "source-unapproved", "source-publisher", "publish", "proposal-unapproved")
    green_incomplete = incomplete_log == "POLICY_REJECT record=proposal-incomplete" and _stored(lab) == []
    green_unapproved = unapproved_log == "POLICY_REJECT record=proposal-unapproved" and _stored(lab) == []
    lab.check("green", "The same publisher rejects an incomplete record under the documented criteria",
              green_incomplete, {"incomplete_record_rejected": green_incomplete})
    lab.check("green", "The same publisher rejects a complete record without approved status",
              green_unapproved, {"unapproved_record_rejected": green_unapproved})
    denied_log = _job(lab, "source-unprivileged", "source-unprivileged", "unauthorized", "proposal-repository")
    denied = denied_log == "API_FORBIDDEN target=approved-model-sources"
    lab.check("green", "An unprivileged Job identity cannot patch the allowlist ConfigMap",
              denied, {"allowlist_patch_forbidden": denied})

    for suffix, proposal in (("repository", "proposal-repository"),
                             ("publisher", "proposal-publisher"),
                             ("registry", "proposal-registry")):
        evaluated = _job(lab, "source-evaluate-" + suffix, "source-reviewer", "evaluate", proposal)
        approved = APPROVED[{"repository": 0, "publisher": 1, "registry": 2}[suffix]]
        expected = "EVALUATION_APPROVED record=%s criteria=%s approver=%s" % (proposal, CRITERIA_ID, APPROVER)
        if evaluated != expected:
            lab.block("Approved record evaluation did not complete as expected")
        published = _job(lab, "source-publish-" + suffix, "source-publisher", "publish", proposal)
        if "PUBLISHED kind=" + approved["kind"] not in published:
            lab.block("Approved record publication did not complete as expected")

    rows = _stored(lab)
    positive = rows == APPROVED and all(row["approver"] == APPROVER and
                                         row["criteria_id"] == CRITERIA_ID and
                                         row["evidence"] == EVIDENCE for row in rows)
    lab.check("positive", "Approved repository, publisher, and registry namespace/CID records persist with criteria, approver, and evidence references",
              positive, {"approved_records_persisted": positive,
                         "repository_present": any(x["kind"] == "repository" for x in rows),
                         "publisher_present": any(x["kind"] == "publisher" for x in rows),
                         "registry_namespace_and_cid_present": any(x["kind"] == "registry-namespace" and x["cid"] == CID for x in rows),
                         "governance_evidence_present": positive})

    (lab.evidence / "model-source-approval.json").write_text(json.dumps(
        {"criteria": CRITERIA, "accepted_records": rows, "inactive_records": red_rows,
         "checked_results": lab.checks}, indent=2) + "\n")
