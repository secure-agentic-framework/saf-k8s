"""Require a separately documented trust review before model eligibility."""
from hashlib import sha256
import json
from pathlib import Path
import time

from fixtures import container, pod

HERE = Path(__file__).parent
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
NS = "saf-test"
RESULTS = "model-trust-decisions"
POLICY = "model-trust-eligibility"
SA = "model-trust-reviewer"
DIGEST = "saf.example/model-digest"
ACTOR = "fixture-security-reviewer"
OWNER = "fixture-platform-approval-owner"
CRITERIA = {"maintenance": "current", "publisher_documentation": "complete", "community_context": "corroborated"}
SIGNALS = {
    "eligible": {"maintenance": ("current", "fixture:update-log-current"),
                 "publisher_documentation": ("complete", "fixture:publisher-profile"),
                 "community_context": ("corroborated", "fixture:review-record")},
    "ineligible": {"maintenance": ("stale", "fixture:update-log-stale"),
                   "publisher_documentation": ("complete", "fixture:publisher-profile"),
                   "community_context": ("sparse", "fixture:review-record")},
}
SCOPE = (
    "One disposable Kind v1.36.1 cluster. Inert candidates carry equally verified provenance "
    "handoff records and separately supplied fictional trust evidence. A restricted Job "
    "persists disposition, rationale and reviewer data in Kubernetes. An admission policy "
    "using that record allows the reviewed artifact digest and rejects the discrepant one. "
    "This establishes the fixture decision path. Human review quality, real publisher or "
    "community signals, independent provenance verification and production coverage are open."
)


def _source(candidate):
    return {"source": f"https://models.example.invalid/{candidate}",
            "digest": "sha256:" + sha256(f"fixture-model:{candidate}".encode()).hexdigest(),
            "publisher": "fictional-fixture-team", "disposition": "verified"}


def _dossier():
    return {"revision": "fixture-trust-v1", "reviewer": ACTOR, "approval_authority": OWNER,
            "criteria": CRITERIA,
            "candidates": [{"candidate": name, "provenance": _source(name), "signals": {
                key: {"assessment": values[0], "evidence": values[1]} for key, values in metrics.items()}}
                           for name, metrics in SIGNALS.items()]}


def _request(lab, candidate):
    shape = pod("fixture-" + candidate, [container("fixture")], automountServiceAccountToken=False)
    shape["metadata"].update(labels={"saf.example/workload": "model"},
                             annotations={DIGEST: _source(candidate)["digest"]})
    return lab.create(shape, dry_run=True, allow_failure=True)


def _setup(lab):
    for name, data, mutable in (
        (RESULTS, {"approvedDigests": "", "record.json": "[]"}, True),
        ("fixture-trust-input", {"dossier.json": json.dumps(_dossier()),
                                "worker.py": (HERE / "worker.py").read_text()}, False),
    ):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "immutable": not mutable, "data": data})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": SA}})
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": SA},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [RESULTS],
                   "verbs": ["get", "update"]}],
    })
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": SA},
        "subjects": [{"kind": "ServiceAccount", "name": SA, "namespace": NS}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": SA},
    })


def _evaluate(lab):
    worker = container("review", image=PYTHON, command=["python", "-B", "/review/worker.py"],
                       volumeMounts=[{"name": "input", "mountPath": "/review", "readOnly": True}],
                       resources={"requests": {"cpu": "10m", "memory": "24Mi"},
                                  "limits": {"cpu": "150m", "memory": "80Mi"}})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "fixture-trust-review"},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
                         "template": {"spec": {"restartPolicy": "Never", "serviceAccountName": SA,
                                               "containers": [worker], "volumes": [{"name": "input",
                                                   "configMap": {"name": "fixture-trust-input"}}]}}}})
    lab.kubectl("wait", "--for=condition=Complete", "job/fixture-trust-review", "--timeout=70s", timeout=75)
    decoded = json.loads(lab.kubectl("get", "configmap/" + RESULTS, "-o", "json").stdout)["data"]
    activity = json.loads(lab.kubectl("logs", "job/fixture-trust-review").stdout)
    return decoded, activity


def _admission(lab):
    spec = {
        "failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
        "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                 "resources": ["pods"], "operations": ["CREATE"]}]},
        "validations": [{"expression": f"params != null && has(object.metadata.annotations) && "
                                      f"'{DIGEST}' in object.metadata.annotations && "
                                      f"object.metadata.annotations['{DIGEST}'].matches('^sha256:[a-f0-9]{{64}}$') && "
                                      f"object.metadata.annotations['{DIGEST}'] in params.data.approvedDigests.split(',')",
                         "message": "model digest lacks approved trust disposition", "reason": "Forbidden"}],
    }
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": POLICY}, "spec": spec})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                         "paramRef": {"name": RESULTS, "namespace": NS, "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector": {
                             "matchLabels": {"kubernetes.io/metadata.name": NS}},
                             "objectSelector": {"matchLabels": {"saf.example/workload": "model"}}}}})


def run(lab):
    _setup(lab)
    off = {key: _request(lab, key).returncode == 0 for key in SIGNALS}
    lab.check("red", "Both provenance-complete model declarations pass before trust eligibility is required",
              all(off.values()), off)
    record, activity = _evaluate(lab)
    decisions = {row["candidate"]: row for row in json.loads(record["record.json"])}
    states = {name: info["disposition"] for name, info in decisions.items()}
    reason = decisions["ineligible"]["unsatisfied_criteria"]
    recorded = all(info["reviewer"] == ACTOR and info["approval_authority"] == OWNER
                   and info["provenance"] == _source(name) and info["signals"] for name, info in decisions.items())
    verified = states == activity["dispositions"] == {"eligible": "approved", "ineligible": "rejected"}
    lab.check("green", "The persisted review treats matching-quality provenance differently according to explicit trust evidence",
              verified and recorded and reason == ["community_context", "maintenance"]
              and record["approvedDigests"] == _source("eligible")["digest"],
              {"dispositions": states, "rejection_reasons": reason, "reviewer_and_provenance_recorded": recorded})
    unprivileged = lab.kubectl("auth", "can-i", "update", "configmap/" + RESULTS,
                               "--as=system:serviceaccount:saf-test:default", allow_failure=True).stdout.strip()
    lab.check("green", "The default workload identity cannot update the trust decision record",
              unprivileged == "no", {"can_update": unprivileged})
    _admission(lab)
    deadline = time.monotonic() + 15
    while True:
        rejected = _request(lab, "ineligible")
        if rejected.returncode or time.monotonic() >= deadline:
            break
        time.sleep(0.3)
    denied = POLICY in rejected.stderr and "model digest lacks approved trust disposition" in rejected.stderr
    lab.check("green", "The same unapproved candidate is denied by Kubernetes admission",
              denied and rejected.returncode != 0, {"expected_policy_denied": denied})
    accepted = _request(lab, "eligible")
    lab.check("positive", "The approved candidate remains eligible under the same policy",
              accepted.returncode == 0, {"admitted": accepted.returncode == 0})
    (lab.evidence / "model-trust-decisions.json").write_text(json.dumps(
        {"input": _dossier(), "decisions": decisions, "checks": lab.checks}, indent=2) + "\n")
