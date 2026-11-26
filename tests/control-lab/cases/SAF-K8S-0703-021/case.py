"""Verify positive admission and quota policy with an owned synthetic resource."""

import json
import time

SCOPE = ("Scoped Pod CREATE admission, synthetic accelerator quota and scheduling, and actual "
         "ServiceAccount-authenticated Job-template dry-runs. Device assignment and deployed "
         "controller-generated Pod authorization require separate evidence.")
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
JOB_POLICY = "saf-fixture-accelerator-job"
JOB_RULE = "fixture Job requires the approved submitting service account and explicit synthetic resource declaration"
PROBE_CONFIG = "accelerator-job-probe"
PROBE_SCRIPT = """import json, os, ssl, urllib.error, urllib.request
base = "https://" + os.environ["KUBERNETES_SERVICE_HOST"] + ":" + os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
root = "/var/run/secrets/kubernetes.io/serviceaccount/"
token = open(root + "token", encoding="utf-8").read().strip()
context = ssl.create_default_context(cafile=root + "ca.crt")
def post(path, obj):
    req = urllib.request.Request(base + path, data=json.dumps(obj).encode(), headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, context=context, timeout=8) as res:
            return res.status, res.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()
review_status, review_raw = post("/apis/authentication.k8s.io/v1/selfsubjectreviews", {"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"})
review = json.loads(review_raw) if review_raw else {}
expected = "system:serviceaccount:saf-test:" + os.environ["EXPECTED_SA"]
identity_ok = review_status == 201 and review.get("status", {}).get("userInfo", {}).get("username") == expected
slot = "saf.example/accelerator-slot"
resources = {"requests": {slot:"1", "cpu":"5m", "memory":"4Mi"}, "limits": {slot:"1", "cpu":"100m", "memory":"24Mi"}}
case = os.environ.get("CASE", "")
if case == "missing":
    del resources["requests"][slot]
    del resources["limits"][slot]
job = {"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"dryrun-" + case,"namespace":"saf-test"},"spec":{"template":{"metadata":{"labels":{"app":"saf-accelerator-dryrun"}},"spec":{"restartPolicy":"Never","automountServiceAccountToken":False,"securityContext":{"runAsNonRoot":True,"runAsUser":65534,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"inert","image":os.environ["FIXTURE_IMAGE"],"command":["/bin/sleep","30"],"resources":resources,"securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}}}]}}}}
status, raw = post("/apis/batch/v1/namespaces/saf-test/jobs?dryRun=All", job)
body = raw.decode("utf-8", "replace")
message_matches = "saf-fixture-accelerator-job" in body and "approved submitting service account" in body
print(json.dumps({"identity_match":identity_ok,"http":status,"policy_message_matches":message_matches,"policy_denied":status == 403 and message_matches}, sort_keys=True))
"""
SLOT = "saf.example/accelerator-slot"
QUOTA_KEY = "requests." + SLOT
POLICY = "saf-fixture-accelerator"
RULE = "fixture accelerator requires the authorized principal and approved resource declaration"
PREFIX = "system:serviceaccount:saf-test:"
APPROVED = "accelerator-submitter"
OTHER = "ordinary-submitter"


def pod(name):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "fixture", "image": IMAGE, "command": ["/bin/sleep", "180"],
                        "resources": {"requests": {SLOT: "1", "cpu": "5m", "memory": "4Mi"},
                                      "limits": {SLOT: "1", "cpu": "100m", "memory": "24Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}}}]}}


def submit(lab, payload, user, *, dry=True):
    flags = ("--dry-run=server",) if dry else ()
    return lab.kubectl("--as", PREFIX + user, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(payload), allow_failure=True)


def wait(lab, predicate, diagnostic, *, seconds=50):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(1)
    lab.block(diagnostic)


def get(lab, kind, name):
    return json.loads(lab.kubectl("get", kind, name, "-o", "json").stdout)


def add_roles(lab):
    for user in (APPROVED, OTHER):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": user},
                    "automountServiceAccountToken": False})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "fixture-submit"},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
                          {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "fixture-submit"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "fixture-submit"},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": user}
                             for user in (APPROVED, OTHER)]})


def apply_policy(lab):
    expression = (f"request.userInfo.username == '{PREFIX}{APPROVED}' && "
                  "object.spec.containers.exists(c, has(c.resources) && has(c.resources.requests) && "
                  f"has(c.resources.limits) && '{SLOT}' in c.resources.requests && '{SLOT}' in c.resources.limits)")
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": POLICY}, "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [
                    {"operations": ["CREATE"], "apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"],
                     "scope": "Namespaced"}]}, "validations": [{"expression": expression, "message": RULE}]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": POLICY}, "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                    "matchResources": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "saf-test"}}}}})


def apply_job_policy(lab):
    expression = (f"request.userInfo.username == '{PREFIX}{APPROVED}' && "
                  "object.spec.template.spec.containers.exists(c, has(c.resources) && has(c.resources.requests) && "
                  f"has(c.resources.limits) && '{SLOT}' in c.resources.requests && '{SLOT}' in c.resources.limits)")
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": JOB_POLICY}, "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [
                    {"operations": ["CREATE"], "apiGroups": ["batch"], "apiVersions": ["v1"], "resources": ["jobs"],
                     "scope": "Namespaced"}]}, "validations": [{"expression": expression, "message": JOB_RULE, "reason": "Forbidden"}]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": JOB_POLICY}, "spec": {"policyName": JOB_POLICY, "validationActions": ["Deny"],
                    "matchResources": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "saf-test"}}}}})


def prepare_job_probes(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": PROBE_CONFIG},
                "data": {"probe.py": PROBE_SCRIPT}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": PROBE_CONFIG},
                "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["selfsubjectreviews"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": PROBE_CONFIG},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": PROBE_CONFIG},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": name} for name in (APPROVED, OTHER)]})
    for case, account in (("approved", APPROVED), ("ordinary", OTHER)):
        lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "job-probe-" + case},
                    "spec": {"serviceAccountName": account, "automountServiceAccountToken": True, "restartPolicy": "Never",
                             "terminationGracePeriodSeconds": 1,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                 "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "probe", "image": PYTHON, "command": ["python3", "-c", "import time; time.sleep(300)"],
                                             "env": [{"name": "EXPECTED_SA", "value": account}, {"name": "FIXTURE_IMAGE", "value": IMAGE}],
                                             "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                                 "capabilities": {"drop": ["ALL"]}},
                                             "volumeMounts": [{"name": "probe", "mountPath": "/probe", "readOnly": True}]}],
                             "volumes": [{"name": "probe", "configMap": {"name": PROBE_CONFIG, "defaultMode": 292}}]}})
        lab.kubectl("wait", "--for=condition=Ready", "pod/job-probe-" + case, "--timeout=70s", timeout=80)


def job_dryrun(lab, pod_case, request_case):
    result = lab.kubectl("exec", "pod/job-probe-" + pod_case, "--", "env", "CASE=" + request_case,
                         "python3", "/probe/probe.py", timeout=20)
    return json.loads(result.stdout.strip().splitlines()[-1])


def cleanup_job_fixture(lab):
    for resource in ("validatingadmissionpolicybinding/" + JOB_POLICY,
                     "validatingadmissionpolicy/" + JOB_POLICY,
                     "pod/job-probe-approved", "pod/job-probe-ordinary", "configmap/" + PROBE_CONFIG):
        lab.kubectl("delete", resource, "--ignore-not-found=true", allow_failure=True)
    lab.kubectl("delete", "clusterrolebinding/" + PROBE_CONFIG, "--ignore-not-found=true", allow_failure=True)
    lab.kubectl("delete", "clusterrole/" + PROBE_CONFIG, "--ignore-not-found=true", allow_failure=True)


def declined(result):
    return result.returncode != 0 and POLICY in result.stderr and RULE in result.stderr


def run(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1 or not nodes[0]["metadata"]["name"].startswith(lab.cluster + "-"):
        lab.block("The fixture requires exactly one owned Kind node")
    node = nodes[0]["metadata"]["name"]
    patch = json.dumps([{"op": "add", "path": "/status/capacity/" + SLOT.replace("/", "~1"), "value": "2"}])
    lab.kubectl("patch", "node", node, "--subresource=status", "--type=json", "-p", patch)
    wait(lab, lambda: get(lab, "node", node)["status"]["allocatable"].get(SLOT) == "2",
         "Synthetic node capacity did not become allocatable", seconds=70)
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    add_roles(lab)
    lab.create({"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": "fixture-accelerators"},
                "spec": {"hard": {QUOTA_KEY: "1"}}})
    quota_used = lambda: get(lab, "resourcequota", "fixture-accelerators").get("status", {}).get("used", {}).get(QUOTA_KEY)
    wait(lab, lambda: quota_used() == "0", "ResourceQuota did not start accounting")
    prepare_job_probes(lab)
    ordinary = pod("ordinary-identity")
    before = submit(lab, ordinary, OTHER)
    lab.check("red", "Namespace Pod creation and quota alone accept a valid fixture request in a dry run",
              before.returncode == 0, {"comparison_request_admitted": before.returncode == 0})
    apply_policy(lab)
    wait(lab, lambda: declined(submit(lab, ordinary, OTHER)), "Fixture admission policy did not converge")
    missing = pod("missing-declaration")
    for kind in ("requests", "limits"):
        del missing["spec"]["containers"][0]["resources"][kind][SLOT]
    incomplete = declined(submit(lab, missing, APPROVED))
    lab.check("green", "Admission requires the approved principal and an explicit synthetic resource declaration",
              incomplete and quota_used() == "0", {"other_principal_denied": True, "missing_declaration_denied": incomplete})
    accepted = submit(lab, pod("approved-one"), APPROVED, dry=False)
    if accepted.returncode != 0:
        lab.block("The approved request did not create its fixture Pod; inspect the command log")
    lab.kubectl("wait", "--for=condition=Ready", "pod/approved-one", "--timeout=70s", timeout=80)
    wait(lab, lambda: quota_used() == "1", "ResourceQuota did not account for the admitted fixture")
    charged = get(lab, "pod", "approved-one")
    resources = charged["spec"]["containers"][0]["resources"]
    scheduled = (charged["spec"]["nodeName"] == node and resources["requests"][SLOT] == resources["limits"][SLOT] == "1")
    lab.check("positive", "The approved Pod reaches Ready on the synthetic node and consumes one quota unit",
              scheduled, {"right_resource_scheduled": scheduled, "namespace_quota_used": 1})
    over = submit(lab, pod("over-quota"), APPROVED)
    denied_quota = over.returncode != 0 and "exceeded quota" in over.stderr and QUOTA_KEY in over.stderr
    lab.check("green", "Namespace quota denies a second valid request while the node still advertises two slots",
              denied_quota and quota_used() == "1", {"quota_denial_verified": denied_quota, "node_slots": 2})
    (lab.evidence / "resource-admission-observations.json").write_text(json.dumps({
        "approved_synthetic_resource": SLOT, "principal_check": True, "quota_verified": denied_quota,
        "admitted_and_scheduled": scheduled, "capacity": 2, "quota": 1,
    }, indent=2) + "\n")

    # Three live ServiceAccount-authenticated Job-template server dry-runs. No Job persists.
    apply_job_policy(lab)
    wait(lab, lambda: job_dryrun(lab, "ordinary", "ordinary").get("policy_denied") is True,
         "Job-template admission did not converge", seconds=20)
    approved_job = job_dryrun(lab, "approved", "approved")
    lab.check("positive", "The approved submitting ServiceAccount can server-dry-run a resource-declared Job template",
              approved_job.get("identity_match") and approved_job.get("http") == 201 and not approved_job.get("policy_denied"),
              {"authenticated_identity_matches": bool(approved_job.get("identity_match")), "dry_run_http": approved_job.get("http")})
    ordinary_job = job_dryrun(lab, "ordinary", "ordinary")
    lab.check("green", "An ordinary submitting ServiceAccount is denied by the Job-template admission policy",
              ordinary_job.get("identity_match") and ordinary_job.get("http") == 403 and ordinary_job.get("policy_denied"),
              {"authenticated_identity_matches": bool(ordinary_job.get("identity_match")), "policy_denial": bool(ordinary_job.get("policy_denied"))})
    missing_job = job_dryrun(lab, "approved", "missing")
    stored_jobs = [lab.kubectl("get", "job", "dryrun-" + name, "-o", "name", allow_failure=True)
                   for name in ("approved", "ordinary", "missing")]
    absent_jobs = all(result.returncode != 0 and "NotFound" in result.stderr for result in stored_jobs)
    lab.check("green", "An approved submitter cannot omit the synthetic resource from a Job template",
              missing_job.get("identity_match") and missing_job.get("http") == 403 and missing_job.get("policy_denied") and absent_jobs,
              {"authenticated_identity_matches": bool(missing_job.get("identity_match")), "policy_denial": bool(missing_job.get("policy_denied")),
               "dry_run_jobs_absent": absent_jobs})
    cleanup_job_fixture(lab)
