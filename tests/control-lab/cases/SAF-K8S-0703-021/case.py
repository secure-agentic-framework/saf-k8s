"""Verify positive admission and quota policy with an owned synthetic resource."""

import json
import re
import time

SCOPE = ("Scoped Pod CREATE admission, synthetic accelerator quota and scheduling, actual "
         "ServiceAccount-authenticated Job-template dry-runs, and one actual benign Job-controller "
         "Pod admitted only for an immutable exact Job owner UID. Physical device assignment, "
         "isolation and deployed controller authorization remain separate evidence.")
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

# Supplemental actual Job-controller Pod lifecycle, after the original seven checks.
CONTROLLER_JOB = "approved-controller-created-pod"
CONTROLLER_PARAMS = "fixture-accelerator-controller-job"
CONTROLLER_POLICY = "saf-fixture-accelerator-controller-pod"
CONTROLLER_ACTOR = "system:serviceaccount:kube-system:job-controller"


def allow_exact_controller_pod(lab, approved_job_uid):
    """Replace the Pod gate with the same declaration check plus one UID-bound controller path."""
    params = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": CONTROLLER_PARAMS, "labels": {"saf.example/fixture": "0703-021"}},
              "immutable": True, "data": {"approved-job-uid": approved_job_uid}}
    lab.create(params)
    expression = (
        f"(request.userInfo.username == '{PREFIX}{APPROVED}' || "
        f"(request.userInfo.username == '{CONTROLLER_ACTOR}' && "
        "has(object.metadata.ownerReferences) && object.metadata.ownerReferences.exists(r, "
        f"r.kind == 'Job' && r.uid == params.data['approved-job-uid'] && r.controller == true))) && "
        "object.spec.containers.exists(c, has(c.resources) && has(c.resources.requests) && "
        "has(c.resources.limits) && "
        f"'{SLOT}' in c.resources.requests && '{SLOT}' in c.resources.limits)"
    )
    policy_spec = {
        "failurePolicy": "Fail",
        "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
        "matchConstraints": {"resourceRules": [{
            "operations": ["CREATE"], "apiGroups": [""], "apiVersions": ["v1"],
            "resources": ["pods"], "scope": "Namespaced"}]},
        "validations": [{"expression": expression,
                         "message": "fixture Pod requires the approved principal or the exact approved Job controller owner and accelerator declaration"}],
    }
    binding_spec = {"policyName": CONTROLLER_POLICY, "validationActions": ["Deny"],
                    "paramRef": {"name": CONTROLLER_PARAMS, "namespace": "saf-test",
                                 "parameterNotFoundAction": "Deny"},
                    "matchResources": {"namespaceSelector": {"matchLabels": {
                        "kubernetes.io/metadata.name": "saf-test"}}}}
    # Install the replacement alongside the existing gate, then retire the older
    # direct-Pod-only rule so there is no interval without Pod admission control.
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": CONTROLLER_POLICY}, "spec": policy_spec})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": CONTROLLER_POLICY}, "spec": binding_spec})

    # Kubernetes reports completion of VAP type checking by populating
    # status.typeChecking and advancing observedGeneration. An empty
    # expressionWarnings list is not a policy-readiness condition: type-check
    # diagnostics do not alter evaluation, while evaluation errors are handled
    # by this policy's failurePolicy=Fail. The existing bounded live admission
    # comparison below remains the behavioral oracle.
    def replacement_ready():
        policy = get(lab, "validatingadmissionpolicy", CONTROLLER_POLICY)
        metadata = policy.get("metadata", {})
        status = policy.get("status", {})
        checking = status.get("typeChecking")
        generation = metadata.get("generation")
        observed = status.get("observedGeneration")
        if not (isinstance(generation, int) and isinstance(observed, int)
                and observed >= generation and isinstance(checking, dict)):
            return False
        binding = get(lab, "validatingadmissionpolicybinding", CONTROLLER_POLICY)
        actual = binding.get("spec", {})
        return (
            actual.get("policyName") == CONTROLLER_POLICY
            and actual.get("validationActions") == ["Deny"]
            and actual.get("paramRef") == binding_spec["paramRef"]
            and actual.get("matchResources", {}).get("namespaceSelector")
                == binding_spec["matchResources"]["namespaceSelector"]
            and actual.get("matchResources", {}).get("objectSelector", {}) == {}
            and not actual.get("matchResources", {}).get("excludeResourceRules")
            and not actual.get("matchResources", {}).get("resourceRules")
        )

    wait(lab, replacement_ready,
         "The replacement VAP was not type-checked and bound with the exact fail-closed scope",
         seconds=25)
    parameter = get(lab, "configmap", CONTROLLER_PARAMS)
    parameter_ok = (parameter.get("immutable") is True
                    and parameter.get("data", {}).get("approved-job-uid") == approved_job_uid)
    if not parameter_ok:
        lab.block("The replacement VAP parameter did not retain the exact immutable Job UID")

    # The new binding is now present with exact Deny action, namespace selector,
    # and required immutable parameter. Retire the previous binding first and
    # its policy second, so at least one Pod admission binding is always active.
    lab.kubectl("delete", "validatingadmissionpolicybinding", POLICY, "--wait=true")
    lab.kubectl("delete", "validatingadmissionpolicy", POLICY, "--wait=true")


def run_controller_job(lab):
    managers = json.loads(lab.kubectl("-n", "kube-system", "get", "pods", "-l",
                                     "component=kube-controller-manager", "-o", "json").stdout)["items"]
    command = managers[0]["spec"]["containers"][0].get("command", []) if len(managers) == 1 else []
    account = json.loads(lab.kubectl("-n", "kube-system", "get", "serviceaccount", "job-controller",
                                    "-o", "json").stdout)
    if "--use-service-account-credentials=true" not in command or account.get("metadata", {}).get("name") != "job-controller":
        lab.block("The owned Kind control plane did not expose a distinct Job controller ServiceAccount")
    # Free the one-unit quota consumed by the original direct-Pod positive check.
    lab.kubectl("delete", "pod", "approved-one", "--wait=true", "--timeout=50s")
    wait(lab, lambda: get(lab, "resourcequota", "fixture-accelerators")
         .get("status", {}).get("used", {}).get(QUOTA_KEY, "0") == "0",
         "The original fixture Pod did not release its quota unit", seconds=35)
    apply_job_policy(lab)

    job = {"apiVersion": "batch/v1", "kind": "Job",
           "metadata": {"name": CONTROLLER_JOB, "namespace": "saf-test"},
           "spec": {"suspend": True, "backoffLimit": 0, "activeDeadlineSeconds": 60,
                    "template": {"metadata": {"labels": {"app": CONTROLLER_JOB}},
                                 "spec": {"serviceAccountName": APPROVED,
                                          "automountServiceAccountToken": False,
                                          "restartPolicy": "Never",
                                          "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                              "seccompProfile": {"type": "RuntimeDefault"}},
                                          "containers": [{"name": "inert", "image": IMAGE,
                                                          "imagePullPolicy": "IfNotPresent",
                                                          "command": ["/bin/sleep", "12"],
                                                          "resources": {"requests": {SLOT: "1", "cpu": "5m", "memory": "4Mi"},
                                                                        "limits": {SLOT: "1", "cpu": "100m", "memory": "24Mi"}},
                                                          "securityContext": {"allowPrivilegeEscalation": False,
                                                                              "readOnlyRootFilesystem": True,
                                                                              "capabilities": {"drop": ["ALL"]}}}]}}}}
    created = submit(lab, job, APPROVED, dry=False)
    if created.returncode != 0:
        lab.block("The approved fixture Job was not admitted: " + created.stderr.strip())
    stored_job = get(lab, "job", CONTROLLER_JOB)
    job_uid = stored_job["metadata"]["uid"]
    allow_exact_controller_pod(lab, job_uid)
    unsuspended = lab.kubectl("patch", "job", CONTROLLER_JOB, "--type=merge",
                              "-p", '{"spec":{"suspend":false}}', allow_failure=True)
    if unsuspended.returncode != 0:
        lab.block("The exact approved Job could not be unsuspended: " + unsuspended.stderr.strip())

    def owned_pods():
        result = lab.kubectl("get", "pods", "-l", f"job-name={CONTROLLER_JOB}", "-o", "json")
        return json.loads(result.stdout).get("items", [])

    wait(lab, lambda: len(owned_pods()) == 1 and
         owned_pods()[0].get("status", {}).get("phase") == "Running",
         "The approved Job controller did not create a running Pod under native admission", seconds=45)
    running_pod = owned_pods()[0]
    refs = running_pod.get("metadata", {}).get("ownerReferences", [])
    controller_owner_ok = any(ref.get("apiVersion") == "batch/v1" and ref.get("kind") == "Job"
                              and ref.get("uid") == job_uid and ref.get("controller") is True
                              for ref in refs)
    container_statuses = running_pod.get("status", {}).get("containerStatuses", [])
    runtime = container_statuses[0] if len(container_statuses) == 1 else {}
    runtime_ok = (runtime.get("ready") is True and
                  runtime.get("state", {}).get("running") is not None and
                  bool(re.search(r"sha256:[0-9a-f]{64}$", runtime.get("imageID", ""))) and
                  running_pod.get("spec", {}).get("containers", [{}])[0].get("image") == IMAGE)
    assigned = (running_pod.get("spec", {}).get("nodeName", "").startswith(lab.cluster + "-")
                and running_pod["spec"]["containers"][0]["resources"]["requests"].get(SLOT) == "1"
                and running_pod["spec"]["containers"][0]["resources"]["limits"].get(SLOT) == "1")
    wait(lab, lambda: get(lab, "resourcequota", "fixture-accelerators")
         .get("status", {}).get("used", {}).get(QUOTA_KEY) == "1",
         "The controller-created Pod did not consume its expected quota unit", seconds=20)
    quota_during = get(lab, "resourcequota", "fixture-accelerators").get("status", {}).get("used", {}).get(QUOTA_KEY)
    lab.kubectl("wait", "--for=condition=Complete", f"job/{CONTROLLER_JOB}",
                "--timeout=45s", timeout=50)
    completed_job = get(lab, "job", CONTROLLER_JOB)
    final_pod = owned_pods()[0]
    final_status = final_pod.get("status", {}).get("containerStatuses", [{}])[0]
    completed = (completed_job.get("status", {}).get("succeeded") == 1 and
                 final_pod.get("status", {}).get("phase") == "Succeeded" and
                 final_status.get("state", {}).get("terminated", {}).get("exitCode") == 0)
    checks = {
        "created_by_approved_submitter": created.returncode == 0,
        "pod_has_exact_controller_job_owner_uid": controller_owner_ok,
        "pod_satisfies_exact_synthetic_resource_request_and_owned_node": assigned,
        "namespace_quota_accounts_controller_pod_while_running": quota_during == "1",
        "running_pod_has_expected_digest_pinned_runtime": runtime_ok,
        "benign_controller_job_completes_successfully": completed,
    }
    lab.check("positive", "The approved controller creates an owner-bound accelerator Pod admitted by the exact scoped policy",
              all(checks.values()), {"checks": checks,
                  "requested_image": IMAGE, "runtime_image_id": runtime.get("imageID"),
                  "quota_used_while_running": quota_during,
                  "policy_name": CONTROLLER_POLICY, "controller_actor": CONTROLLER_ACTOR})
    (lab.evidence / "controller-created-accelerator-pod.json").write_text(json.dumps({
        "control": "SAF-K8S-0703-021",
        "scope": "one approved synthetic Job and its actual controller-created Pod in the owned namespace",
        "job": {"name": CONTROLLER_JOB, "uid": job_uid,
                "creator": PREFIX + APPROVED,
                "succeeded": completed_job.get("status", {}).get("succeeded")},
        "pod": {"name": final_pod["metadata"]["name"], "uid": final_pod["metadata"]["uid"],
                "owner_references": refs, "node": running_pod.get("spec", {}).get("nodeName"),
                "phase_running_observed": True, "phase_final": final_pod.get("status", {}).get("phase"),
                "runtime_image_id": runtime.get("imageID"),
                "synthetic_request": running_pod["spec"]["containers"][0]["resources"]},
        "policy": {"name": CONTROLLER_POLICY, "approved_job_uid_parameter": job_uid,
                   "controller_actor": CONTROLLER_ACTOR},
        "quota_used_while_running": quota_during,
        "checks": checks,
    }, sort_keys=True, indent=2) + "\n")
    lab.kubectl("delete", "job", CONTROLLER_JOB, "--wait=true", "--timeout=45s")
    wait(lab, lambda: get(lab, "resourcequota", "fixture-accelerators")
         .get("status", {}).get("used", {}).get(QUOTA_KEY, "0") == "0",
         "The controller-created Pod did not release its quota unit", seconds=35)
    lab.kubectl("delete", "validatingadmissionpolicybinding", CONTROLLER_POLICY,
                "--ignore-not-found=true", allow_failure=True)
    lab.kubectl("delete", "validatingadmissionpolicy", CONTROLLER_POLICY,
                "--ignore-not-found=true", allow_failure=True)
    lab.kubectl("delete", "configmap", CONTROLLER_PARAMS, "--ignore-not-found=true", allow_failure=True)
    lab.kubectl("delete", "validatingadmissionpolicybinding", JOB_POLICY,
                "--ignore-not-found=true", allow_failure=True)
    lab.kubectl("delete", "validatingadmissionpolicy", JOB_POLICY,
                "--ignore-not-found=true", allow_failure=True)


_published_run = run


def run(lab):
    _published_run(lab)
    run_controller_job(lab)
