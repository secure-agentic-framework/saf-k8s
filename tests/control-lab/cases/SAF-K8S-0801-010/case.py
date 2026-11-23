"""Exercise accelerator request admission, quota, and scheduler behavior with a synthetic resource."""

import json
import time

SCOPE = "Live Kubernetes Pod admission and namespace quota for a synthetic extended accelerator resource."
RESOURCE = "fixture.example/accelerator-slice"
UNAPPROVED = "fixture.example/accelerator-unapproved"
QUOTA_KEY = f"requests.{RESOURCE}"
QUOTA = "fixture-accelerator-budget"
POLICY = "fixture-accelerator-authorization"
ALLOWED = "fixture-accelerator-approved"
ORDINARY = "fixture-accelerator-ordinary"
IDENTITY_REASON = "Fixture accelerator request requires approved identity"
PROFILE_REASON = "Fixture accelerator request has an unsupported profile"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def pod(name, resource=None, *, init=False):
    limits = {"cpu": "100m", "memory": "40Mi"}
    if resource:
        limits[resource] = "1"
    container = {"name": "fixture", "image": IMAGE,
                 "command": ["python", "-c", "import time; time.sleep(160)"],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                 "resources": {"limits": limits, "requests": {"cpu": "5m", "memory": "12Mi"}}}
    spec = {"restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container]}
    if init:
        spec["containers"] = [dict(container, resources={"requests": {"cpu": "5m", "memory": "12Mi"}})]
        spec["initContainers"] = [dict(container, name="fixture-init", command=["python", "-c", "pass"])]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}


def request(lab, user, manifest, *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("--as", user, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(manifest), allow_failure=True)


def allow_fixture_submitters(lab):
    rbac = "rbac.authorization.k8s.io"
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "Role", "metadata": {"name": POLICY},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]})
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "RoleBinding", "metadata": {"name": POLICY},
                "roleRef": {"apiGroup": rbac, "kind": "Role", "name": POLICY},
                "subjects": [{"apiGroup": rbac, "kind": "User", "name": user} for user in (ALLOWED, ORDINARY)]})


def install_policy(lab):
    api = "admissionregistration.k8s.io/v1"
    eligible = 'has(c.resources) && has(c.resources.limits)'
    prefix = "key.startsWith('fixture.example/accelerator-')"
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "variables": [{"name": "containers",
                                        "expression": "object.spec.containers + (has(object.spec.initContainers) ? object.spec.initContainers : [])"}],
                         "validations": [
                             {"expression": f"request.userInfo.username == '{ALLOWED}' || !variables.containers.exists(c, {eligible} && c.resources.limits.exists(key, {prefix}))",
                              "message": IDENTITY_REASON},
                             {"expression": f"variables.containers.all(c, !({eligible}) || c.resources.limits.all(key, !({prefix}) || key == '{RESOURCE}'))",
                              "message": PROFILE_REASON},
                         ]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"fixture.example/accelerator-policy": "true"}}}}})


def advertise_and_quota(lab):
    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    path = RESOURCE.replace("/", "~1")
    lab.kubectl("patch", "node", node["metadata"]["name"], "--subresource=status", "--type=json", "-p",
                json.dumps([{"op": "add", "path": f"/status/capacity/{path}", "value": "2"}]))
    lab.create({"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": QUOTA},
                "spec": {"hard": {QUOTA_KEY: "1"}}})
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        quota = json.loads(lab.kubectl("get", "resourcequota", QUOTA, "-o", "json").stdout)
        if quota.get("status", {}).get("hard", {}).get(QUOTA_KEY) == "1":
            return
        time.sleep(0.5)
    lab.block("The fixture quota controller did not initialize the requested limit")


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "fixture.example/accelerator-policy=true")
    allow_fixture_submitters(lab)
    ordinary_accelerator = pod("ordinary-accelerator", RESOURCE)
    before = request(lab, ORDINARY, ordinary_accelerator)
    admitted_before = before.returncode == 0
    lab.check("red", "The ordinary user can submit the synthetic request before admission enforcement",
              admitted_before, {"ordinary_request_admitted_before_policy": admitted_before})
    install_policy(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        denied = request(lab, ORDINARY, ordinary_accelerator)
        if denied.returncode and IDENTITY_REASON in denied.stderr:
            break
        time.sleep(0.45)
    else:
        lab.block("The admission policy did not produce the reviewed identity denial")
    denied_init = request(lab, ORDINARY, pod("ordinary-init", RESOURCE, init=True))
    denied_profile = request(lab, ALLOWED, pod("unapproved-profile", UNAPPROVED))
    rejected_init = denied_init.returncode != 0 and IDENTITY_REASON in denied_init.stderr
    rejected_profile = denied_profile.returncode != 0 and PROFILE_REASON in denied_profile.stderr
    lab.check("green", "Admission rejects the unauthorized application and init-container requests and an unapproved profile",
              rejected_init and rejected_profile, {"ordinary_request_rejected": True, "init_request_rejected": rejected_init,
                                                   "unapproved_profile_rejected": rejected_profile})
    advertise_and_quota(lab)
    approved = request(lab, ALLOWED, pod("approved-accelerator", RESOURCE), dry_run=False)
    if approved.returncode:
        lab.block("The approved fixture workload could not be admitted")
    lab.kubectl("wait", "--for=condition=Ready", "pod/approved-accelerator", "--timeout=70s", timeout=80)
    overflow = request(lab, ALLOWED, pod("over-budget-accelerator", RESOURCE))
    quota_rejected = overflow.returncode != 0 and "exceeded quota" in overflow.stderr and QUOTA in overflow.stderr
    ordinary_ok = request(lab, ORDINARY, pod("ordinary-cpu")).returncode == 0
    live = json.loads(lab.kubectl("get", "pod", "approved-accelerator", "-o", "json").stdout)
    on_node = bool(live["spec"].get("nodeName")) and live["spec"]["containers"][0]["resources"]["requests"].get(RESOURCE) == "1"
    lab.check("positive", "The allowed synthetic workload runs, the namespace quota rejects a second unit, and ordinary CPU admission works",
              on_node and quota_rejected and ordinary_ok,
              {"allowed_workload_scheduled": on_node, "extra_unit_denied_by_quota": quota_rejected, "ordinary_cpu_admitted": ordinary_ok})
    (lab.evidence / "accelerator-admission-observations.json").write_text(json.dumps(
        {"synthetic_resource": RESOURCE, "advertised_units": 2, "namespace_quota_units": 1,
         "allowed_workload_scheduled": on_node, "extra_unit_denied_by_quota": quota_rejected,
         "ordinary_cpu_admitted": ordinary_ok, "unapproved_profile_rejected": rejected_profile,
         "init_request_rejected": rejected_init}, indent=2) + "\n")
