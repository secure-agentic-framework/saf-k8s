"""Verify two actual job identities are limited to their own approved Kubernetes resources."""

import json
import time

from fixtures import container

NS = "saf-test"
LABEL = "saf.example.org/scoped-job-identity"
POLICY = "fixture-job-identity.saf.example.org"
MESSAGE = "fixture job name must use its approved service account and explicit token projection"
JOBS = ("fixture-train", "fixture-evaluate")
RESOURCES = dict(zip(JOBS, ("fixture-training-data", "fixture-evaluation-data")))
MARKERS = dict(zip(RESOURCES.values(), ("public-training-marker", "public-evaluation-marker")))
APISERVER = "https://kubernetes.default.svc"
IMAGE = ("docker.io/curlimages/curl:8.17.0@sha256:"
         "935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40")
SCOPE = (
    "Assess per-job Kubernetes identity and actual resource-by-resource access with two owned "
    "Kubernetes Jobs and public ConfigMaps. Cloud paths, separate data-service permissions, "
    "orchestrator privileges, and production identity lifecycle are distinct evidence."
)


def job(name, account):
    unit = container("job", image=IMAGE, command=["sh", "-c", "sleep 420"],
                     volumeMounts=[{"name": "identity", "mountPath": "/identity", "readOnly": True}])
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
            "spec": {"backoffLimit": 0, "template": {"spec": {
                "automountServiceAccountToken": False, "restartPolicy": "Never", "serviceAccountName": account,
                "containers": [unit], "volumes": [{"name": "identity", "projected": {"sources": [
                    {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                    {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                ]}}],
            }}}}


def grant(lab, name, subjects, resources):
    api = "rbac.authorization.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "Role", "metadata": {"name": name},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": resources, "verbs": ["get"]}]})
    lab.create({"apiVersion": api, "kind": "RoleBinding", "metadata": {"name": name},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
                "subjects": [{"kind": "ServiceAccount", "name": subject, "namespace": NS} for subject in subjects]})


def policy(lab):
    api = "admissionregistration.k8s.io/v1"
    rule = " || ".join(
        f"(object.metadata.name == '{name}' && object.spec.template.spec.serviceAccountName == '{name}')"
        for name in JOBS)
    constraints = [
        "(" + rule + ")",
        "has(object.spec.template.spec.automountServiceAccountToken) && !object.spec.template.spec.automountServiceAccountToken",
        "has(object.spec.template.spec.volumes) && object.spec.template.spec.volumes.exists(v, "
        "has(v.projected) && v.projected.sources.exists(s, has(s.serviceAccountToken) && "
        "has(s.serviceAccountToken.expirationSeconds) && s.serviceAccountToken.expirationSeconds <= 600))",
    ]
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": ["batch"], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["jobs"]}]},
                    "validations": [{"expression": expression, "message": MESSAGE} for expression in constraints]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {LABEL: "true"}}}}})


def fixture_names(lab):
    result = json.loads(lab.kubectl("get", "pods", "-o", "json").stdout)
    return {item["metadata"]["labels"]["batch.kubernetes.io/job-name"]: item["metadata"]["name"]
            for item in result["items"] if item["metadata"].get("labels", {}).get("batch.kubernetes.io/job-name") in JOBS}


def access(lab, name, target, action="get"):
    script = r'''set -eu
umask 077
cfg=$(mktemp)
body=$(mktemp)
trap 'rm -f "$cfg" "$body"' EXIT
printf 'header = "Authorization: Bearer %s"\n' "$(cat /identity/token)" > "$cfg"
if [ "$3" = patch ]; then
    set -- "$1" "$2" "$3" --request PATCH --header 'Content-Type: application/merge-patch+json' --data '{"data":{"probe":"inert"}}'
fi
url=$1
marker=$2
shift 3
status=$(curl --silent --show-error --max-time 6 --cacert /identity/ca.crt --config "$cfg" \
              --output "$body" --write-out '%{http_code}' "$@" "$url")
if test "$status" = 200 && grep -Fq "$marker" "$body"; then printf '200 expected-marker'; else printf '%s' "$status"; fi
'''
    url = APISERVER + f"/api/v1/namespaces/{NS}/configmaps"
    if action != "list":
        url += "/" + target
    if action == "patch":
        url += "?dryRun=All"
    result = lab.kubectl("exec", name, "--", "sh", "-c", script, "fixture-job",
                         url, MARKERS.get(target, "fixture-marker"), action, allow_failure=True)
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def matrix(lab, names):
    return {name: {target: access(lab, names[name], target) for target in MARKERS} for name in names}


def run(lab):
    lab.kubectl("label", "namespace", NS, f"{LABEL}=true")
    for name in JOBS:
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name},
                    "automountServiceAccountToken": False})
    for name, marker in MARKERS.items():
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {"marker": marker}})
    mismatched = job(JOBS[0], JOBS[1])
    initial_mismatch = lab.create(mismatched, dry_run=True, allow_failure=True).returncode == 0
    grant(lab, "fixture-shared-read", list(JOBS), list(MARKERS))
    for name in JOBS:
        lab.create(job(name, name))
    deadline = time.monotonic() + 24
    names = {}
    while time.monotonic() < deadline:
        names = fixture_names(lab)
        if set(names) == set(JOBS):
            break
        time.sleep(.5)
    if set(names) != set(JOBS):
        lab.block("The two disposable Jobs did not create their fixture Pods")
    for name in names.values():
        lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "--timeout=60s", timeout=72)
    baseline = matrix(lab, names)
    lab.check("red", "The unspecialized grant allows both real jobs to read both owned resources and permits an identity mismatch",
              initial_mismatch and set(names) == set(JOBS) and all(status == "200 expected-marker"
                for row in baseline.values() for status in row.values()),
              {"identity_mismatch_initially_admitted": initial_mismatch, "initial_access": baseline})

    policy(lab)
    for name, resource in RESOURCES.items():
        grant(lab, "grant-" + name, [name], [resource])
    lab.kubectl("delete", "rolebinding/fixture-shared-read")
    expected = {name: {resource: ("200 expected-marker" if resource == RESOURCES[name] else "403")
                       for resource in MARKERS} for name in JOBS}
    deadline = time.monotonic() + 35
    after = {}
    while time.monotonic() < deadline:
        after = matrix(lab, names)
        if after == expected:
            break
        time.sleep(.5)
    unrelated_actions = {name: {"list": access(lab, pod_name, "", "list"),
                                "patch": access(lab, pod_name, RESOURCES[name], "patch")}
                         for name, pod_name in names.items()}
    blocked_operations = all(status == "403" for row in unrelated_actions.values() for status in row.values())
    lab.check("green", "The same actual Jobs retain only their own resource and cannot list or patch with scoped grants",
              after == expected and blocked_operations, {"scoped_access": after, "other_actions": unrelated_actions})

    for name in JOBS:
        lab.kubectl("delete", "job/" + name, "--wait=true")
    mismatch_probe = lab.create(mismatched, dry_run=True, allow_failure=True)
    mismatch_denied = mismatch_probe.returncode != 0 and POLICY in mismatch_probe.stderr and MESSAGE in mismatch_probe.stderr
    matches = all(lab.create(job(name, name), dry_run=True, allow_failure=True).returncode == 0 for name in JOBS)
    lab.check("positive", "The live Job admission policy denies the swapped identity and accepts both approved assignments",
              mismatch_denied and matches, {"swapped_identity_denied": mismatch_denied, "approved_assignments_allowed": matches})
    (lab.evidence / "per-job-credential-observations.json").write_text(json.dumps({
        "initial_access": baseline, "scoped_access": after, "other_actions": unrelated_actions, "initial_identity_mismatch_allowed": initial_mismatch,
        "swapped_identity_denied": mismatch_denied, "approved_assignments_allowed": matches,
        "provider_permissions_tested": False,
    }, indent=2) + "\n")
