"""Check native Argo-definition authorization and a restricted marker Job."""
import hashlib
import importlib.util
import json
from pathlib import Path
import time
from types import SimpleNamespace

from fixtures import BUSYBOX_IMAGE


FIXTURES = Path(__file__).resolve().parent / "fixtures"
CRD = "workflowtemplates.argoproj.io"
CRD_SHA256 = "d7b69c80937843de3216185ed3400641a598cfdee4518b1e6fea11214b46633e"
AUTHOR = "saf-local-template-author"
READER = "saf-local-template-reviewer"
ROLE = "saf-template-editor"
ACCOUNT = "saf-pipeline-step"
SECRET = "saf-pipeline-public-marker"
JOB = "saf-restricted-pipeline-step"
ADMISSION_POLICY = "saf-workflowtemplate-literal-env"
ADMISSION_MESSAGE = "workflow template public marker must use the approved Secret reference"
LITERAL_ENV_NAME = "SAF_PUBLIC_MARKER"
SCOPE = (
    "One Kind v1.36.1 cluster uses the upstream Argo Workflows v3.7.6 minimal "
    "namespaced WorkflowTemplate CRD. Kubernetes API authorization controls create "
    "and update access. The case verifies that the persisted narrow author template "
    "holds an exact approved fixture definition and submits its corresponding native "
    "Job. The Job is tokenless, non-root and uses a read-only Secret reference to "
    "a public inert marker. A pinned namespaced Argo controller also reconciles "
    "one Workflow referencing that exact persisted template. Other orchestrator "
    "releases, deployed policy beyond one namespace-scoped CREATE check for a "
    "literal public marker environment value, Secret encryption and external "
    "stores require separate evidence."
)


def step_container():
    return {
        "name": "main", "image": BUSYBOX_IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["/bin/sh", "-ec", "test \"$(id -u)\" = 65534; test -s /run/marker/data; head -c 128 /run/marker/data >/dev/null; printf 'marker-mounted\\n'"],
        "resources": {"requests": {"cpu": "10m", "memory": "8Mi"},
                      "limits": {"cpu": "100m", "memory": "32Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                            "runAsUser": 65534, "runAsGroup": 65534},
        "volumeMounts": [{"name": "marker", "mountPath": "/run/marker", "readOnly": True}],
    }


def definition(name):
    return {
        "apiVersion": "argoproj.io/v1alpha1", "kind": "WorkflowTemplate",
        "metadata": {"name": name},
        "spec": {"entrypoint": "marker", "serviceAccountName": ACCOUNT,
                 "templates": [{"name": "marker", "container": step_container()}],
                 "volumes": [{"name": "marker", "secret": {
                     "secretName": SECRET, "items": [{"key": "marker", "path": "data"}]}}]},
    }


def access(lab, identity, verb):
    result = lab.kubectl("auth", "can-i", verb, CRD, f"--as={identity}", allow_failure=True)
    value = result.stdout.strip()
    if (result.returncode, value) not in {(0, "yes"), (1, "no")}:
        lab.block(f"Unexpected API authorization response for {identity} {verb}")
    return value == "yes"


def request(lab, identity, verb, document, *, dry_run=False):
    flags = ("--dry-run=server",) if dry_run else ()
    return lab.kubectl(verb, "-f", "-", "-o", "json", f"--as={identity}", *flags,
                       payload=json.dumps(document), allow_failure=True)


def require_object(lab, result, name):
    if result.returncode:
        lab.block(f"WorkflowTemplate {name} request returned an API error: {result.stderr}")
    return json.loads(result.stdout)


def subjects(*users):
    return [{"kind": "User", "name": user, "apiGroup": "rbac.authorization.k8s.io"}
            for user in users]


def run(lab):
    crd_path = FIXTURES / "argo-workflowtemplates.yaml"
    if hashlib.sha256(crd_path.read_bytes()).hexdigest() != CRD_SHA256:
        lab.block("Versioned Argo WorkflowTemplate CRD content changed")
    lab.apply(crd_path)
    lab.kubectl("wait", "--for=condition=Established", "crd/" + CRD,
                "--timeout=45s", timeout=55)
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": ROLE},
                "rules": [{"apiGroups": ["argoproj.io"], "resources": ["workflowtemplates"],
                           "verbs": ["get", "create", "update"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": ROLE},
                "subjects": subjects(AUTHOR, READER),
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ROLE}})
    seed = lab.create(definition("saf-seed-template"))
    seed["metadata"]["annotations"] = {"saf.example/revision": "two"}
    create_probe = definition("saf-reader-template")
    before = {}
    for verb, intent, resource in (("create", "create", create_probe), ("update", "replace", seed)):
        observation = require_object(lab, request(lab, READER, intent, resource, dry_run=True), verb)
        before[verb] = access(lab, READER, verb) and observation["metadata"]["name"] == resource["metadata"]["name"]
    lab.check("red", "The broad baseline grants the reviewer live server-side create and update",
              before == {"create": True, "update": True}, before)

    lab.kubectl("patch", "rolebinding", ROLE, "--type=merge", "-p",
                json.dumps({"subjects": subjects(AUTHOR)}))
    until = time.monotonic() + 10
    after = {}
    while time.monotonic() < until:
        after = {verb: access(lab, READER, verb) for verb in ("create", "update")}
        if after == {"create": False, "update": False}:
            break
        time.sleep(0.25)
    denies = {}
    for verb, intent, resource in (("create", "create", create_probe), ("update", "replace", seed)):
        result = request(lab, READER, intent, resource, dry_run=True)
        denies[verb] = result.returncode != 0 and "forbidden" in result.stderr.lower() and "workflowtemplates" in result.stderr
    lab.check("green", "Narrowing the binding gives the same reviewer exact API authorization denials",
              after == {"create": False, "update": False} and all(denies.values()),
              {"reviewer_access": after, "api_forbidden": denies})

    author_template = definition("saf-approved-template")
    authored = require_object(lab, request(lab, AUTHOR, "create", author_template), "create")
    authored["metadata"]["annotations"] = {"saf.example/revision": "reviewed"}
    updated = require_object(lab, request(lab, AUTHOR, "replace", authored), "update")
    persisted = json.loads(lab.kubectl("get", CRD, "saf-approved-template", "-o", "json").stdout)
    good = (updated["metadata"]["annotations"]["saf.example/revision"] == "reviewed"
            and persisted["metadata"]["uid"] == authored["metadata"]["uid"]
            and persisted["metadata"]["annotations"].get("saf.example/revision") == "reviewed"
            and persisted["spec"] == author_template["spec"])
    lab.check("positive", "The scoped author creates and revises the exact approved workflow template",
              good, {"approved_definition_retained": good, "api_kind": persisted["kind"]})

    marker = FIXTURES / "public-marker.txt"
    lab.kubectl("create", "secret", "generic", SECRET, f"--from-file=marker={marker}")
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT},
                "automountServiceAccountToken": False})
    job = lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                      "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60, "template": {
                          "spec": {"restartPolicy": "Never", "serviceAccountName": ACCOUNT,
                                   "automountServiceAccountToken": False,
                                   "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                       "seccompProfile": {"type": "RuntimeDefault"}},
                                   "containers": [persisted["spec"]["templates"][0]["container"]],
                                   "volumes": persisted["spec"]["volumes"]}}}})
    lab.kubectl("wait", "--for=condition=Complete", "job/" + JOB, "--timeout=70s", timeout=80)
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"batch.kubernetes.io/job-name={JOB}",
                                  "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block("Expected one retained Job Pod")
    pod, = pods
    spec = pod["spec"]
    security = spec["containers"][0]["securityContext"]
    logs = lab.kubectl("logs", "job/" + JOB).stdout.strip()
    text = marker.read_text().strip()
    actual = {"owned_by_job": any(ref.get("uid") == job["metadata"]["uid"]
                                   for ref in pod["metadata"].get("ownerReferences", [])),
              "succeeded": pod["status"]["phase"] == "Succeeded",
              "dedicated_tokenless_identity": spec["serviceAccountName"] == ACCOUNT
                                              and spec["automountServiceAccountToken"] is False,
              "restricted_context": spec["securityContext"]["runAsNonRoot"] is True
                                    and spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
                                    and security == {"allowPrivilegeEscalation": False,
                                                     "readOnlyRootFilesystem": True,
                                                     "capabilities": {"drop": ["ALL"]},
                                                     "runAsNonRoot": True, "runAsUser": 65534,
                                                     "runAsGroup": 65534},
              "secret_volume_references_marker": any(volume.get("secret", {}).get("secretName") == SECRET
                                                     for volume in spec["volumes"]),
              "expected_marker_confirmation": logs == "marker-mounted",
              "literal_absent": not any(text in region for region in
                                        (logs, json.dumps(spec), json.dumps(persisted)))}
    lab.check("positive", "The owned Job runs its restricted step and mounts the public marker by Secret reference",
              bool(text) and all(actual.values()), actual)
    (lab.evidence / "workflow-authorization.raw.json").write_text(json.dumps(
        {"retained_template": persisted, "job": job, "pod": pod, "result": logs}, indent=2) + "\n")

    helper_path = Path(__file__).resolve().parent / "controller_witness.py"
    spec = importlib.util.spec_from_file_location("saf_0904_001_controller_witness", helper_path)
    if spec is None or spec.loader is None:
        lab.block("The pinned controller witness helper is unavailable")
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    controller.run(lab, SimpleNamespace(namespace="saf-test", account=ACCOUNT,
                                        template="saf-approved-template", marker=SECRET,
                                        marker_text=text,
                                        approved_spec=author_template["spec"]))
    verify_template_admission(lab, text, author_template["spec"])


def verify_template_admission(lab, public_marker, approved_spec):
    """Compare one literal field with the existing Secret-reference form."""
    before_policy = definition("saf-literal-marker-before-policy")
    before_policy["spec"]["templates"][0]["container"].setdefault("env", []).append(
        {"name": LITERAL_ENV_NAME, "value": public_marker})
    before = request(lab, AUTHOR, "create", before_policy, dry_run=True)
    before_ok = False
    if before.returncode == 0:
        observed = json.loads(before.stdout)
        before_ok = observed.get("metadata", {}).get("name") == before_policy["metadata"]["name"]

    api = "admissionregistration.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": ADMISSION_POLICY},
                "spec": {
                    "failurePolicy": "Fail",
                    "matchConstraints": {"resourceRules": [{
                        "apiGroups": ["argoproj.io"], "apiVersions": ["v1alpha1"],
                        "operations": ["CREATE"], "resources": ["workflowtemplates"]}]},
                    "validations": [{
                        "expression": (
                            "object.spec.templates.all(t, !has(t.container.env) || "
                            f"t.container.env.all(e, e.name != '{LITERAL_ENV_NAME}' || !has(e.value)))"),
                        "message": ADMISSION_MESSAGE,
                        "reason": "Forbidden"}],
                }})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": ADMISSION_POLICY},
                "spec": {"policyName": ADMISSION_POLICY, "validationActions": ["Deny"],
                         "matchResources": {"namespaceSelector": {"matchLabels": {
                             "kubernetes.io/metadata.name": "saf-test"}}}}})

    deadline = time.monotonic() + 20
    denied = False
    while time.monotonic() < deadline:
        rejected = request(lab, AUTHOR, "create", before_policy, dry_run=True)
        denied = (rejected.returncode != 0 and ADMISSION_POLICY in rejected.stderr
                  and ADMISSION_MESSAGE in rejected.stderr)
        if denied:
            break
        time.sleep(0.25)

    safe = definition("saf-policy-allowed-template")
    allowed = request(lab, AUTHOR, "create", safe, dry_run=True)
    allowed_ok = False
    if allowed.returncode == 0:
        observed = json.loads(allowed.stdout)
        allowed_ok = (observed.get("metadata", {}).get("name") == safe["metadata"]["name"]
                      and observed.get("spec") == approved_spec)

    persisted = json.loads(lab.kubectl(
        "get", CRD, "saf-approved-template", "-o", "json").stdout)
    persisted_safe = (persisted.get("spec") == approved_spec
                      and persisted.get("spec", {}).get("templates", [{}])[0]
                      .get("container", {}).get("env") is None
                      and persisted.get("spec", {}).get("volumes", [{}])[0]
                      .get("secret", {}).get("secretName") == SECRET)
    absent = lab.kubectl("get", CRD, before_policy["metadata"]["name"],
                         "-o", "name", allow_failure=True)
    not_persisted = (absent.returncode != 0
                     and "notfound" in absent.stderr.lower()
                     and before_policy["metadata"]["name"] in absent.stderr)
    observations = {
        "literal_proposal_admitted_before_policy_server_dry_run": before_ok,
        "same_literal_proposal_denied_after_policy": denied,
        "approved_secret_reference_admitted_after_policy": allowed_ok,
        "persisted_approved_template_unchanged": persisted_safe,
        "rejected_template_not_persisted": not_persisted,
    }
    lab.check("green", "Namespace-scoped admission refuses only the tested public literal env field before persistence",
              all(observations.values()), observations)
