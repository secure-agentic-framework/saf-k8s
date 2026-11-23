"""Bind a fictional supplier approval to the exact image and active intake requirements."""
from copy import deepcopy
from hashlib import sha256
import json
import time

from fixtures import BUSYBOX_IMAGE

APPROVAL = "supplier-intake-approved"
POLICY = "saf-supplier-intake"
SUBMITTER = "supplier-deployer"
NAMESPACE = "saf-test"
DENIAL = "image and review must match the active verified supplier intake record"
ANNOTATION = "saf-k8s.example/supplier-review"
PROFILE = {"revision": "intake-profile-v2", "supplier": "Saf Fictional Components",
           "criteria": ["disclosure-contact", "support-window", "license-review", "image-verification-evidence"]}
SCOPE = (
    "One fictional supplier, two independently signed review records, and an exact image "
    "reference enforced on Pod creation. Kubernetes blocks absent or different records and "
    "prevents a fixture deployer from changing the approved parameter. Real communication, "
    "contract commitments, signature or SBOM systems, and coverage require independent evidence."
)


def encoded(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


class ReviewSigner:
    def __init__(self, lab, path, name):
        self.lab, self.path, self.name = lab, path, name
        self.private, self.public = path / (name + ".pem"), path / (name + ".pub")
        lab.command("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-out", str(self.private))
        self.private.chmod(0o600)
        lab.command("openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public))

    def sign(self, doc, tag):
        raw = self.path / f"{self.name}-{tag}.json"
        signed = self.path / f"{self.name}-{tag}.sig"
        raw.write_bytes(encoded(doc))
        self.lab.command("openssl", "dgst", "-sha256", "-sign", str(self.private),
                         "-out", str(signed), str(raw))
        return signed

    def approves(self, doc, signature):
        raw = self.path / f"{self.name}-verification.json"
        raw.write_bytes(encoded(doc))
        result = self.lab.command("openssl", "dgst", "-sha256", "-verify", str(self.public),
                                  "-signature", str(signature), str(raw), allow_failure=True)
        return result.returncode == 0 and "Verified OK" in result.stdout


def approval_record(profile, image, procurement, technical, procurement_signature, technical_signature, reviewers):
    contract_reviewer, technical_reviewer = reviewers
    if not contract_reviewer.approves(procurement, procurement_signature):
        return "unapproved-procurement-authority"
    if not technical_reviewer.approves(technical, technical_signature):
        return "unapproved-technical-authority"
    if procurement["revision"] != profile["revision"] or technical["revision"] != profile["revision"]:
        return "requirements-revision-mismatch"
    if procurement["supplier"] != profile["supplier"] or not set(profile["criteria"][:-1]) <= set(procurement["reviewed"]):
        return "required-procurement-review-missing"
    if procurement["image"] != image or technical["image"] != image or technical["sbom_subject"] != image:
        return "artifact-or-subject-mismatch"
    if technical["evidence"] != "fixture image-verification record":
        return "required-image-evidence-missing"
    return {"review": "fixture-record-v2", "revision": profile["revision"], "image": image}


def pod(name, image=BUSYBOX_IMAGE, review="fixture-record-v2"):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "annotations": {ANNOTATION: review}},
            "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never", "containers": [
                {"name": "marker", "image": image, "command": ["/bin/echo", "supplier-intake-approved"]},
            ]}}


def allowed(lab, manifest, *, actor=None, dry=True):
    args = ["create", "-f", "-", "-o", "json"]
    if actor:
        args.extend(["--as", actor])
    if dry:
        args.append("--dry-run=server")
    return lab.kubectl(*args, payload=encoded(manifest).decode(), allow_failure=True)


def configmap(name, data):
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
            "immutable": True, "data": data}


def deployer(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": SUBMITTER}})
    common = {"apiVersion": "rbac.authorization.k8s.io/v1", "metadata": {"name": SUBMITTER}}
    lab.create({**common, "kind": "Role", "rules": [
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [APPROVAL], "verbs": ["get"]},
    ]})
    lab.create({**common, "kind": "RoleBinding",
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": SUBMITTER},
                "subjects": [{"kind": "ServiceAccount", "name": SUBMITTER, "namespace": NAMESPACE}]})
    return f"system:serviceaccount:{NAMESPACE}:{SUBMITTER}"


def install(lab, revision):
    findings = [
        f"has(object.metadata.annotations) && '{ANNOTATION}' in object.metadata.annotations",
        f"params != null && params.data.revision == '{revision}'",
        f"object.metadata.annotations['{ANNOTATION}'] == params.data.review",
        "object.spec.containers.all(c, c.image == params.data.image)",
        "!has(object.spec.initContainers) || object.spec.initContainers.all(c, c.image == params.data.image)",
    ]
    base = {"apiVersion": "admissionregistration.k8s.io/v1", "metadata": {"name": POLICY}}
    lab.create({**base, "kind": "ValidatingAdmissionPolicy",
                "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": {"resourceRules": [
                             {"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"],
                              "operations": ["CREATE"], "scope": "Namespaced"}
                         ]},
                         "validations": [{"expression": " && ".join(f"({part})" for part in findings),
                                          "message": DENIAL, "reason": "Forbidden"}]}})
    lab.create({**base, "kind": "ValidatingAdmissionPolicyBinding",
                "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                         "paramRef": {"name": APPROVAL, "namespace": NAMESPACE, "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector": {
                             "matchLabels": {"kubernetes.io/metadata.name": NAMESPACE},
                         }}}})


def wait_until(lab, operation, match, description):
    end = time.monotonic() + 25
    while time.monotonic() < end:
        result = operation()
        if match(result):
            return result
        time.sleep(0.4)
    lab.block(description)


def exercise_records(lab, profile, wrong_image):
    path = lab.kubeconfig.parent / "supplier-signatures"
    path.mkdir(mode=0o700)
    review, evidence = ReviewSigner(lab, path, "procurement"), ReviewSigner(lab, path, "technical")
    procurement = {"supplier": profile["supplier"], "image": BUSYBOX_IMAGE, "revision": profile["revision"],
                   "reviewed": profile["criteria"][:-1]}
    technical = {"image": BUSYBOX_IMAGE, "revision": profile["revision"],
                 "sbom_subject": BUSYBOX_IMAGE, "evidence": "fixture image-verification record"}
    procurement_signature = review.sign(procurement, "approved")
    technical_signature = evidence.sign(technical, "approved")

    def decide(contract, check, contract_signature, check_signature):
        return approval_record(profile, BUSYBOX_IMAGE, contract, check, contract_signature,
                               check_signature, (review, evidence))

    same_role = review.sign(technical, "same-authority")
    obsolete = {**procurement, "revision": "intake-profile-v1"}
    mismatched = {**technical, "sbom_subject": wrong_image}
    decisions = {
        "one_authority": decide(procurement, technical, procurement_signature, same_role),
        "stale_profile": decide(obsolete, technical, review.sign(obsolete, "stale"), technical_signature),
        "wrong_artifact": decide(procurement, mismatched, procurement_signature, evidence.sign(mismatched, "mismatch")),
    }
    expected = {"one_authority": "unapproved-technical-authority", "stale_profile": "requirements-revision-mismatch",
                "wrong_artifact": "artifact-or-subject-mismatch"}
    lab.check("green", "Independent approvals, the current requirements and the exact artifact are required",
              decisions == expected, decisions)
    accepted = decide(procurement, technical, procurement_signature, technical_signature)
    if not isinstance(accepted, dict):
        lab.block("The test artifact did not obtain the two matching fixture reviews")
    return accepted


def run(lab):
    wrong_image = BUSYBOX_IMAGE.split("@")[0] + "@sha256:" + "f" * 64
    actor = deployer(lab)
    baseline = allowed(lab, pod("intake-baseline", wrong_image), actor=actor)
    lab.check("red", "The same unreviewed image reference reaches admission before the intake policy",
              baseline.returncode == 0, {"unreviewed_reference_admitted": baseline.returncode == 0})

    lab.create(configmap("supplier-intake-profile", {"requirements.json": encoded(PROFILE).decode()}))
    stored = json.loads(lab.kubectl("get", "configmap", "supplier-intake-profile", "-o", "json").stdout)
    profile = json.loads(stored["data"]["requirements.json"])
    install(lab, profile["revision"])
    missing = wait_until(lab, lambda: allowed(lab, pod("approval-absent")),
                         lambda item: item.returncode and POLICY in item.stderr and "param" in item.stderr.lower(),
                         "The API never enforced the absent approval parameter")
    lab.check("green", "The API denies the exact image when the approval parameter is absent",
              missing.returncode != 0, {"missing_approval_denied": True})
    approved = exercise_records(lab, profile, wrong_image)
    record = configmap(APPROVAL, approved)
    lab.create(record)
    wait_until(lab, lambda: allowed(lab, pod("approval-ready"), actor=actor),
               lambda item: item.returncode == 0, "The authorized fixture release never became admissible")
    patch = json.dumps({"data": {"image": wrong_image}})
    denied_patch = lab.kubectl("--as", actor, "patch", "configmap", APPROVAL, "--type=merge", "-p", patch,
                               allow_failure=True)
    forbidden = denied_patch.returncode != 0 and "cannot patch resource" in denied_patch.stderr
    lab.check("green", "The deploying identity cannot change the approved artifact parameter",
              forbidden, {"deployer_patch_denied": forbidden})
    wrong_review = pod("wrong-review", review="fixture-record-v1")
    wrong_init = deepcopy(pod("wrong-init"))
    wrong_init["spec"]["initContainers"] = [{"name": "wrong", "image": wrong_image}]
    results = [allowed(lab, item, actor=actor) for item in (pod("wrong-image", wrong_image), wrong_review, wrong_init)]
    rejected = [item.returncode != 0 and POLICY in item.stderr and DENIAL in item.stderr for item in results]
    lab.check("green", "The effective policy denies a mismatched image, review or init image",
              all(rejected), {"wrong_image_denied": rejected[0], "wrong_review_denied": rejected[1],
                              "wrong_init_denied": rejected[2]})
    created = allowed(lab, pod("intake-runtime"), actor=actor, dry=False)
    if created.returncode:
        lab.block(f"The live admitted fixture could not be created: {created.stderr}")
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/intake-runtime", "--timeout=60s", timeout=70)
    marker = lab.kubectl("logs", "intake-runtime").stdout.strip() == "supplier-intake-approved"
    lab.check("positive", "The authorized deployer runs the matching fixture image under the approved review",
              marker, {"approved_fixture_ran": marker})
    (lab.evidence / "supplier-intake-review.json").write_text(json.dumps(
        {"profile": profile, "profile_sha256": sha256(encoded(profile)).hexdigest(), "approved": approved},
        indent=2, sort_keys=True
    ) + "\n")
