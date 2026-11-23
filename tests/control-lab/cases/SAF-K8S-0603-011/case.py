"""Verify signed policy revisions, separated change approval and effective enforcement."""
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY = "saf-0603-011-policy"
WEBHOOKS = ("ivpol.validate.kyverno.svc-fail", f"ivpol.validate.kyverno.svc-fail-finegrained-{POLICY}")
NS = "saf-0603-011"
SUBJECT = "saf-0603-011-policy-applier"
AUTHOR = "saf-0603-011-policy-author"
TYPE = "https://saf-k8s.example/attestations/review-tier/v1"
MESSAGE = "attestation tier must match the effective verified policy revision"
SCOPE = (
    "One disposable Kind cluster and opt-in namespace. Distinct ephemeral policy author, "
    "promoter, rollback and artifact attestor keys protect two successive Kyverno revisions. "
    "Kubernetes RBAC separates direct policy authoring and the restricted policy applier. "
    "Server readback and changed admission decisions verify the effective revision. "
    "Production branch protection, identity custody and change records require independent evidence."
)


def load(folder, name):
    path = HERE.parent / folder / name
    spec = importlib.util.spec_from_file_location(folder, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(obj):
    return sha256(canonical(obj)).hexdigest()


class Signatures:
    def __init__(self, lab):
        self.lab = lab
        self.root = lab.kubeconfig.parent / "policy-signatures"
        self.root.mkdir(mode=0o700)
        self.signers = {}
        for role in ("author", "promoter", "rollback"):
            key, public = self.root / f"{role}.pem", self.root / f"{role}.pub"
            lab.command("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                         "ec_paramgen_curve:prime256v1", "-out", str(key))
            key.chmod(0o600)
            lab.command("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public))
            self.signers[role] = (key, public)
        fingerprints = {sha256(public.read_bytes()).hexdigest() for _, public in self.signers.values()}
        if len(fingerprints) != 3:
            lab.block("The policy authorities did not have independent fixture keys")

    def sign(self, obj, role, name):
        content = self.root / (name + ".json")
        signature = self.root / (name + ".sig")
        content.write_bytes(canonical(obj))
        self.lab.command("openssl", "dgst", "-sha256", "-sign", str(self.signers[role][0]),
                         "-out", str(signature), str(content))
        return signature

    def verified(self, obj, role, signature):
        path = self.root / "expected-bytes.json"
        path.write_bytes(canonical(obj))
        result = self.lab.command("openssl", "dgst", "-sha256", "-verify", str(self.signers[role][1]),
                                  "-signature", str(signature), str(path), allow_failure=True)
        return result.returncode == 0 and "Verified OK" in result.stdout


def image_policy(registry, key, revision, tier):
    record = "verifyAttestationSignatures(image, attestations.release, [attestors.operator]) > 0"
    payload = "extractPayload(image, attestations.release).predicate"
    return {
        "apiVersion": "policies.kyverno.io/v1", "kind": "ImageValidatingPolicy",
        "metadata": {"name": POLICY, "annotations": {"saf-k8s.example/revision": revision}},
        "spec": {
            "failurePolicy": "Fail", "validationActions": ["Deny"],
            "evaluation": {"background": {"enabled": False}},
            "matchConstraints": {"namespaceSelector": {"matchLabels": {"saf-k8s.example/case": "0603-011"}},
                                 "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                    "operations": ["CREATE"], "resources": ["pods"]}]},
            "matchImageReferences": [{"glob": f"{registry.registry}/fixture/*@sha256:*"}],
            "attestors": [{"name": "operator", "cosign": {"key": {"data": key},
                "ctlog": {"insecureIgnoreSCT": True, "insecureIgnoreTlog": True}}}],
            "attestations": [{"name": "release", "intoto": {"type": TYPE}}],
            "validations": [{"expression": f"images.containers.map(image, {record} ? "
                                           f"{payload}.tier == '{tier}' : false).all(ok, ok)",
                             "message": MESSAGE}],
        },
    }


def public_projection(obj):
    metadata = obj["metadata"]
    return {"apiVersion": obj["apiVersion"], "kind": obj["kind"],
            "metadata": {"name": metadata["name"], "annotations": {
                "saf-k8s.example/revision": metadata["annotations"]["saf-k8s.example/revision"]
            }}, "spec": obj["spec"]}


def server_projection(registry, obj):
    response = registry.kube("create", "-f", "-", "--dry-run=server", "-o", "json", input_text=json.dumps(obj))
    return public_projection(json.loads(response.stdout))


def state(registry):
    return json.loads(registry.kube("get", "imagevalidatingpolicy", POLICY, "-o", "json").stdout)


def approval(obj, previous, action):
    return {"operation": action, "targetPolicy": POLICY, "namespace": NS,
            "fromPolicyDigest": digest(previous), "toPolicyDigest": digest(obj)}


def set_policy(registry, fixture, signed, new, author_signature, ticket, ticket_signature, role):
    before = state(registry)
    if not signed.verified(new, "author", author_signature):
        return "bad-author-signature"
    if ticket != approval(new, public_projection(before), role):
        return "unexpected-revision-or-target"
    if not signed.verified(ticket, role, ticket_signature):
        return "missing-independent-approval"
    replacement = deepcopy(new)
    replacement["metadata"]["resourceVersion"] = before["metadata"]["resourceVersion"]
    actor = f"--as=system:serviceaccount:saf-test:{SUBJECT}"
    registry.kube(actor, "replace", "-f", "-", input_text=json.dumps(replacement))
    fixture._wait_policy(registry)
    return "applied" if public_projection(state(registry)) == new else "effective-policy-mismatch"


def rbac(lab):
    for actor in (SUBJECT, AUTHOR):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": actor}})
    name = "saf-0603-011-policy-updater"
    common = {"apiVersion": "rbac.authorization.k8s.io/v1", "metadata": {"name": name}}
    lab.create({**common, "kind": "ClusterRole", "rules": [
        {"apiGroups": ["policies.kyverno.io"], "resources": ["imagevalidatingpolicies"],
         "resourceNames": [POLICY], "verbs": ["get", "update"]},
    ]})
    lab.create({**common, "kind": "ClusterRoleBinding",
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": name},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": SUBJECT}]})


def attested_images(fixture, faults, registry, port):
    refs, _ = faults.publish_images(fixture, registry, port)
    work = registry.work / "signed-probe"
    work.mkdir(mode=0o700)
    registry.cosign(work, "generate-key-pair")
    images = {"alpha": refs["healthy"], "beta": refs["registry-outage"]}
    for tier, image in images.items():
        (work / "predicate.json").write_text(json.dumps({"tier": tier}))
        registry.cosign(work, "attest", *fixture.FIXTURE_SIGNING, "--type", TYPE,
                        "--predicate", "/work/predicate.json", image)
    return images, (work / "cosign.pub").read_text()


def run(lab):
    fixture = load("SAF-K8S-0605-002", "image_admission.py")
    kyverno = load("SAF-K8S-1006-005", "case.py")
    faults = load("SAF-K8S-0602-006", "case.py")
    fixture.POLICY = POLICY
    with fixture.registry(lab) as (registry, port, values):
        kyverno._install_kyverno(lab, values)
        refs, key = attested_images(fixture, faults, registry, port)
        signatures = Signatures(lab)
        registry.kube("create", "namespace", NS)
        registry.kube("label", "namespace", NS, "saf-k8s.example/case=0603-011")
        rbac(lab)
        original = server_projection(registry, image_policy(registry, key, "A", "alpha"))
        replacement = server_projection(registry, image_policy(registry, key, "B", "beta"))
        signed_a = signatures.sign(original, "author", "revision-a")
        signed_b = signatures.sign(replacement, "author", "revision-b")
        promote = approval(replacement, original, "promoter")
        rollback = approval(original, replacement, "rollback")
        promoted = signatures.sign(promote, "promoter", "promoted")
        rolled_back = signatures.sign(rollback, "rollback", "rolled-back")
        author_only = signatures.sign(promote, "author", "author-only-promotion")

        def compare(expected):
            rejected_tier = "beta" if expected == "alpha" else "alpha"
            no_name, yes_name = f"probe-reject-{rejected_tier}", f"probe-accept-{expected}"
            negative = fixture._probe(registry, no_name, refs[rejected_tier], NS)
            positive = fixture._probe(registry, yes_name, refs[expected], NS)
            webhook_denied = any(f'admission webhook "{name}" denied the request' in negative.stderr
                                 for name in WEBHOOKS)
            return (negative.returncode != 0 and webhook_denied
                    and f"Policy {POLICY} failed: {MESSAGE}" in negative.stderr
                    and fixture._admitted(positive, yes_name, refs[expected], NS))

        before = fixture._probe(registry, "initial-beta", refs["beta"], NS)
        lab.check("red", "Before activation the artifact that revision A will reject is admitted",
                  fixture._admitted(before, "initial-beta", refs["beta"], NS), {"baseline_beta_admitted": True})
        if not signatures.verified(original, "author", signed_a):
            lab.block("The signed bootstrap revision failed author verification")
        registry.kube("create", "-f", "-", input_text=json.dumps(original))
        fixture._wait_policy(registry)
        applies_a = faults.wait_for(registry, lambda: compare("alpha"), "Bootstrapped policy A did not take effect")
        lab.check("positive", "Signed policy A is read back exactly and governs admission",
                  public_projection(state(registry)) == original and applies_a, {"revision_a_effective": True})

        direct = deepcopy(replacement)
        direct["metadata"]["resourceVersion"] = state(registry)["metadata"]["resourceVersion"]
        actor = f"--as=system:serviceaccount:saf-test:{AUTHOR}"
        result = registry.kube(actor, "replace", "-f", "-", input_text=json.dumps(direct), allow_failure=True)
        authorization_denied = result.returncode != 0 and "cannot update resource" in result.stderr and AUTHOR in result.stderr
        lab.check("green", "The policy author cannot submit a direct policy update",
                  authorization_denied, {"author_direct_update_forbidden": authorization_denied})

        changed = deepcopy(replacement)
        changed["spec"]["webhookConfiguration"] = {"timeoutSeconds": 5}
        tampered = set_policy(registry, fixture, signatures, changed, signed_b, promote, promoted, "promoter")
        unapproved = set_policy(registry, fixture, signatures, replacement, signed_b,
                                promote, author_only, "promoter")
        stale = set_policy(registry, fixture, signatures, original, signed_a,
                           rollback, rolled_back, "rollback")
        still_a = public_projection(state(registry)) == original and compare("alpha")
        lab.check("green", "Tampered bytes, an author-only approval and a stale rollback leave A effective",
                  (tampered, unapproved, stale) == (
                      "bad-author-signature", "missing-independent-approval", "unexpected-revision-or-target"
                  ) and still_a, {"tampered_policy": tampered, "wrong_approver": unapproved,
                                  "rollback_wrong_base": stale, "policy_a_preserved": still_a})

        moved = set_policy(registry, fixture, signatures, replacement, signed_b, promote, promoted, "promoter")
        uses_b = faults.wait_for(registry, lambda: compare("beta"), "The approved B revision did not take effect")
        lab.check("green", "Independent approval promotes the exact B revision and changes API decisions",
                  moved == "applied" and uses_b, {"approved_b_effective": moved == "applied", "beta_only": uses_b})

        invalid = set_policy(registry, fixture, signatures, original, signed_a, rollback, promoted, "rollback")
        lab.check("green", "A promotion signature cannot authorize rollback", invalid == "missing-independent-approval"
                  and public_projection(state(registry)) == replacement, {"rollback_wrong_authority": invalid})
        restored = set_policy(registry, fixture, signatures, original, signed_a, rollback, rolled_back, "rollback")
        uses_a = faults.wait_for(registry, lambda: compare("alpha"), "Authorized rollback did not restore A decisions")
        lab.check("positive", "Independent rollback authorization restores exact A bytes and admission",
                  restored == "applied" and uses_a, {"approved_rollback_effective": restored == "applied",
                                                     "alpha_only": uses_a})
        (lab.evidence / "effective-policy-revisions.json").write_text(json.dumps({
            "policy_a_signed_digest": digest(original), "policy_b_signed_digest": digest(replacement),
            "effective_after_rollback_digest": digest(public_projection(state(registry))),
            "promoted": moved, "rolled_back": restored,
        }, indent=2, sort_keys=True) + "\n")
