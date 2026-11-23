"""Verify a build-to-promotion attestation chain in admission."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import ssl
import urllib.request

HERE = Path(__file__).resolve().parent
NS = "saf-0603-014"
POLICY = "saf-0603-014-chain"
WEBHOOK = f"ivpol.validate.kyverno.svc-fail-finegrained-{POLICY}"
MUTATING = f"ivpol.mutate.kyverno.svc-fail-finegrained-{POLICY}"
BUILD_TYPE = "https://saf-k8s.example/attestations/build-record/v1"
PROMOTION_TYPE = "https://saf-k8s.example/attestations/promotion-record/v1"
BUILD_REQUIRED = "verified build stage required"
PROMOTION_REQUIRED = "verified promotion stage required"
CHAIN_REQUIRED = "promotion must reference the verified build record"
VARIANTS = ("approved", "build-only", "wrong-promoter", "unlinked", "registry-outage", "webhook-outage")
SCOPE = (
    "A disposable Kubernetes v1.36.1 cluster with Kyverno 1.20.0, a test-owned TLS registry, "
    "and independent ephemeral in-toto build and promotion attestors. The case verifies two "
    "digest-bound attestations and their record linkage at Pod CREATE in one enrolled namespace, "
    "with uncached registry and API-to-webhook failures. Additional workload types, stages, "
    "cached verification, and production coverage require separate evidence."
)


def load(folder, name):
    path = HERE.parent / folder / name
    spec = importlib.util.spec_from_file_location(folder, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def publish(fixture, registry, port):
    base = fixture._build_and_push(registry, port)["approved"]
    image, base_digest = base.rsplit("@", 1)
    repository = image.split("/", 1)[1]
    url = f"https://127.0.0.1:{port}/v2/{repository}/manifests/"
    media = "application/vnd.oci.image.manifest.v1+json"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=registry.registry_ca)),
    )
    with opener.open(urllib.request.Request(url + base_digest, headers={"Accept": media}), timeout=10) as response:
        original = json.load(response)
    refs = {}
    for label in VARIANTS:
        body = json.dumps({**original, "annotations": {"org.opencontainers.image.title": label}},
                          sort_keys=True, separators=(",", ":")).encode("ascii")
        digest = "sha256:" + sha256(body).hexdigest()
        request = urllib.request.Request(url + label, data=body, method="PUT", headers={"Content-Type": media})
        with opener.open(request, timeout=10) as response:
            if response.status != 201 or response.headers["Docker-Content-Digest"] != digest:
                registry.lab.block("Owned registry did not store the exact fixture manifest")
        refs[label] = f"{image}@{digest}"
    return refs


def signer(registry, name):
    work = registry.work / name
    work.mkdir(mode=0o700)
    registry.cosign(work, "generate-key-pair")
    return work


def attest(fixture, registry, work, kind, predicate, ref):
    (work / "record.json").write_text(json.dumps(predicate, sort_keys=True))
    registry.cosign(work, "attest", *fixture.FIXTURE_SIGNING, "--type", kind,
                    "--predicate", "/work/record.json", ref)


def sign_stages(fixture, registry, refs):
    builder = signer(registry, "fixture-builder")
    promoter = signer(registry, "fixture-promoter")
    unrelated = signer(registry, "fixture-unrelated")
    for label, ref in refs.items():
        digest = ref.rsplit("@", 1)[1]
        build_record = sha256(f"saf-0603-014:build:{digest}".encode()).hexdigest()
        attest(fixture, registry, builder, BUILD_TYPE, {"stage": "build", "record": build_record}, ref)
        if label != "build-only":
            record = {"stage": "promotion", "buildRecord": build_record if label != "unlinked" else "0" * 64}
            actor = unrelated if label == "wrong-promoter" else promoter
            attest(fixture, registry, actor, PROMOTION_TYPE, record, ref)
    keys = [(item / "cosign.pub").read_text() for item in (builder, promoter)]
    if len(set(keys)) != 2:
        registry.lab.block("The two stage signers must be independent")
    return keys


def policy(registry, keys):
    build_verify = "verifyAttestationSignatures(image, attestations.build, [attestors.builder]) > 0"
    release_verify = "verifyAttestationSignatures(image, attestations.promotion, [attestors.promoter]) > 0"
    build = "extractPayload(image, attestations.build).predicate"
    promotion = "extractPayload(image, attestations.promotion).predicate"
    chain = (
        f"({build_verify} && {release_verify}) ? "
        f"({build}.stage == 'build' && {promotion}.stage == 'promotion' "
        f"&& {promotion}.buildRecord == {build}.record) : false"
    )
    return {
        "apiVersion": "policies.kyverno.io/v1", "kind": "ImageValidatingPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "validationActions": ["Deny"], "failurePolicy": "Fail",
            "webhookConfiguration": {"timeoutSeconds": 10},
            "evaluation": {"background": {"enabled": False}},
            "matchConstraints": {"resourceRules": [
                {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]},
            ], "namespaceSelector": {"matchLabels": {"saf-k8s.example/case": "0603-014"}}},
            "matchImageReferences": [{"glob": f"{registry.registry}/fixture/*@sha256:*"}],
            "attestors": [{
                "name": label, "cosign": {"key": {"data": key},
                    "ctlog": {"insecureIgnoreSCT": True, "insecureIgnoreTlog": True}},
            } for label, key in zip(("builder", "promoter"), keys)],
            "attestations": [{"name": label, "intoto": {"type": kind}}
                             for label, kind in (("build", BUILD_TYPE), ("promotion", PROMOTION_TYPE))],
            "validations": [{"expression": f"images.containers.map(image, {expression}).all(ok, ok)",
                             "message": message}
                            for expression, message in ((build_verify, BUILD_REQUIRED),
                                (release_verify, PROMOTION_REQUIRED), (chain, CHAIN_REQUIRED))],
        },
    }


def run(lab):
    fixture = load("SAF-K8S-0605-002", "image_admission.py")
    kyverno = load("SAF-K8S-1006-005", "case.py")
    faults = load("SAF-K8S-0602-006", "case.py")
    fixture.POLICY = POLICY
    faults.WEBHOOK, faults.MUTATING_WEBHOOK = WEBHOOK, MUTATING
    with fixture.registry(lab) as (registry, port, values):
        kyverno._install_kyverno(lab, values)
        refs = publish(fixture, registry, port)
        keys = sign_stages(fixture, registry, refs)
        registry.kube("create", "namespace", NS)
        registry.kube("label", "namespace", NS, "saf-k8s.example/case=0603-014")

        def probe(label):
            return fixture._probe(registry, f"probe-{label}", refs[label], NS)

        def admitted(label):
            result = probe(label)
            return fixture._admitted(result, f"probe-{label}", refs[label], NS)

        def denies(label, message):
            result = probe(label)
            return result.returncode != 0 and WEBHOOK in result.stderr and message in result.stderr

        baseline = admitted("build-only")
        lab.check("red", "The identical incomplete chain is admitted before policy activation",
                  baseline, {"incomplete_baseline_admitted": baseline})
        registry.kube("create", "-f", "-", input_text=json.dumps(policy(registry, keys)))
        fixture._wait_policy(registry)
        incomplete = faults.wait_for(registry, lambda: denies("build-only", PROMOTION_REQUIRED),
                                     "Admission did not explicitly deny the missing promotion record")
        lab.check("green", "The policy rejects the same digest with no promotion attestation",
                  incomplete, {"missing_promotion_attestation_denied": incomplete})
        for label, message in (("wrong-promoter", PROMOTION_REQUIRED), ("unlinked", CHAIN_REQUIRED)):
            denied = denies(label, message)
            lab.check("green", f"Admission explicitly denies {label}",
                      denied, {"policy_denial_matches_expected_reason": denied})
        valid = admitted("approved")
        lab.check("positive", "Both verified attestations on the digest form an admitted chain",
                  valid, {"approved_chain_admitted": valid})

        with faults.without_registry(registry):
            def no_registry():
                result = probe("registry-outage")
                msg = result.stderr.lower()
                return (result.returncode != 0 and WEBHOOK in result.stderr and "denied the request" in msg
                        and "connection refused" in msg)
            refusals = faults.wait_for(registry, no_registry, "Expected reachable-webhook registry denial was absent")
            ready = faults.service_has_endpoint(registry) and not faults.registry_running(registry)
            lab.check("green", "The reachable verifier rejects a fresh complete chain when registry lookup fails",
                      refusals and ready, {"reachable_webhook_rejected_registry_failure": refusals,
                                          "owned_registry_stopped": ready})
        accepted = faults.wait_for(registry, lambda: admitted("registry-outage"),
                                   "Previously unavailable registry proof did not recover")
        lab.check("positive", "The same complete chain is admitted when registry lookup recovers",
                  accepted, {"recovered_registry_chain_admitted": accepted})

        with faults.without_webhook(registry):
            registered = faults.failure_policies(registry)
            result = probe("webhook-outage")
            rejected = (result.returncode != 0 and MUTATING in result.stderr
                        and "failed calling webhook" in result.stderr.lower())
            lab.check("green", "The API rejects attested admission when its required webhook cannot be reached",
                      registered == {WEBHOOK: "Fail", MUTATING: "Fail"} and rejected
                      and faults.registry_running(registry),
                      {"mutating_policy": registered.get(MUTATING), "validating_policy": registered.get(WEBHOOK),
                       "webhook_call_failed_and_request_rejected": rejected})
        accepted = faults.wait_for(registry, lambda: admitted("webhook-outage"),
                                   "The same complete chain was not admitted after webhook recovery")
        lab.check("positive", "The fresh complete chain is admitted after its required webhook recovers",
                  accepted, {"recovered_webhook_chain_admitted": accepted})
