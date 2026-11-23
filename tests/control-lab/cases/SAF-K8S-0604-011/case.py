"""Use independently assessed builder trust when enforcing a provenance threshold."""
from copy import deepcopy
from datetime import date
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
AS_OF = date.fromisoformat("2026-01-15")
SCOPE = (
    "Real BuildKit-generated provenance and Cosign signatures cover an immutable OCI "
    "fixture. A separate signed governance record models trusted SLSA Build levels "
    "by builder and signer, a release target and a scheduled review. Level assignments "
    "are test data. Actual platform assessment and production SLSA level require "
    "independent evidence."
)


def dependency(name, control):
    source = HERE.parent / control / "case.py"
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fingerprint(signer):
    return sha256((signer / "cosign.pub").read_bytes()).hexdigest()


def signer(registry, name):
    directory = registry.work / name
    directory.mkdir(mode=0o700)
    registry.cosign(directory, "generate-key-pair")
    return directory


def publish_attestation(registry, directory, statement, ref, fixture, build):
    predicate = directory / "provenance.json"
    predicate.write_text(json.dumps(statement["predicate"], sort_keys=True))
    registry.cosign(directory, "attest", *fixture.FIXTURE_SIGNING, "--type", build.PREDICATE_TYPE,
                    "--predicate", "/work/provenance.json", ref)
    result = build.cosign_verify(registry, directory, ref)
    verified = [] if result.returncode else build.decoded_statements(result)
    if len(verified) != 1 or verified[0]["predicate"] != statement["predicate"]:
        registry.lab.block("The specified key did not verify the exact stored provenance")
    return {"signer": fingerprint(directory), "statement": verified[0]}


def evaluate(build, governance, document, authority, verified, ref, original, as_of):
    if not authority.approves(governance, document):
        return "governance-signature-invalid"
    if as_of >= date.fromisoformat(governance["review_before"]):
        return "governance-review-overdue"
    candidate, release_key = verified["statement"], verified["signer"]
    if not build.digest_matches(candidate, ref):
        return "wrong-subject"
    if candidate.get("predicateType") != build.PREDICATE_TYPE:
        return "wrong-predicate-type"
    body = candidate["predicate"]
    builder = body["runDetails"]["builder"]["id"]
    assessed = next((row for row in governance["trusted_builders"]
                     if row["builder"] == builder and row["signer"] == release_key), None)
    if assessed is None:
        return "builder-not-assessed"
    if assessed["maximum_fixture_level"] < governance["minimum_fixture_level"]:
        return "target-level-not-met"
    if body["buildDefinition"] != original["predicate"]["buildDefinition"]:
        return "build-expectation-mismatch"
    return "eligible"


def exercise(registry, port, fixture, build, review):
    lab = registry.lab
    archive, arch = build.build(registry)
    ref, statement, manifest = build.publish_layout(registry, port, archive, arch)
    if not build.digest_matches(statement, ref):
        lab.block("The fixture produced mismatched provenance before intake")
    accepted, low = signer(registry, "assessed"), signer(registry, "below-target")
    assert fingerprint(accepted) != fingerprint(low)
    exaggerated = deepcopy(statement)
    exaggerated["predicate"]["runDetails"]["builder"].setdefault("version", {})["fixture-claimed-level"] = "3"
    signed_low = publish_attestation(registry, low, exaggerated, ref, fixture, build)
    signed_ok = publish_attestation(registry, accepted, statement, ref, fixture, build)
    unassessed = signer(registry, "not-assessed")
    signed_unassessed = publish_attestation(registry, unassessed, statement, ref, fixture, build)

    verification_only = signed_low["statement"]["predicate"]["runDetails"]["builder"]["version"]["fixture-claimed-level"] == "3"
    lab.check("red", "Signature and subject validation alone accept the below-target signed declaration",
              verification_only and build.digest_matches(signed_low["statement"], ref),
              {"low_assurance_signature_verified": verification_only})

    directory = registry.work / "governance"
    directory.mkdir(mode=0o700)
    approved_reviewer = review.ReviewSigner(lab, directory, "review-authority")
    publisher_key = review.ReviewSigner(lab, directory, "release-submitter")
    governance = {
        "revision": "fixture-governance-v2", "slsa_build_spec": "1.2", "minimum_fixture_level": 2,
        "review_before": "2026-02-01", "improvement_record": "fixture-build-governance-042",
        "trusted_builders": [
            {"builder": build.BUILDER_ID, "signer": fingerprint(accepted), "maximum_fixture_level": 2},
            {"builder": build.BUILDER_ID, "signer": fingerprint(low), "maximum_fixture_level": 1},
        ],
    }
    signature = approved_reviewer.sign(governance, "authorized")
    rejected_signature = publisher_key.sign(governance, "wrong-authority")

    def check(claim, *, approval=signature, evaluated=AS_OF, subject=ref):
        return evaluate(build, governance, approval, approved_reviewer, claim, subject, statement, evaluated)

    wrong_ref = ref.split("@")[0] + "@sha256:" + "f" * 64
    observed = {
        "self_assigned": check(signed_low),
        "unassessed": check(signed_unassessed),
        "wrong_subject": check(signed_ok, subject=wrong_ref),
        "stale_governance": check(signed_ok, evaluated=date.fromisoformat("2026-02-01")),
        "wrong_governance_authority": check(signed_ok, approval=rejected_signature),
    }
    expected = {
        "self_assigned": "target-level-not-met", "unassessed": "builder-not-assessed", "wrong_subject": "wrong-subject",
        "stale_governance": "governance-review-overdue", "wrong_governance_authority": "governance-signature-invalid",
    }
    lab.check("green", "The authenticated policy denies unsupported level, identity, subject, and review states",
              observed == expected, observed)
    allowed = check(signed_ok)
    lab.check("green", "Independent assessment and exact verified provenance authorize the fixture release",
              allowed == "eligible" and build.digest(manifest) == ref.split("@")[1],
              {"fixture_assessment_satisfied": allowed == "eligible", "exact_verified_subject": True})
    build.run_image(registry, ref)
    (lab.evidence / "builder-assurance.json").write_text(json.dumps({
        "fixture_scope": SCOPE, "governance": governance, "release_target": ref,
        "accepted_build": signed_ok, "measurements": observed,
    }, indent=2, sort_keys=True) + "\n")


def run(lab):
    build = dependency("assurance_buildkit", "SAF-K8S-0603-009")
    review = dependency("assurance_review_signatures", "SAF-K8S-0604-007")
    fixture = build.load_registry()
    with fixture.registry(lab) as (registry, port, _):
        exercise(registry, int(port), fixture, build, review)
