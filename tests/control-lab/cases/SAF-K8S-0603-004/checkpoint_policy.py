"""Verify real signature sets over immutable synthetic lifecycle manifests."""
from hashlib import sha256
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey


ARTIFACT_DIR = Path("/artifacts")
ARTIFACTS = ("training-inputs", "model-weights", "checkpoint", "embedding-index", "inference-output")
DOMAIN = b"saf-k8s.example/ml-artifact-manifest/v1"
CLASSIC = "ecdsa-p256-sha256"
QUANTUM = "ml-dsa-65"
PHASES = {"legacy": {CLASSIC}, "dual": {CLASSIC, QUANTUM}, "post-quantum": {QUANTUM}}


def manifest(names=ARTIFACTS):
    return {name: sha256((ARTIFACT_DIR / name).read_bytes()).hexdigest() for name in names}


def encode(items):
    return DOMAIN + b"\n" + json.dumps(items, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verifies(trusted, algorithm, signature, message):
    try:
        if algorithm == CLASSIC:
            trusted[algorithm].verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            trusted[algorithm].verify(signature, message, DOMAIN)
    except InvalidSignature:
        return False
    return True


def decide(phase, artifacts, signatures, trusted):
    if artifacts != manifest():
        return "artifact-manifest-mismatch"
    message = encode(artifacts)
    for algorithm in sorted(PHASES[phase]):
        if algorithm not in signatures:
            return f"missing:{algorithm}"
        if not verifies(trusted, algorithm, signatures[algorithm], message):
            return f"invalid:{algorithm}"
    return "verified"


def run():
    classical = ec.generate_private_key(ec.SECP256R1())
    quantum = MLDSA65PrivateKey.generate()
    unrelated = MLDSA65PrivateKey.generate()
    public = {CLASSIC: classical.public_key(), QUANTUM: quantum.public_key()}
    artifacts = manifest()
    original = encode(artifacts)
    classical_sig = classical.sign(original, ec.ECDSA(hashes.SHA256()))
    quantum_sig = quantum.sign(original, DOMAIN)
    both = {CLASSIC: classical_sig, QUANTUM: quantum_sig}
    less = manifest(tuple(name for name in ARTIFACTS if name != "checkpoint"))
    less_message = encode(less)
    authentic_but_incomplete = {
        CLASSIC: classical.sign(less_message, ec.ECDSA(hashes.SHA256())),
        QUANTUM: quantum.sign(less_message, DOMAIN),
    }
    modified = dict(artifacts, checkpoint="0" * 64)
    return {
        "legacy": decide("legacy", artifacts, {CLASSIC: classical_sig}, public),
        "dual_missing_pq": decide("dual", artifacts, {CLASSIC: classical_sig}, public),
        "dual_missing_classical": decide("dual", artifacts, {QUANTUM: quantum_sig}, public),
        "dual_wrong_pq_identity": decide("dual", artifacts, {**both, QUANTUM: unrelated.sign(original, DOMAIN)}, public),
        "dual_incomplete_artifact_list": decide("dual", less, authentic_but_incomplete, public),
        "incomplete_signatures_genuinely_verify": all(
            verifies(public, algorithm, sig, less_message) for algorithm, sig in authentic_but_incomplete.items()
        ),
        "dual_changed_digest": decide("dual", modified, both, public),
        "dual": decide("dual", artifacts, both, public),
        "pq_only_old_signer": decide("post-quantum", artifacts, {CLASSIC: classical_sig}, public),
        "pq_only": decide("post-quantum", artifacts, {QUANTUM: quantum_sig}, public),
        "artifacts": artifacts,
    }


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
