"""Verify an actual fixture release against out-of-band publisher trust."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import time

OPENSSL = "docker.io/alpine/openssl:3.3.2@sha256:5008e829163320a6e8166883c03e68189e8925ade68cde36584dc2a41cfa5248"
PUBLISHER = "urn:saf:fixture:publisher:cardinal"
SOURCE = "https://models.example.invalid/fixture/cardinal"
SCOPE = (
    "A fresh Kubernetes v1.36.1 cluster runs a restricted intake Job using OpenSSL 3.3.2. "
    "The fixture generates a genuine local Git commit, exact model and card bytes and a "
    "signed release. An out-of-band public key and exact expected repository commit bind "
    "publisher and release metadata before persisting the approval. The test covers missing "
    "signature, untrusted signature, changed publisher metadata and content mismatch. "
    "Production provenance coverage, actual publisher identity, trust-root lifecycle, and "
    "cryptographic attestation of a public platform account are open."
)
PROGRAM = r'''
set -eu
if [ "$1" = unchecked ]; then
    echo APPROVED_WITHOUT_PROVENANCE
    exit 0
fi
if [ ! -s /input/release.sig ]; then echo provenance-signature-missing; exit 21; fi
if ! openssl dgst -sha256 -verify /trust/publisher.pub -signature /input/release.sig /input/release.json >/dev/null 2>&1; then
    echo provenance-signature-untrusted
    exit 22
fi
if ! cmp -s /trust/exact-release.json /input/release.json; then echo provenance-release-mismatch; exit 23; fi
(
    cd /input
    if ! sha256sum -c /trust/content.sha256 >/dev/null 2>&1; then
        echo provenance-content-mismatch
        exit 24
    fi
)
echo APPROVED_WITH_VERIFIED_PROVENANCE
cat /input/release.json
'''


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _hash(value):
    return sha256(value).hexdigest()


def _cm(lab, name, values, *, binary=False):
    data = {"binaryData": {k: base64.b64encode(v).decode() for k, v in values.items()}} if binary else {"data": values}
    return lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                       "immutable": True, **data})


def _release(lab, work):
    source = work / "publisher"
    source.mkdir()
    model = _canonical({"model": "inert-cardinal", "weight": 2.0})
    card = _canonical({"publisher": PUBLISHER, "source": SOURCE, "license": "fixture-only"})
    (source / "model.json").write_bytes(model)
    (source / "model-card.json").write_bytes(card)
    git = ("git", "-C", str(source), "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false")
    lab.command(*git, "init", "--object-format=sha1", "--initial-branch=main")
    lab.command(*git, "add", "--", "model.json", "model-card.json")
    lab.command("env", "GIT_AUTHOR_DATE=2026-04-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-04-01T00:00:00Z",
                *git, "-c", "user.name=Fixture Publisher", "-c", "user.email=publisher@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "-m", "Release inert model")
    commit = lab.command(*git, "rev-parse", "HEAD").stdout.strip()
    for name, raw in (("model.json", model), ("model-card.json", card)):
        if lab.command(*git, "show", f"{commit}:{name}").stdout.encode() != raw:
            lab.block("Fixture Git commit does not match actual artifact bytes")
    release = {"publisher": PUBLISHER, "source": SOURCE, "release": "fixture-v1", "commit": commit,
               "model_sha256": _hash(model), "model_card_sha256": _hash(card)}
    return release, model, card


def _key(lab, work, name):
    key, pub = work / f"{name}.key", work / f"{name}.pub"
    lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                "-out", str(key), timeout=25)
    lab.command("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub))
    return key, pub.read_bytes()


def _signed(lab, work, key, release):
    payload, signature = work / "sign-input", work / "sign-output"
    payload.write_bytes(_canonical(release))
    lab.command("openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(payload))
    return signature.read_bytes()


def _intake(lab, name, release, model, card, signature, *, mode="guarded"):
    inputs = {"release.json": _canonical(release), "model.json": model, "model-card.json": card}
    if signature is not None:
        inputs["release.sig"] = signature
    _cm(lab, name, inputs, binary=True)
    mounts = [{"name": mount, "mountPath": f"/{mount}", "readOnly": True}
              for mount in ("input", "trust", "scripts")]
    volumes = [{"name": mount, "configMap": {"name": config}}
               for mount, config in (("input", name), ("trust", "release-trust"), ("scripts", "intake-code"))]
    container = {"name": "intake", "image": OPENSSL, "command": ["/bin/sh", "/scripts/intake", mode],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                 "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                               "limits": {"cpu": "150m", "memory": "64Mi"}}, "volumeMounts": mounts}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 55,
                         "template": {"spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                               "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                                   "seccompProfile": {"type": "RuntimeDefault"}},
                                               "containers": [container], "volumes": volumes}}}})
    end = time.monotonic() + 65
    while time.monotonic() < end:
        observed = json.loads(lab.kubectl("get", "job/" + name, "-o", "json").stdout)
        states = {r["type"] for r in observed.get("status", {}).get("conditions", []) if r["status"] == "True"}
        if "Complete" in states or "Failed" in states:
            output = lab.kubectl("logs", "job/" + name).stdout.strip()
            return "Complete" in states, output
        time.sleep(0.5)
    lab.block(f"Intake Job {name} did not reach a terminal state")


def run(lab):
    with tempfile.TemporaryDirectory(prefix="fixture-origin-", dir=lab.kubeconfig.parent) as folder:
        work = Path(folder)
        release, model, card = _release(lab, work)
        trusted, public = _key(lab, work, "trusted-publisher")
        other, other_public = _key(lab, work, "unrelated-publisher")
        if public == other_public:
            lab.block("The trusted and unrelated fixture keys are identical")
        signature = _signed(lab, work, trusted, release)
        wrong_signature = _signed(lab, work, other, release)
        wrong_release = {**release, "publisher": "urn:saf:fixture:publisher:unrelated"}
        wrong_metadata_signature = _signed(lab, work, trusted, wrong_release)

    trust = {"publisher.pub": public, "exact-release.json": _canonical(release),
             "content.sha256": (f"{_hash(model)}  model.json\n{_hash(card)}  model-card.json\n").encode()}
    _cm(lab, "release-trust", trust, binary=True)
    _cm(lab, "intake-code", {"intake": PROGRAM})
    off, red_marker = _intake(lab, "unchecked-intake", release, model, card, None, mode="unchecked")
    lab.check("red", "The same unsigned release crosses the intake approval boundary with verification disabled",
              off and red_marker == "APPROVED_WITHOUT_PROVENANCE", {"accepted_with_no_signature": off})
    for name, presented, presented_model, presented_card, sig, expected in (
        ("unknown-signature", release, model, card, wrong_signature, "provenance-signature-untrusted"),
        ("missing-signature", release, model, card, None, "provenance-signature-missing"),
        ("publisher-metadata", wrong_release, model, card, wrong_metadata_signature, "provenance-release-mismatch"),
        ("changed-model", release, model + b"\n", card, signature, "provenance-content-mismatch"),
        ("changed-card", release, model, card + b"\n", signature, "provenance-content-mismatch"),
    ):
        accepted, output = _intake(lab, name, presented, presented_model, presented_card, sig)
        lab.check("green", f"Intake rejects the {name} fixture with its expected decision marker",
                  not accepted and output == expected, {"approved": accepted, "expected_rejection": output == expected})
    approved, result = _intake(lab, "verified-approval", release, model, card, signature)
    parts = result.splitlines()
    valid = approved and len(parts) == 2 and parts[0] == "APPROVED_WITH_VERIFIED_PROVENANCE"
    if not valid or json.loads(parts[-1]) != release:
        lab.block("Verified intake did not produce the exact reviewed release")
    stored = _cm(lab, "release-approval", {"disposition": "approved", "reviewed-release.json": parts[1]})
    lab.check("positive", "The stored approval binds the trusted publisher, source commit, release and model and card hashes",
              stored["immutable"] and json.loads(stored["data"]["reviewed-release.json"]) == release,
              {"publisher": PUBLISHER, "source": SOURCE, "commit": release["commit"],
               "release": release["release"], "model_and_card_verified": True})
    (lab.evidence / "publisher-provenance.json").write_text(json.dumps(
        {"approved_release": release, "fixture_verifier": OPENSSL, "checks": lab.checks}, indent=2) + "\n")
