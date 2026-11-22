"""Validate an exact base digest allowlist using synthetic signed provenance."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
SCOPE = (
    "Build a local OCI artifact from a digest-pinned public base, verify manifest-to-"
    "attestation descriptor linkage and read the resolved base reported by BuildKit. "
    "A second synthetic case verifies trusted-key DSSE, subject digest binding and "
    "an exact approved base allowlist. No image is published. This case covers local "
    "build evidence and the verification mechanism. Production builder identities, "
    "provenance ingestion and runtime admission integration require their own checks."
)
BUILD_BASE = "sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


class Rejected(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def final_image_digest(image):
    manifest = image["manifest"]
    config_bytes = canonical(image["config"])
    descriptor = manifest["config"]
    if descriptor["digest"] != sha256(config_bytes) or descriptor["size"] != len(config_bytes):
        raise Rejected("final image config descriptor mismatch")
    if manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise Rejected("unexpected manifest media type")
    return sha256(canonical(manifest))


def dsse_pae(payload_type, payload):
    # DSSE v1 pre-authentication encoding: PAE(type, body).
    return (b"DSSEv1 " + str(len(payload_type.encode())).encode() + b" " +
            payload_type.encode() + b" " + str(len(payload)).encode() + b" " + payload)


def signature_valid(envelope, public_key):
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        return False
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        signatures = envelope["signatures"]
        if len(signatures) != 1 or signatures[0].get("keyid") != "synthetic-lab-builder-v1":
            return False
        signature = base64.b64decode(signatures[0]["sig"], validate=True)
    except (KeyError, TypeError, ValueError):
        return False
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("OpenSSL is required to verify the synthetic detached signature")
    with tempfile.TemporaryDirectory(prefix="saf-0601-016-verify-") as temp:
        root = Path(temp)
        data_path = root / "pae.bin"
        signature_path = root / "signature.bin"
        data_path.write_bytes(dsse_pae(PAYLOAD_TYPE, payload))
        signature_path.write_bytes(signature)
        result = subprocess.run(
            [openssl, "dgst", "-sha256", "-verify", str(public_key), "-signature",
             str(signature_path), str(data_path)], capture_output=True, text=True, timeout=10,
        )
    return result.returncode == 0


def verified_base_digest(envelope, public_key, expected_image_digest):
    if not signature_valid(envelope, public_key):
        raise Rejected("provenance signature invalid or signer key id untrusted")
    payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
    if payload.get("_type") != STATEMENT_TYPE or payload.get("predicateType") != PREDICATE_TYPE:
        raise Rejected("unexpected attestation statement or predicate type")
    subjects = payload.get("subject", [])
    if not any(subject.get("digest", {}).get("sha256") == expected_image_digest.removeprefix("sha256:")
               for subject in subjects):
        raise Rejected("provenance subject does not bind the final image digest")
    predicate = payload.get("predicate", {})
    builder = predicate.get("runDetails", {}).get("builder", {}).get("id")
    if builder != "https://synthetic.invalid/builder/release-v1":
        raise Rejected("builder identity is not on the local trust policy")
    dependencies = predicate.get("buildDefinition", {}).get("resolvedDependencies", [])
    bases = [item.get("digest", {}).get("sha256") for item in dependencies
             if item.get("name") == "base-image"]
    if len(bases) != 1 or not bases[0]:
        raise Rejected("provenance must identify exactly one base-image digest")
    return "sha256:" + bases[0]


def require_approved_base(envelope, public_key, image_digest, approved_bases):
    base_digest = verified_base_digest(envelope, public_key, image_digest)
    if base_digest not in approved_bases:
        raise Rejected("base image digest is not in the approved base digest allowlist")
    return base_digest


def expect_reject(action, reason):
    try:
        action()
    except Rejected as error:
        if reason not in str(error):
            raise AssertionError(f"wrong rejection reason: expected {reason!r}; got {error!r}")
        return str(error)
    raise AssertionError(f"case unexpectedly accepted input; expected rejection: {reason}")


def live_material(lab, approved_bases):
    node = f"{lab.cluster}-control-plane"
    architecture = lab.kubectl("get", f"node/{node}",
                               "-o", "jsonpath={.status.nodeInfo.architecture}").stdout.strip()
    if architecture not in ("amd64", "arm64"):
        lab.block("The pinned base proof covers Linux arm64 and amd64")
    with tempfile.TemporaryDirectory(prefix="saf-0601-016-build-") as temporary:
        root = Path(temporary)
        context = root / "context"
        context.mkdir()
        image = root / "built-image.tar"
        (context / "Dockerfile").write_text(
            f"FROM docker.io/library/busybox:1.37.0@{BUILD_BASE}\n"
            'LABEL org.opencontainers.image.title="SAF synthetic local verification image"\n'
        )
        lab.command("docker", "buildx", "build", "--network", "none",
                    "--platform", f"linux/{architecture}", "--provenance=mode=max,version=v1",
                    "--output", f"type=oci,dest={image}", str(context), timeout=180)
        with tarfile.open(image) as archive:
            def member(path):
                stream = archive.extractfile(path)
                if stream is None:
                    lab.block("OCI archive member is not a file")
                return stream.read()

            def descriptor(entry):
                digest = entry["digest"]
                raw = member("blobs/sha256/" + digest.removeprefix("sha256:"))
                if sha256(raw) != digest or entry["size"] != len(raw):
                    lab.block("BuildKit OCI descriptor digest or size did not match its bytes")
                return json.loads(raw)

            outer, = json.loads(member("index.json"))["manifests"]
            descriptors = descriptor(outer)["manifests"]
            platform = {"architecture": architecture, "os": "linux"}
            workload, = [entry for entry in descriptors if entry.get("platform") == platform]
            descriptor(workload)
            attestation, = [entry for entry in descriptors
                            if entry.get("annotations", {}).get("vnd.docker.reference.type")
                            == "attestation-manifest"]
            linked = attestation["annotations"]["vnd.docker.reference.digest"] == workload["digest"]
            assert linked, "BuildKit provenance did not reference the actual workload descriptor"
            provenance, = descriptor(attestation)["layers"]
            statement = descriptor(provenance)
            definitions = statement["predicate"]["buildDefinition"]
            matches = ["sha256:" + item["digest"]["sha256"]
                       for item in definitions["resolvedDependencies"]
                       if item["uri"].startswith("pkg:docker/busybox@")]
    material_ok = matches == [BUILD_BASE] and BUILD_BASE in approved_bases
    lab.check("positive", "BuildKit links a real local artifact to the exact approved base material",
              linked and material_ok and statement["predicateType"] == PREDICATE_TYPE,
              {"oci_attestation_links_workload_digest": linked,
               "resolved_base_is_approved": material_ok, "base_digest": BUILD_BASE})


def run(lab):
    policy = load_json(HERE / "allowlist.json")
    live_material(lab, set(policy["approved_base_digests"]))
    image = load_json(HERE / "image.json")
    public_key = HERE / "trusted-builder.pub"
    final_digest = final_image_digest(image)
    image_only_policy = set(policy["approved_final_image_digests"])
    base_policy = set(policy["approved_base_digests"])

    # Image metadata may expose a self-asserted FROM-like history string, but is not
    # authenticated build lineage. Require signed provenance to authorize its base.
    lab.check(
        "red", "final OCI metadata alone cannot establish an approved base image",
        final_digest in image_only_policy,
        {"final_digest": final_digest, "history": image["config"].get("history", []),
         "approved_as_final_artifact": final_digest in image_only_policy,
         "claim": "exact final artifact identity is established; base lineage is not"},
    )

    altered_manifest = json.loads(json.dumps(image["manifest"]))
    altered_manifest["annotations"] = {"synthetic.invalid/change": "mutated"}
    altered_final_digest = sha256(canonical(altered_manifest))
    lab.check("red", "unlisted changed final image digest is rejected by exact final-image allowlist",
              altered_final_digest not in image_only_policy,
              {"altered_final_digest": altered_final_digest,
               "approved_final_digests": sorted(image_only_policy)})

    reason = expect_reject(
        lambda: require_approved_base({}, public_key, final_digest, base_policy),
        "signature invalid",
    )
    lab.check("red", "final image digest and self-asserted history cannot replace authenticated provenance",
              "signature invalid" in reason,
              {"final_digest_is_approved": final_digest in image_only_policy,
               "observed": reason})

    approved = load_json(HERE / "provenance-approved.json")
    unapproved = load_json(HERE / "provenance-unapproved-base.json")
    tampered = load_json(HERE / "provenance-tampered.json")

    reason = expect_reject(
        lambda: require_approved_base(approved, public_key, altered_final_digest, base_policy),
        "subject does not bind the final image",
    )
    lab.check("red", "Authentic provenance is rejected when presented for a different image digest",
              "subject does not bind the final image" in reason, {"observed": reason})

    approved_base = require_approved_base(approved, public_key, final_digest, base_policy)
    lab.check(
        "green", "trusted signed provenance binds the final image to the approved base digest",
        approved_base in base_policy,
        {"final_digest": final_digest, "verified_base_digest": approved_base,
         "builder": "https://synthetic.invalid/builder/release-v1"},
    )

    reason = expect_reject(
        lambda: require_approved_base(unapproved, public_key, final_digest, base_policy),
        "not in the approved base digest allowlist",
    )
    lab.check("red", "validly signed provenance naming an unapproved base is denied",
              "not in the approved base digest allowlist" in reason,
              {"observed": reason})

    reason = expect_reject(
        lambda: require_approved_base(tampered, public_key, final_digest, base_policy),
        "signature invalid",
    )
    lab.check("red", "altered provenance payload is denied before trusting its base claim",
              "signature invalid" in reason, {"observed": reason})

    # The same final image is the explicitly permitted workload when authenticated
    # provenance names the one approved base digest.
    lab.check("positive", "permitted final image with approved authenticated base remains allowed",
              final_digest == final_image_digest(image) and approved_base in base_policy,
              {"final_digest": final_digest, "base_digest": approved_base,
               "synthetic_fixture_only": True})
