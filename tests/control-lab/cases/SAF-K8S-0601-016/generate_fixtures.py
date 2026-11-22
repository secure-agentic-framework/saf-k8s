"""Regenerate synthetic image metadata and signed provenance fixtures locally."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
APPROVED_BASE = "a" * 64
UNAPPROVED_BASE = "b" * 64
PAYLOAD_TYPE = "application/vnd.in-toto+json"


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def signed_envelope(openssl, private_key, image_digest, base_digest):
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "synthetic.local/app", "digest": {"sha256": image_digest.removeprefix("sha256:")}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://synthetic.invalid/build-types/oci-image/v1",
                "externalParameters": {"source": "fixture://synthetic/source"},
                "resolvedDependencies": [{
                    "name": "base-image", "uri": "oci://synthetic.local/base",
                    "digest": {"sha256": base_digest},
                }],
            },
            "runDetails": {"builder": {"id": "https://synthetic.invalid/builder/release-v1"}},
        },
    }
    payload = compact(statement)
    pae = (b"DSSEv1 " + str(len(PAYLOAD_TYPE)).encode() + b" " + PAYLOAD_TYPE.encode() +
           b" " + str(len(payload)).encode() + b" " + payload)
    with tempfile.TemporaryDirectory(prefix="saf-0601-016-sign-") as temp:
        data_path = Path(temp) / "pae.bin"
        signature_path = Path(temp) / "signature.bin"
        data_path.write_bytes(pae)
        result = subprocess.run(
            [openssl, "dgst", "-sha256", "-sign", str(private_key), "-out",
             str(signature_path), str(data_path)], capture_output=True, text=True, timeout=10,
        )
        if result.returncode:
            raise RuntimeError("OpenSSL could not sign synthetic fixture: " + result.stderr)
        signature = signature_path.read_bytes()
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": "synthetic-lab-builder-v1",
                        "sig": base64.b64encode(signature).decode("ascii")}],
    }


def main():
    import shutil
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("OpenSSL is required to generate the synthetic signatures")
    config = {
        "architecture": "amd64", "os": "linux",
        "config": {"Labels": {"org.opencontainers.image.title": "synthetic-control-lab-image"}},
        "rootfs": {"type": "layers", "diff_ids": []},
        "history": [
            {"created_by": "FROM synthetic.local/base@sha256:" + APPROVED_BASE,
             "empty_layer": True},
            {"created_by": "COPY synthetic fixture", "empty_layer": True},
        ],
    }
    config_bytes = compact(config)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": sha256(config_bytes), "size": len(config_bytes)},
        "layers": [],
    }
    image = {"synthetic": True, "manifest": manifest, "config": config}
    image_digest = sha256(compact(manifest))
    (HERE / "image.json").write_text(json.dumps(image, indent=2) + "\n", encoding="utf-8")
    (HERE / "allowlist.json").write_text(json.dumps({
        "format": "synthetic-local-policy-v1",
        "approved_base_digests": [
            "sha256:" + APPROVED_BASE,
            "sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec",
        ],
        "approved_final_image_digests": [image_digest],
    }, indent=2) + "\n", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="saf-0601-016-keygen-") as temp:
        private_key = Path(temp) / "synthetic-private.pem"
        public_key = HERE / "trusted-builder.pub"
        result = subprocess.run(
            [openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", str(private_key)], capture_output=True, text=True, timeout=20,
        )
        if result.returncode:
            raise RuntimeError("OpenSSL could not generate temporary fixture key: " + result.stderr)
        result = subprocess.run(
            [openssl, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode:
            raise RuntimeError("OpenSSL could not export fixture public key: " + result.stderr)
        for name, base_digest in (("provenance-approved.json", APPROVED_BASE),
                                  ("provenance-unapproved-base.json", UNAPPROVED_BASE)):
            envelope = signed_envelope(openssl, private_key, image_digest, base_digest)
            (HERE / name).write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")

    approved = json.loads((HERE / "provenance-approved.json").read_text(encoding="utf-8"))
    payload = base64.b64decode(approved["payload"])
    tampered_payload = payload.replace(APPROVED_BASE.encode(), UNAPPROVED_BASE.encode(), 1)
    if tampered_payload == payload:
        raise RuntimeError("Could not create tampered synthetic provenance payload")
    approved["payload"] = base64.b64encode(tampered_payload).decode("ascii")
    (HERE / "provenance-tampered.json").write_text(
        json.dumps(approved, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
