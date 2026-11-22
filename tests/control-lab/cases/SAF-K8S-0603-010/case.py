"""Verify a signed CycloneDX claim against locally generated OCI image digests."""
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import time
import uuid


HERE = Path(__file__).parent
IMAGE = (
    "docker.io/alpine/openssl:3.3.2@sha256:"
    "5008e829163320a6e8166883c03e68189e8925ade68cde36584dc2a41cfa5248"
)
PARSER_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
NAMESPACE = "saf-test"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
CYCLONEDX_PREDICATE = "https://cyclonedx.org/bom"
SCOPE = (
    "One fresh local Kubernetes v1.36.1 Kind cluster. The case creates two distinct, "
    "case-owned OCI image layouts in a temporary directory from inert synthetic config and "
    "layer bytes; it computes each OCI image-manifest digest from the serialized manifest. "
    "A CycloneDX 1.6 fixture SBOM is generated from package metadata read out of each "
    "verified OCI layer, wrapped in an in-toto Statement v1 and signed with one ephemeral RSA "
    "key. A Kubernetes verifier Job independently verifies the DSSE signature and recomputes "
    "the supplied OCI manifest digest. One Job accepts the approved image's exact subject; "
    "another verifies a valid claim from the same signer for the second image and rejects its "
    "different subject against the approved digest. A disposable loopback TLS OCI registry "
    "stores the same two images and attaches only the approved image's exact signed statement. "
    "The case verifies discovery, digest-scoped retrieval, signature, and cleanup."
)


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _descriptor(media_type, content):
    return {"mediaType": media_type, "digest": "sha256:" + _sha256(content),
            "size": len(content)}


def _layer_tar(fixture):
    raw = io.BytesIO()
    files = {"etc/saf-fixture-release": fixture["release_marker"].encode("utf-8"),
             "var/lib/saf-fixture/packages.json": _json_bytes(fixture["components"])}
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mode = 0o444
            item.uid = item.gid = 0
            item.uname = item.gname = "root"
            item.mtime = 0
            archive.addfile(item, io.BytesIO(data))
    return raw.getvalue()


def _oci_image(name, fixture, root):
    """Write a small OCI Image Layout containing one valid, inert image manifest."""
    image_root = root / name
    blobs = image_root / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    raw_layer = _layer_tar(fixture)
    layer = gzip.compress(raw_layer, mtime=0)
    config = _json_bytes({
        "architecture": "amd64",
        "config": {"User": "65532:65532"},
        "created": "2026-01-01T00:00:00Z",
        "history": [{"created": "2026-01-01T00:00:00Z",
                     "created_by": "SAF-K8S-0603-010 inert fixture"}],
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + _sha256(raw_layer)]},
    })
    manifest = _json_bytes({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": _descriptor("application/vnd.oci.image.config.v1+json", config),
        "layers": [_descriptor("application/vnd.oci.image.layer.v1.tar+gzip", layer)],
    })
    for content in (layer, config, manifest):
        (blobs / _sha256(content)).write_bytes(content)
    digest = "sha256:" + _sha256(manifest)
    image_root.joinpath("oci-layout").write_bytes(_json_bytes({"imageLayoutVersion": "1.0.0"}))
    image_root.joinpath("index.json").write_bytes(_json_bytes({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            **_descriptor("application/vnd.oci.image.manifest.v1+json", manifest),
            "platform": {"architecture": "amd64", "os": "linux"},
            "annotations": {"org.opencontainers.image.ref.name": name},
        }],
    }))
    return {"name": name, "digest": digest, "manifest": manifest,
            "manifest_sha256": _sha256(manifest), "layout": image_root}


def _inventory(image):
    manifest = json.loads(image["manifest"])
    digest = manifest["layers"][0]["digest"].removeprefix("sha256:")
    blob = image["layout"] / "blobs" / "sha256" / digest
    with tarfile.open(blob, "r:gz") as archive:
        entries = [entry for entry in archive.getmembers()
                   if entry.name == "var/lib/saf-fixture/packages.json" and entry.isfile()]
        if len(entries) != 1:
            raise ValueError("Fixture image has no unique package inventory")
        with archive.extractfile(entries[0]) as contents:
            return json.load(contents)


def _cyclonedx_sbom(name, image_digest, inventory):
    """Generate a CycloneDX document from package metadata in the verified OCI layer."""
    components = []
    dependencies = []
    for index, source in enumerate(inventory, start=1):
        bom_ref = f"urn:saf-k8s:0603-010:{name}:component:{index}"
        components.append({**source, "bom-ref": bom_ref})
        dependencies.append({"ref": bom_ref, "dependsOn": []})
    image_ref = f"urn:saf-k8s:0603-010:{name}:image"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {"bom-ref": image_ref, "type": "container",
                          "name": name, "version": "1.0.0",
                          "externalReferences": [{"type": "distribution",
                              "url": f"oci://saf-k8s-control-lab/{name}@{image_digest}"}]},
            "properties": [{"name": "saf-k8s:fixture-image-manifest-digest",
                            "value": image_digest},
                           {"name": "saf-k8s:sbom-inventory-source",
                            "value": "package manifest in verified OCI layer"}],
        },
        "components": components,
        "dependencies": [{"ref": image_ref,
                          "dependsOn": [item["bom-ref"] for item in components]},
                         *dependencies],
    }


def _statement(image_name, image_digest, sbom):
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": f"oci://saf-k8s-control-lab/{image_name}",
                     "digest": {"sha256": image_digest.removeprefix("sha256:")}}],
        "predicateType": CYCLONEDX_PREDICATE,
        "predicate": sbom,
    }


def _pae(payload):
    payload_type = PAYLOAD_TYPE.encode("ascii")
    return (b"DSSEv1 " + str(len(payload_type)).encode("ascii") + b" " + payload_type + b" "
            + str(len(payload)).encode("ascii") + b" " + payload)


def _sign(lab, work, label, statement, key):
    payload = _json_bytes(statement)
    payload_path = work / f"{label}.statement.json"
    pae_path = work / f"{label}.pae"
    signature_path = work / f"{label}.sig"
    public_path = work / "authorized-signer.pub"
    payload_path.write_bytes(payload)
    pae_path.write_bytes(_pae(payload))
    if not key.exists():
        lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                    "rsa_keygen_bits:2048", "-out", str(key), timeout=30)
        lab.command("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public_path))
    lab.command("openssl", "dgst", "-sha256", "-sign", str(key), "-out",
                str(signature_path), str(pae_path))
    return {"payload": payload, "signature": signature_path.read_bytes(),
            "public": public_path.read_bytes()}


SUBJECT_PARSER = """import json
from pathlib import Path

statement = json.loads(Path('/verify/statement.json').read_bytes())
if (statement['_type'] != 'https://in-toto.io/Statement/v1'
        or statement['predicateType'] != 'https://cyclonedx.org/bom'
        or statement['predicate']['bomFormat'] != 'CycloneDX'
        or len(statement['subject']) != 1):
    raise ValueError('Unexpected signed SBOM statement shape')
Path('/work/subject-sha256').write_text(statement['subject'][0]['digest']['sha256'], encoding='ascii')
"""


def _verifier_script():
    return r"""#!/bin/sh
set -eu
cd /verify
actual_manifest=$(sha256sum image-manifest.json | awk '{print $1}')
expected_manifest=$(cat expected-manifest-sha256)
if [ "$actual_manifest" != "$expected_manifest" ]; then
  echo 'oci-manifest-digest-rejected'
  exit 21
fi
echo "oci-manifest-digest-verified sha256:$actual_manifest"
payload_type='application/vnd.in-toto+json'
type_length=$(printf %s "$payload_type" | wc -c | tr -d ' ')
payload_length=$(wc -c < statement.json | tr -d ' ')
{
  printf 'DSSEv1 %s %s %s ' "$type_length" "$payload_type" "$payload_length"
  cat statement.json
} > /work/statement.pae
if ! openssl dgst -sha256 -verify /trust/signer.pub -signature statement.sig /work/statement.pae; then
  echo 'sbom-signature-rejected'
  exit 22
fi
echo 'sbom-signature-verified'
expected_subject=$(cat approved-subject-sha256)
signed_subject=$(cat /work/subject-sha256)
if [ "$signed_subject" = "$expected_subject" ] && [ "$signed_subject" = "$actual_manifest" ]; then
  echo "approved-sbom-subject-verified sha256:$expected_subject"
else
  echo "sbom-subject-mismatch expected sha256:$expected_subject"
  exit 23
fi
"""


def _job(name, image, signed, approved_digest):
    files = {
        "run.sh": _verifier_script().encode("utf-8"),
        "parse.py": SUBJECT_PARSER.encode("utf-8"),
        "image-manifest.json": image["manifest"],
        "statement.json": signed["payload"],
        "statement.sig": signed["signature"],
        "expected-manifest-sha256": image["manifest_sha256"].encode("ascii"),
        "approved-subject-sha256": approved_digest.removeprefix("sha256:").encode("ascii"),
    }
    cm_name = name + "-data"
    cm = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": cm_name, "namespace": NAMESPACE},
        "immutable": True,
        "binaryData": {key: base64.b64encode(value).decode("ascii")
                       for key, value in files.items()
                       if key in {"statement.sig", "image-manifest.json"}},
        "data": {key: value.decode("utf-8") for key, value in files.items()
                 if key not in {"statement.sig", "image-manifest.json"}},
    }
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "backoffLimit": 0, "activeDeadlineSeconds": 90,
            "ttlSecondsAfterFinished": 300,
            "template": {"metadata": {"labels": {"app": "saf-0603-010-verifier"}},
                         "spec": {
                "restartPolicy": "Never", "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                    "fsGroup": 1000,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "initContainers": [{
                    "name": "parse", "image": PARSER_IMAGE, "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "-B", "/verify/parse.py"],
                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                  "limits": {"cpu": "100m", "memory": "64Mi"}},
                    "securityContext": {"allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "fixture", "mountPath": "/verify", "readOnly": True},
                                     {"name": "work", "mountPath": "/work"}],
                }],
                "containers": [{
                    "name": "verify", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                    "command": ["/bin/sh", "/verify/run.sh"],
                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                  "limits": {"cpu": "100m", "memory": "64Mi"}},
                    "securityContext": {"allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "fixture", "mountPath": "/verify", "readOnly": True},
                                     {"name": "trust", "mountPath": "/trust", "readOnly": True},
                                     {"name": "work", "mountPath": "/work"}],
                }],
                "volumes": [{"name": "fixture", "configMap": {"name": cm_name,
                                                                     "defaultMode": 292}},
                            {"name": "trust", "configMap": {
                                "name": "saf-0603-010-authorized-signer",
                                "defaultMode": 292}},
                            {"name": "work", "emptyDir": {"sizeLimit": "1Mi"}}],
            }},
        },
    }
    return cm, job


def _wait_job(lab, name):
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        obj = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {item.get("type"): item.get("status")
                      for item in obj.get("status", {}).get("conditions", [])}
        if conditions.get("Complete") == "True":
            return "complete"
        if conditions.get("Failed") == "True":
            return "failed"
        time.sleep(0.5)
    lab.block(f"Verifier Job {name} did not finish")


def _run_verifier(lab, name, image, signed, approved_digest):
    cm, job = _job(name, image, signed, approved_digest)
    lab.create(cm)
    lab.create(job)
    state = _wait_job(lab, name)
    pods = json.loads(lab.kubectl("get", "pods", "-l", "job-name=" + name,
                                  "-o", "json").stdout)
    pod_name = pods["items"][0]["metadata"]["name"] if pods.get("items") else None
    if not pod_name:
        lab.block(f"Verifier Job {name} has no Pod evidence")
    logs = lab.kubectl("logs", pod_name, allow_failure=True)
    return state, logs.stdout + logs.stderr


def _validate_layout(image):
    layout = image["layout"]
    manifest = json.loads(image["manifest"])
    layout_version = json.loads((layout / "oci-layout").read_bytes())
    if layout_version.get("imageLayoutVersion") != "1.0.0":
        raise ValueError("OCI layout version mismatch")
    if manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise ValueError("OCI manifest media type mismatch")
    index = json.loads((layout / "index.json").read_bytes())
    descriptor = index["manifests"][0]
    if descriptor["digest"] != image["digest"] or descriptor["size"] != len(image["manifest"]):
        raise ValueError("OCI index does not identify the generated manifest")
    manifest_blob = (layout / "blobs" / "sha256" / image["manifest_sha256"]).read_bytes()
    if manifest_blob != image["manifest"]:
        raise ValueError("OCI layout manifest blob differs from the digest-bound bytes")
    for descriptor in [manifest["config"], *manifest["layers"]]:
        algorithm, digest = descriptor["digest"].split(":", 1)
        if algorithm != "sha256":
            raise ValueError("Fixture OCI blob uses an unsupported digest algorithm")
        content = (layout / "blobs" / algorithm / digest).read_bytes()
        if _sha256(content) != digest or len(content) != descriptor["size"]:
            raise ValueError("OCI blob descriptor mismatch")


def run(lab):
    server = json.loads(lab.kubectl("get", "--raw=/version").stdout).get("gitVersion")
    lab.check("positive", "Disposable API server is Kubernetes v1.36.1",
              server == "v1.36.1", {"server": server})
    fixture = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
    if fixture.get("format") != "saf-k8s-0603-010-fixtures-v1":
        lab.block("Unexpected 0603-010 fixture format")
    with tempfile.TemporaryDirectory(prefix="saf-0603-010-") as directory:
        work = Path(directory)
        images = {name: _oci_image(name, value, work / "oci")
                  for name, value in fixture["images"].items()}
        for image in images.values():
            _validate_layout(image)
        approved_name = fixture["approved"]
        approved = images[approved_name]
        other_name = next(name for name in images if name != approved_name)
        other = images[other_name]
        if approved["digest"] == other["digest"]:
            lab.block("Independent OCI fixtures unexpectedly share a manifest digest")
        lab.check("positive", "Two case-owned OCI image manifests have distinct computed digests",
                  True, {"approved_manifest_digest": approved["digest"],
                         "other_manifest_digest": other["digest"],
                         "distinct": approved["digest"] != other["digest"]})

        signing_key = work / "authorized-signer.key"
        signed_claims = {}
        for name, image in ((approved_name, approved), (other_name, other)):
            inventory = _inventory(image)
            sbom = _cyclonedx_sbom(name, image["digest"], inventory)
            expected = fixture["images"][name]["components"]
            observed = [{field: component[field] for field in ("name", "version", "type")}
                        for component in sbom["components"]]
            lab.check("positive", f"CycloneDX evidence matches the package inventory in {name}",
                      observed == inventory == expected,
                      {"components": observed, "source_is_verified_oci_layer": True})
            statement = _statement(name, image["digest"], sbom)
            signed_claims[name] = _sign(lab, work, name, statement, signing_key)
        if signed_claims[approved_name]["public"] != signed_claims[other_name]["public"]:
            lab.block("SBOM claims do not share the authorized fixture signer")
        signer_cm = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "saf-0603-010-authorized-signer", "namespace": NAMESPACE},
            "data": {"signer.pub": signed_claims[approved_name]["public"].decode("ascii")},
        }
        lab.create(signer_cm)

        accepted, accepted_log = _run_verifier(
            lab, "saf-0603-010-approved", approved, signed_claims[approved_name],
            approved["digest"])
        lab.check("green", "Independent Kubernetes verifier accepts the signed SBOM for the approved OCI manifest digest",
                  accepted == "complete"
                  and "oci-manifest-digest-verified" in accepted_log
                  and "sbom-signature-verified" in accepted_log
                  and "approved-sbom-subject-verified" in accepted_log,
                  {"job": accepted,
                   "manifest_digest_recomputed": "oci-manifest-digest-verified" in accepted_log,
                   "signature_verified": "sbom-signature-verified" in accepted_log,
                   "subject_matched": "approved-sbom-subject-verified" in accepted_log})

        rejected, rejected_log = _run_verifier(
            lab, "saf-0603-010-other-subject", other, signed_claims[other_name],
            approved["digest"])
        same_signer = signed_claims[approved_name]["public"] == signed_claims[other_name]["public"]
        lab.check("red", "Valid SBOM claim from the same signer for the other image digest fails exact approved-subject comparison",
                  rejected == "failed" and same_signer
                  and "oci-manifest-digest-verified" in rejected_log
                  and "sbom-signature-verified" in rejected_log
                  and "sbom-subject-mismatch" in rejected_log,
                  {"job": rejected, "same_authorized_signer": same_signer,
                   "other_manifest_digest": other["digest"],
                   "counterfactual_claim_subject_digest": other["digest"],
                   "approved_manifest_digest": approved["digest"],
                   "signature_verified_before_subject_rejection":
                       "sbom-signature-verified" in rejected_log,
                   "subject_mismatch": "sbom-subject-mismatch" in rejected_log})

        path = HERE / "registry-referrers" / "fixture.py"
        spec = importlib.util.spec_from_file_location("sbom_registry_referrers", path)
        registry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(registry)
        registry.verify(lab, work, approved, other, signed_claims[approved_name])
