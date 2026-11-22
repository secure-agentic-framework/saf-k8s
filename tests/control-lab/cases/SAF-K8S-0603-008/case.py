"""Exercise consumed-material and produced-artifact attestations in isolated Jobs."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import time


HERE = Path(__file__).parent
IMAGE = (
    "docker.io/alpine/openssl:3.3.2@sha256:"
    "5008e829163320a6e8166883c03e68189e8925ade68cde36584dc2a41cfa5248"
)
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
NAMESPACE = "saf-test"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
MATERIALS_TYPE = "https://saf-k8s.example.test/attestation/materials/v1"
ARTIFACTS_TYPE = "https://saf-k8s.example.test/attestation/artifacts/v1"
SCOPE = (
    "One fresh local Kubernetes v1.36.1 Kind cluster. A builder Job reads two mounted fixture "
    "materials (source and dependency), normalizes the source into an intermediate product, and "
    "combines that intermediate with the dependency to produce a final artifact. The Job reports "
    "the bytes and SHA-256 digests it actually consumed and produced. The host signs separate "
    "in-toto Statement v1 DSSE payloads for the material set and artifact products using distinct "
    "ephemeral keys. A separate verifier Job checks both signatures and exact expected contents; "
    "a validly signed incomplete materials statement must be rejected. This does not establish "
    "production builder identity, protected key custody, trusted independent evidence generation, "
    "durable storage, or production CI/CD coverage."
)


def _pae(payload_type, payload):
    return (b"DSSEv1 " + str(len(payload_type)).encode("ascii") + b" " + payload_type + b" "
            + str(len(payload)).encode("ascii") + b" " + payload)


def _wait_job(lab, name):
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {c["type"] for c in job.get("status", {}).get("conditions", [])
                      if c.get("status") == "True"}
        if "Complete" in conditions:
            return "complete"
        if "Failed" in conditions:
            return "failed"
        time.sleep(0.5)
    lab.block(f"Job {name} did not reach a terminal condition")


def _builder_script():
    return r"""#!/bin/sh
set -eu
mkdir -p /work
tr -d '\r' < /materials/source.txt > /work/source.normalized
cat /work/source.normalized /materials/dependency.txt > /work/release.txt
printf 'SAF0603008_BUILDER_EVIDENCE_BEGIN\n'
printf 'SOURCE_B64='
base64 /materials/source.txt | tr -d '\n'
printf '\nDEPENDENCY_B64='
base64 /materials/dependency.txt | tr -d '\n'
printf '\nINTERMEDIATE_B64='
base64 /work/source.normalized | tr -d '\n'
printf '\nARTIFACT_B64='
base64 /work/release.txt | tr -d '\n'
printf '\nSOURCE_SHA256='
sha256sum /materials/source.txt | cut -d ' ' -f 1
printf 'DEPENDENCY_SHA256='
sha256sum /materials/dependency.txt | cut -d ' ' -f 1
printf 'INTERMEDIATE_SHA256='
sha256sum /work/source.normalized | cut -d ' ' -f 1
printf 'ARTIFACT_SHA256='
sha256sum /work/release.txt | cut -d ' ' -f 1
printf 'SAF0603008_BUILDER_EVIDENCE_END\n'
"""


def _builder_resources(fixture):
    cm = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-0603-008-materials", "namespace": NAMESPACE},
        "data": fixture["materials"],
    }
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": "saf-0603-008-builder", "namespace": NAMESPACE},
        "spec": {
            "backoffLimit": 0, "activeDeadlineSeconds": 90,
            "ttlSecondsAfterFinished": 300,
            "template": {"metadata": {"labels": {"app": "saf-0603-008-builder"}}, "spec": {
                "restartPolicy": "Never", "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                    "fsGroup": 1000,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "builder", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                    "command": ["/bin/sh", "-c", _builder_script()],
                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                  "limits": {"cpu": "100m", "memory": "64Mi"}},
                    "securityContext": {"allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "materials", "mountPath": "/materials", "readOnly": True},
                                     {"name": "work", "mountPath": "/work"}],
                }],
                "volumes": [{"name": "materials", "configMap": {"name": "saf-0603-008-materials",
                                                                     "defaultMode": 292}},
                            {"name": "work", "emptyDir": {"sizeLimit": "1Mi"}}],
            }},
        },
    }
    return cm, job


def _verifier_script():
    return """#!/bin/sh
set -eu
cd /verify
verify_signature() {
  prefix="$1"
  payload="$prefix.json"
  type_length=$(printf %s 'application/vnd.in-toto+json' | wc -c | tr -d ' ')
  payload_length=$(wc -c < "$payload" | tr -d ' ')
  {
    printf 'DSSEv1 %s %s %s ' "$type_length" 'application/vnd.in-toto+json' "$payload_length"
    cat "$payload"
  } > "/work/$prefix.pae"
  openssl dgst -sha256 -verify "$prefix.pub" -signature "$prefix.sig" "/work/$prefix.pae" >/dev/null
}
verify_signature materials
verify_signature artifacts
echo 'both-independent-signatures-verified'
actual_artifact=$(sha256sum release.txt | cut -d ' ' -f 1)
actual_intermediate=$(sha256sum source.normalized | cut -d ' ' -f 1)
if [ "$actual_artifact" != "$(cat expected-artifact-sha256)" ] || \
   [ "$actual_intermediate" != "$(cat expected-intermediate-sha256)" ]; then
  echo 'produced-artifact-or-intermediate-mismatch'
  exit 24
fi
actual_materials=$(sha256sum materials.json | cut -d ' ' -f 1)
if [ "$actual_materials" != "$(cat expected-materials-payload-sha256)" ]; then
  echo 'materials-completeness-rejected'
  exit 25
fi
actual_artifacts=$(sha256sum artifacts.json | cut -d ' ' -f 1)
if [ "$actual_artifacts" != "$(cat expected-artifacts-payload-sha256)" ]; then
  echo 'artifact-products-mismatch'
  exit 26
fi
echo 'materials-artifacts-and-observed-products-verified'
"""


def _statement(subject, digest, predicate_type, predicate):
    return {"_type": STATEMENT_TYPE,
            "subject": [{"name": subject, "digest": {"sha256": digest}}],
            "predicateType": predicate_type,
            "predicate": predicate}


def _canonical(statement):
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(lab, work, label, statement, *, signing_key=None):
    payload = _canonical(statement)
    key = signing_key or work / f"{label}.key"
    public = work / f"{label}.pub"
    signature = work / f"{label}.sig"
    pae = work / f"{label}.pae"
    pae.write_bytes(_pae(PAYLOAD_TYPE.encode("ascii"), payload))
    if signing_key is None:
        lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(key), timeout=20)
    lab.command("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public))
    lab.command("openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(pae))
    return {"payload": payload, "signature": signature.read_bytes(),
            "public": public.read_bytes(), "key": key,
            "payload_sha256": hashlib.sha256(payload).hexdigest()}


def _run_verifier(lab, name, signed, products, *, expected_materials_hash, expected_artifacts_hash):
    files = {
        "run.sh": _verifier_script().encode(),
        "materials.json": signed["materials"]["payload"],
        "materials.sig": signed["materials"]["signature"],
        "materials.pub": signed["materials"]["public"],
        "artifacts.json": signed["artifacts"]["payload"],
        "artifacts.sig": signed["artifacts"]["signature"],
        "artifacts.pub": signed["artifacts"]["public"],
        "release.txt": products["artifact"],
        "source.normalized": products["intermediate"],
        "expected-artifact-sha256": products["artifact_sha256"].encode("ascii"),
        "expected-intermediate-sha256": products["intermediate_sha256"].encode("ascii"),
        "expected-materials-payload-sha256": expected_materials_hash.encode("ascii"),
        "expected-artifacts-payload-sha256": expected_artifacts_hash.encode("ascii"),
    }
    cm_name = name + "-data"
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": cm_name, "namespace": NAMESPACE},
          "binaryData": {key: base64.b64encode(value).decode("ascii") for key, value in files.items()
                         if key.endswith((".sig", ".txt", ".normalized"))},
          "data": {key: value.decode("utf-8") for key, value in files.items()
                   if not key.endswith((".sig", ".txt", ".normalized"))}}
    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                 "ttlSecondsAfterFinished": 300,
                 "template": {"metadata": {"labels": {"app": "saf-0603-008-verifier"}}, "spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                         "fsGroup": 1000,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "verify", "image": IMAGE,
                                      "imagePullPolicy": "IfNotPresent",
                                      "command": ["/bin/sh", "/verify/run.sh"],
                                      "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                    "limits": {"cpu": "100m", "memory": "64Mi"}},
                                      "securityContext": {"allowPrivilegeEscalation": False,
                                                          "readOnlyRootFilesystem": True,
                                                          "capabilities": {"drop": ["ALL"]}},
                                      "volumeMounts": [{"name": "fixture", "mountPath": "/verify", "readOnly": True},
                                                       {"name": "work", "mountPath": "/work"}]}],
                     "volumes": [{"name": "fixture", "configMap": {"name": cm_name,
                                                                        "defaultMode": 292}},
                                 {"name": "work", "emptyDir": {"sizeLimit": "1Mi"}}],
                 }},
        },
    }
    lab.create(cm)
    lab.create(job)
    state = _wait_job(lab, name)
    pods = json.loads(lab.kubectl("get", "pods", "-l", "job-name=" + name, "-o", "json").stdout)
    pod_name = pods["items"][0]["metadata"]["name"] if pods.get("items") else None
    if not pod_name:
        lab.block(f"Verifier Job {name} has no Pod evidence")
    logs = lab.kubectl("logs", pod_name, allow_failure=True)
    return state, logs.stdout + logs.stderr


def _parse_builder_evidence(log):
    start, end = "SAF0603008_BUILDER_EVIDENCE_BEGIN", "SAF0603008_BUILDER_EVIDENCE_END"
    if start not in log or end not in log:
        raise ValueError("builder Job did not emit its bounded evidence record")
    body = log.split(start, 1)[1].split(end, 1)[0]
    fields = {}
    for line in body.splitlines():
        if "=" in line:
            key, value = line.strip().split("=", 1)
            fields[key] = value
    decoded = {key: base64.b64decode(fields[key], validate=True) for key in
               ("SOURCE_B64", "DEPENDENCY_B64", "INTERMEDIATE_B64", "ARTIFACT_B64")}
    return fields, decoded


def run(lab):
    server = json.loads(lab.kubectl("get", "--raw=/version").stdout).get("gitVersion")
    lab.check("positive", "Disposable API server is Kubernetes v1.36.1", server == "v1.36.1",
              {"server": server})
    fixture = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="saf-0603-008-") as directory:
        work = Path(directory)
        material_cm, builder = _builder_resources(fixture)
        lab.create(material_cm)
        lab.create(builder)
        state = _wait_job(lab, "saf-0603-008-builder")
        pods = json.loads(lab.kubectl("get", "pods", "-l", "job-name=saf-0603-008-builder", "-o", "json").stdout)
        pod_name = pods["items"][0]["metadata"]["name"] if pods.get("items") else None
        if not pod_name:
            lab.block("Builder Job has no Pod evidence")
        result = lab.kubectl("logs", pod_name, allow_failure=True)
        fields, decoded = _parse_builder_evidence(result.stdout + result.stderr)
        lab.check("green", "Isolated builder Job consumes both fixture materials and performs the requested transform",
                  state == "complete" and decoded["SOURCE_B64"] == fixture["materials"]["source.txt"].encode()
                  and decoded["DEPENDENCY_B64"] == fixture["materials"]["dependency.txt"].encode(),
                  {"job": state, "source_consumed": decoded["SOURCE_B64"] == fixture["materials"]["source.txt"].encode(),
                   "dependency_consumed": decoded["DEPENDENCY_B64"] == fixture["materials"]["dependency.txt"].encode()})
        expected_intermediate = fixture["materials"]["source.txt"].replace("\r", "").encode()
        expected_artifact = expected_intermediate + fixture["materials"]["dependency.txt"].encode()
        lab.check("green", "Builder intermediate and final output are actual derived fixture bytes",
                  decoded["INTERMEDIATE_B64"] == expected_intermediate and decoded["ARTIFACT_B64"] == expected_artifact,
                  {"intermediate": decoded["INTERMEDIATE_B64"].decode(),
                   "artifact": decoded["ARTIFACT_B64"].decode()})
        observed_hashes = {
            "source": hashlib.sha256(decoded["SOURCE_B64"]).hexdigest(),
            "dependency": hashlib.sha256(decoded["DEPENDENCY_B64"]).hexdigest(),
            "intermediate": hashlib.sha256(decoded["INTERMEDIATE_B64"]).hexdigest(),
            "artifact": hashlib.sha256(decoded["ARTIFACT_B64"]).hexdigest(),
        }
        for key, field in (("source", "SOURCE_SHA256"), ("dependency", "DEPENDENCY_SHA256"),
                           ("intermediate", "INTERMEDIATE_SHA256"), ("artifact", "ARTIFACT_SHA256")):
            lab.check("positive", f"Builder reported {key} digest matches captured bytes",
                      fields.get(field) == observed_hashes[key],
                      {"reported": fields.get(field), "observed": observed_hashes[key]})

        subject = "saf-lab://0603-008/build/release.txt"
        materials = [{"name": "source.txt", "digest": {"sha256": observed_hashes["source"]}},
                     {"name": "dependency.txt", "digest": {"sha256": observed_hashes["dependency"]}}]
        products = [{"name": "source.normalized", "digest": {"sha256": observed_hashes["intermediate"]}},
                    {"name": "release.txt", "digest": {"sha256": observed_hashes["artifact"]}}]
        complete_material_statement = _statement(
            subject, observed_hashes["artifact"], MATERIALS_TYPE,
            {"materials": materials, "completeness": "all fixture materials consumed by this build"})
        artifact_statement = _statement(
            subject, observed_hashes["artifact"], ARTIFACTS_TYPE,
            {"products": products, "materials": materials})
        artifact_statement["subject"].append({
            "name": "saf-lab://0603-008/build/source.normalized",
            "digest": {"sha256": observed_hashes["intermediate"]},
        })
        signed = {
            "materials": _sign(lab, work, "materials", complete_material_statement),
            "artifacts": _sign(lab, work, "artifacts", artifact_statement),
        }
        distinct = signed["materials"]["public"] != signed["artifacts"]["public"]
        lab.check("positive", "Materials and artifacts attestations have distinct signing keys",
                  distinct, {"distinct_public_keys": distinct})
        observed_products = {"artifact": decoded["ARTIFACT_B64"],
                             "intermediate": decoded["INTERMEDIATE_B64"],
                             "artifact_sha256": observed_hashes["artifact"],
                             "intermediate_sha256": observed_hashes["intermediate"]}
        good, good_log = _run_verifier(
            lab, "saf-0603-008-verify-complete", signed, observed_products,
            expected_materials_hash=signed["materials"]["payload_sha256"],
            expected_artifacts_hash=signed["artifacts"]["payload_sha256"])
        lab.check("green", "Independent verifier accepts separately signed complete materials and artifact attestations",
                  good == "complete" and "both-independent-signatures-verified" in good_log
                  and "materials-artifacts-and-observed-products-verified" in good_log,
                  {"job": good, "signatures_verified": "both-independent-signatures-verified" in good_log,
                   "products_verified": "materials-artifacts-and-observed-products-verified" in good_log})

        incomplete_statement = _statement(
            subject, observed_hashes["artifact"], MATERIALS_TYPE,
            {"materials": [materials[0]], "completeness": "all fixture materials consumed by this build"})
        incomplete = _sign(lab, work, "materials-incomplete", incomplete_statement,
                           signing_key=signed["materials"]["key"])
        same_signer = incomplete["public"] == signed["materials"]["public"]
        signed_incomplete = {"materials": incomplete, "artifacts": signed["artifacts"]}
        red, red_log = _run_verifier(
            lab, "saf-0603-008-reject-incomplete-materials", signed_incomplete, observed_products,
            expected_materials_hash=signed["materials"]["payload_sha256"],
            expected_artifacts_hash=signed["artifacts"]["payload_sha256"])
        lab.check("red", "Valid signature over an incomplete materials list is rejected against the complete consumed-input record",
                  red == "failed" and same_signer and "both-independent-signatures-verified" in red_log
                  and "materials-completeness-rejected" in red_log,
                  {"job": red, "same_trusted_fixture_signer": same_signer,
                   "signatures_verified_before_policy_check": "both-independent-signatures-verified" in red_log,
                   "incomplete_materials_rejected": "materials-completeness-rejected" in red_log})
