"""Verify separate environment/process DSSE-style signatures inside disposable Jobs."""
import base64
import hashlib
import json
from pathlib import Path
import re
import tempfile
import time


HERE = Path(__file__).parent
IMAGE = (
    "docker.io/alpine/openssl:3.3.2@sha256:"
    "5008e829163320a6e8166883c03e68189e8925ade68cde36584dc2a41cfa5248"
)
PAYLOAD_TYPE = "application/vnd.in-toto+json"
NAMESPACE = "saf-test"
SCOPE = (
    "One fresh local Kubernetes v1.36.1 Kind cluster. Two separate in-toto Statement JSON "
    "payloads model environment inventory and process/tool execution for the same inert "
    "synthetic artifact digest. Each payload is independently DSSE-pre-authenticated and "
    "signed with a distinct ephemeral local RSA key; Kubernetes Jobs verify the signatures, "
    "payload hashes and expected subject. Counterfactual Jobs reject a corrupted signature "
    "and a valid signature whose statement names the wrong subject. A second synthetic build "
    "subject has its own valid environment and process pair. This does not exercise or establish "
    "coverage of any production CI/CD system, builder identity, key custody, attestation "
    "generation, registry storage, or admission enforcement."
)


def _pae(payload_type: bytes, payload: bytes) -> bytes:
    return (b"DSSEv1 " + str(len(payload_type)).encode("ascii") + b" " + payload_type + b" "
            + str(len(payload)).encode("ascii") + b" " + payload)


def _statement(subject_name, digest, predicate_type, predicate):
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": subject_name, "digest": {"sha256": digest}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def _job_script():
    return """#!/bin/sh
set -eu
cd /verify
payload_type='application/vnd.in-toto+json'
type_length=$(printf %s "$payload_type" | wc -c | tr -d ' ')
payload_length=$(wc -c < payload.json | tr -d ' ')
{
  printf 'DSSEv1 %s %s %s ' "$type_length" "$payload_type" "$payload_length"
  cat payload.json
} > /work/pae.bin
if ! openssl dgst -sha256 -verify public.pem -signature signature.bin /work/pae.bin; then
  echo "signature-verification-rejected"
  exit 22
fi
actual=$(sha256sum payload.json | cut -d ' ' -f 1)
expected=$(cat expected-payload-sha256)
if [ "$actual" != "$expected" ]; then
  echo "subject-or-payload-mismatch"
  exit 23
fi
echo "signature-and-expected-payload-verified"
"""


def _make_attestation(lab, work, label, subject_name, subject_digest, claim,
                      expected_payload_hash, signing_key=None):
    safe = re.sub(r"[^a-z0-9-]", "-", label.lower())[:40].strip("-")
    key = signing_key or work / f"{safe}.key"
    public = work / f"{safe}.pub.pem"
    payload = work / f"{safe}.payload.json"
    pae = work / f"{safe}.pae.bin"
    signature = work / f"{safe}.sig"
    statement = _statement(subject_name, subject_digest, claim["predicateType"], claim["predicate"])
    payload_bytes = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    actual_payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    if actual_payload_hash != expected_payload_hash:
        lab.block(f"Pinned fixture payload hash mismatch for {label}: {actual_payload_hash}")
    payload.write_bytes(payload_bytes)
    pae.write_bytes(_pae(PAYLOAD_TYPE.encode("ascii"), payload_bytes))
    if signing_key is None:
        lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(key), timeout=20)
    lab.command("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public))
    lab.command("openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(pae))
    return {
        "payload": payload_bytes,
        "signature": signature.read_bytes(),
        "public": public.read_bytes(),
        "signing_key": key,
        "expected_hash": expected_payload_hash,
    }


def _job(name, files):
    cm_name = name + "-data"
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": cm_name, "namespace": NAMESPACE},
          "binaryData": {k: base64.b64encode(v).decode("ascii") for k, v in files.items()
                         if k == "signature.bin"},
          "data": {k: v.decode("utf-8") for k, v in files.items()
                   if k != "signature.bin"}}
    container = {
        "name": "verify", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["/bin/sh", "/verify/run.sh"],
        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [{"name": "fixture", "mountPath": "/verify", "readOnly": True},
                         {"name": "work", "mountPath": "/work"}],
    }
    pod_spec = {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                            "fsGroup": 1000,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container],
        "volumes": [{"name": "fixture", "configMap": {"name": cm_name, "defaultMode": 292}},
                    {"name": "work", "emptyDir": {"sizeLimit": "1Mi"}}],
    }
    job = {"apiVersion": "batch/v1", "kind": "Job",
           "metadata": {"name": name, "namespace": NAMESPACE},
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                    "ttlSecondsAfterFinished": 300,
                    "template": {"metadata": {"labels": {"app": "saf-0603-007-verifier"}},
                                 "spec": pod_spec}}}
    return cm, job


def _wait_job(lab, name):
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        obj = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {c.get("type"): c.get("status") for c in obj.get("status", {}).get("conditions", [])}
        if conditions.get("Complete") == "True":
            return "complete"
        if conditions.get("Failed") == "True":
            return "failed"
        time.sleep(0.5)
    lab.block(f"Job {name} did not finish before its case timeout")


def _run_job(lab, name, attestation, *, expected_hash=None, corrupt_signature=False):
    files = {
        "run.sh": _job_script().encode("utf-8"),
        "payload.json": attestation["payload"],
        "signature.bin": attestation["signature"],
        "public.pem": attestation["public"],
        "expected-payload-sha256": (expected_hash or attestation["expected_hash"]).encode("ascii"),
    }
    if corrupt_signature:
        damaged = bytearray(files["signature.bin"])
        damaged[-1] ^= 1
        files["signature.bin"] = bytes(damaged)
    cm, job = _job(name, files)
    lab.create(cm)
    lab.create(job)
    state = _wait_job(lab, name)
    pods = json.loads(lab.kubectl("get", "pods", "-l", "job-name=" + name, "-o", "json").stdout)
    pod_name = pods["items"][0]["metadata"]["name"] if pods.get("items") else None
    if not pod_name:
        lab.block(f"Job {name} has no Pod evidence")
    log_result = lab.kubectl("logs", pod_name, allow_failure=True)
    return state, log_result.stdout + log_result.stderr


def run(lab):
    server = json.loads(lab.kubectl("get", "--raw=/version").stdout).get("gitVersion")
    lab.check("positive", "Disposable API server is Kubernetes v1.36.1",
              server == "v1.36.1", {"server": server})
    fixture = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="saf-0603-007-") as directory:
        work = Path(directory)
        claims = {}
        for build_name, build in fixture["subjects"].items():
            artifact = build["artifact_bytes"].encode("utf-8")
            digest = hashlib.sha256(artifact).hexdigest()
            lab.check("positive", f"Pinned {build_name} inert artifact bytes match their fixture digest",
                      digest == build["artifact_sha256"], {"sha256": digest})
            for category in ("environment", "process"):
                name = f"saf-0603-007-{build_name}-{category}"
                claims[(build_name, category)] = _make_attestation(
                    lab, work, name, build["name"], digest, build[category],
                    build[category]["expected_payload_sha256"])

        for category in ("environment", "process"):
            result, log = _run_job(lab, f"saf-0603-007-primary-{category}",
                                   claims[("primary", category)])
            lab.check("green", f"Primary build {category} claim has an independently valid signature, exact expected contents, and subject",
                      result == "complete" and "signature-and-expected-payload-verified" in log,
                      {"job": result, "expected_payload_verified": "signature-and-expected-payload-verified" in log})

        bad_sig, bad_log = _run_job(lab, "saf-0603-007-invalid-signature",
                                    claims[("primary", "environment")], corrupt_signature=True)
        lab.check("red", "Corrupted environment signature is rejected by cryptographic verification",
                  bad_sig == "failed" and "signature-verification-rejected" in bad_log,
                  {"job": bad_sig, "signature_rejected": "signature-verification-rejected" in bad_log})

        wrong_subject = _statement(
            "saf-lab://0603-007/build/not-the-signed-subject",
            fixture["subjects"]["independent"]["artifact_sha256"],
            fixture["subjects"]["primary"]["environment"]["predicateType"],
            fixture["subjects"]["primary"]["environment"]["predicate"],
        )
        # It is deliberately signed and valid; its mismatch must be caught by the expected payload digest.
        bad_claim = dict(fixture["subjects"]["primary"]["environment"])
        bad_claim["predicateType"] = wrong_subject["predicateType"]
        bad_claim["predicate"] = wrong_subject["predicate"]
        signed_wrong = _make_attestation(lab, work, "wrong-subject", wrong_subject["subject"][0]["name"],
                                         wrong_subject["subject"][0]["digest"]["sha256"], bad_claim,
                                         hashlib.sha256(json.dumps(
                                             wrong_subject, sort_keys=True,
                                             separators=(",", ":")).encode("utf-8")).hexdigest(),
                                         signing_key=claims[("primary", "environment")]["signing_key"])
        same_signer = signed_wrong["public"] == claims[("primary", "environment")]["public"]
        wrong, wrong_log = _run_job(lab, "saf-0603-007-wrong-subject", signed_wrong,
                                    expected_hash=claims[("primary", "environment")]["expected_hash"])
        lab.check("red", "Validly signed claim for another subject is rejected against the expected build subject",
                  wrong == "failed" and same_signer and "subject-or-payload-mismatch" in wrong_log,
                  {"job": wrong, "same_trusted_fixture_signer": same_signer,
                   "expected_payload_mismatch": "subject-or-payload-mismatch" in wrong_log})

        for category in ("environment", "process"):
            result, log = _run_job(lab, f"saf-0603-007-independent-{category}",
                                   claims[("independent", category)])
            lab.check("positive", f"Independent compliant {category} claim verifies for its own build subject",
                      result == "complete" and "signature-and-expected-payload-verified" in log,
                      {"job": result, "expected_payload_verified": "signature-and-expected-payload-verified" in log})
