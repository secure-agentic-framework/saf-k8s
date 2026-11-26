"""Additive consumer signer-policy comparison for SAF-K8S-0603-007.

Uses existing per-category ephemeral keys and exact fixtures. The trust policy is
mounted separately from the submitted envelope. This models consumer enforcement;
it does not establish producer isolation or independent production key custody.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import time


def _policy_script():
    return r'''#!/bin/sh
set -eu
payload_type='application/vnd.in-toto+json'
type_length=$(printf %s "$payload_type" | wc -c | tr -d ' ')
payload_length=$(wc -c < /envelope/payload.json | tr -d ' ')
{
  printf 'DSSEv1 %s %s %s ' "$type_length" "$payload_type" "$payload_length"
  cat /envelope/payload.json
} > /work/pae.bin
# First establish that this envelope's signature is valid under its submitted key.
if ! openssl dgst -sha256 -verify /envelope/public.pem -signature /envelope/signature.bin /work/pae.bin >/dev/null 2>&1; then
  echo 'envelope-signature-invalid'
  exit 22
fi
echo 'envelope-signature-valid'
# Trust is sourced only from the separately mounted policy, never from the envelope.
trusted_hash=$(sha256sum /policy/trusted-public.pem | cut -d ' ' -f 1)
expected_trusted_hash=$(cat /policy/trusted-public-sha256)
if [ "$trusted_hash" != "$expected_trusted_hash" ]; then
  echo 'trusted-policy-key-integrity-failed'
  exit 23
fi
submitted_hash=$(sha256sum /envelope/public.pem | cut -d ' ' -f 1)
if [ "$submitted_hash" != "$expected_trusted_hash" ]; then
  echo 'unapproved-signer-rejected'
  exit 24
fi
category=$(cat /policy/category)
predicate_type=$(cat /policy/predicate-type)
case "$category" in
  environment) required_predicate='https://saf-k8s.example.test/attestation/build-environment/v1' ;;
  process) required_predicate='https://saf-k8s.example.test/attestation/build-process/v1' ;;
  *) echo 'category-rejected'; exit 25 ;;
esac
if [ "$predicate_type" != "$required_predicate" ]; then
  echo 'category-predicate-policy-mismatch'
  exit 26
fi
subject_name=$(cat /policy/subject-name)
subject_sha256=$(cat /policy/subject-sha256)
expected_payload_sha256=$(cat /policy/expected-payload-sha256)
actual_payload_sha256=$(sha256sum /envelope/payload.json | cut -d ' ' -f 1)
if [ "$actual_payload_sha256" != "$expected_payload_sha256" ] \
  || ! grep -Fq '"predicateType":"'"$predicate_type"'"' /envelope/payload.json \
  || ! grep -Fq '"name":"'"$subject_name"'"' /envelope/payload.json \
  || ! grep -Fq '"sha256":"'"$subject_sha256"'"' /envelope/payload.json; then
  echo 'category-subject-or-payload-policy-mismatch'
  exit 27
fi
if ! openssl dgst -sha256 -verify /policy/trusted-public.pem \
     -signature /envelope/signature.bin /work/pae.bin >/dev/null 2>&1; then
  echo 'trusted-signer-verification-rejected'
  exit 28
fi
echo 'consumer-policy-accepted'
'''


def _configmap_files(lab, namespace, name, files, directory, *, immutable=False):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "-n", namespace, "create", "configmap", name]
    for key, value in files.items():
        path = directory / key
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else str(value).encode("utf-8"))
        path.chmod(0o600)
        args.append(f"--from-file={key}={path}")
    if not immutable:
        lab.command(*args, timeout=30)
        return
    generated = lab.command(*args, "--dry-run=client", "-o", "json", timeout=30)
    manifest = json.loads(generated.stdout)
    manifest["immutable"] = True
    manifest_path = directory / "policy-configmap.json"
    manifest_path.write_text(json.dumps(manifest))
    manifest_path.chmod(0o600)
    lab.kubectl("-n", namespace, "create", "-f", str(manifest_path), timeout=30)


def _policy_job(lab, name, payload, signature, submitted_public, trusted_public,
                category, predicate_type, subject_name, subject_sha256, expected_payload_sha256,
                temporary, namespace, image):
    envelope_name = name + "-envelope"
    policy_name = name + "-policy"
    work = temporary / name
    envelope_files = {"payload.json": payload, "signature.bin": signature,
                      "public.pem": submitted_public}
    # `public.pem` is deliberately labeled as envelope data and is never the trust source.
    trusted_hash = hashlib.sha256(trusted_public).hexdigest().encode("ascii")
    policy_files = {"run.sh": _policy_script().encode("utf-8"),
                    "trusted-public.pem": trusted_public,
                    "trusted-public-sha256": trusted_hash,
                    "category": category,
                    "predicate-type": predicate_type,
                    "subject-name": subject_name,
                    "subject-sha256": subject_sha256,
                    "expected-payload-sha256": expected_payload_sha256}
    # Provision the trust policy first and make it immutable before the envelope appears.
    _configmap_files(lab, namespace, policy_name, policy_files, work / "policy", immutable=True)
    _configmap_files(lab, namespace, envelope_name, envelope_files, work / "envelope")
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name, "namespace": namespace},
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90, "ttlSecondsAfterFinished": 300,
                    "template": {"metadata": {"labels": {"app": "saf-0603-007-policy-verifier"}},
                                 "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                          "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                              "fsGroup": 1000,
                                                              "seccompProfile": {"type": "RuntimeDefault"}},
                                          "containers": [{"name": "verify", "image": image,
                                                          "imagePullPolicy": "IfNotPresent",
                                                          "command": ["/bin/sh", "/policy/run.sh"],
                                                          "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                                        "limits": {"cpu": "100m", "memory": "64Mi"}},
                                                          "securityContext": {"allowPrivilegeEscalation": False,
                                                                              "readOnlyRootFilesystem": True,
                                                                              "capabilities": {"drop": ["ALL"]}},
                                                          "volumeMounts": [{"name": "envelope", "mountPath": "/envelope",
                                                                            "readOnly": True},
                                                                           {"name": "policy", "mountPath": "/policy",
                                                                            "readOnly": True},
                                                                           {"name": "work", "mountPath": "/work"}]}],
                                          "volumes": [{"name": "envelope", "configMap": {"name": envelope_name,
                                                                                              "defaultMode": 292}},
                                                      {"name": "policy", "configMap": {"name": policy_name,
                                                                                           "defaultMode": 292}},
                                                      {"name": "work", "emptyDir": {"sizeLimit": "1Mi"}}]}}}}
    lab.create(job)
    return name


def _wait_job(lab, name):
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        obj = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {row.get("type"): row.get("status")
                      for row in obj.get("status", {}).get("conditions", [])}
        if conditions.get("Complete") == "True":
            state = "complete"
            break
        if conditions.get("Failed") == "True":
            state = "failed"
            break
        time.sleep(0.5)
    else:
        lab.block(f"Policy verifier job {name} timed out")
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json").stdout)
    items = pods.get("items", [])
    if not items:
        lab.block(f"Policy verifier job {name} has no Pod")
    pod_name = items[0]["metadata"]["name"]
    output = lab.kubectl("logs", pod_name, allow_failure=True).stdout
    return state, output


def run_signer_policy(lab, claims, fixture, pae_builder, payload_type, namespace, image):
    """Test separate approved signer policy for each category and a valid wrong signer."""
    temporary = lab.kubeconfig.parent / "0603-007-signer-policy"
    subjects = fixture["subjects"]["primary"]
    accepted = {}
    for category in ("environment", "process"):
        claim = subjects[category]
        attestation = claims[("primary", category)]
        suffix = "environment" if category == "environment" else "process"
        name = f"saf-0603-007-policy-{suffix}"
        _policy_job(lab, name, attestation["payload"], attestation["signature"], attestation["public"],
                    attestation["public"], category, claim["predicateType"], subjects["name"],
                    subjects["artifact_sha256"], claim["expected_payload_sha256"], temporary,
                    namespace, image)
        state, output = _wait_job(lab, name)
        accepted[category] = {"state": state, "policy_accepted": "consumer-policy-accepted" in output}
        lab.check("positive", f"Consumer policy accepts the approved {category} signer, predicate, and subject digest",
                  state == "complete" and accepted[category]["policy_accepted"],
                  accepted[category])

    # Re-sign the exact approved environment payload using the already-created process key.
    # The resulting envelope is cryptographically valid under its own public key but not allowlisted.
    environment = claims[("primary", "environment")]
    process = claims[("primary", "process")]
    pae = temporary / "unapproved-environment.pae"
    signature = temporary / "unapproved-environment.sig"
    temporary.mkdir(mode=0o700, parents=True, exist_ok=True)
    pae.write_bytes(pae_builder(payload_type.encode("ascii"), environment["payload"]))
    lab.command("openssl", "dgst", "-sha256", "-sign", str(process["signing_key"]),
                "-out", str(signature), str(pae), timeout=20)
    bad_name = "saf-0603-007-policy-unapproved-signer"
    _policy_job(lab, bad_name, environment["payload"], signature.read_bytes(), process["public"],
                environment["public"], "environment",
                subjects["environment"]["predicateType"], subjects["name"],
                subjects["artifact_sha256"], subjects["environment"]["expected_payload_sha256"],
                temporary, namespace, image)
    denied, output = _wait_job(lab, bad_name)
    matched = (denied == "failed" and "envelope-signature-valid" in output
               and "unapproved-signer-rejected" in output)
    lab.check("red", "Valid same-payload signature from a signer unapproved for the environment category is rejected by the separate consumer trust policy",
              matched, {"job": denied, "envelope_signature_validated_before_policy": "envelope-signature-valid" in output,
                        "policy_rejection": matched, "key_material_retained_in_receipt": False})
