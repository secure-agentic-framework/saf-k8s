"""Exercise one fixed signed OCI fixture at a fail-closed Kubernetes admission boundary."""
import base64
import json
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
WEBHOOK = "saf-model-fixture-verifier"
PYTHON_IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
PAUSE_IMAGE = "registry.k8s.io/pause:3.10.1@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
SCOPE = (
    "One fresh Kubernetes 1.36.1 Kind cluster and namespace saf-test. A fixture-only HTTPS admission "
    "webhook examines CREATE requests for one inert Deployment shape, recomputes the exact fixed OCI "
    "manifest and layer digests, verifies an RSA-SHA256 manifest signature, verifies two sorted signed "
    "in-toto Statement v1 DSSE approval/provenance materials with matching subjects, and returns a real "
    "fail-closed Kubernetes admission denial or allow. Proves only this fixed test key, artifact, policy, "
    "Deployment CREATE path, and namespace; not registry retrieval, arbitrary OCI artifacts, UPDATE, "
    "production trust custody, all provenance steps, or all model deployments."
)


def _resource(name, annotations=None):
    metadata = {"name": name, "namespace": NAMESPACE}
    if annotations is not None:
        metadata["annotations"] = annotations
    return {
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata,
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {"containers": [{"name": "inert-model-fixture", "image": PAUSE_IMAGE}]},
            },
        },
    }


def _trusted_annotations(fixture):
    return {
        "saf.example.test/model-digest": "sha256:" + fixture["manifest_sha256"],
        "saf.example.test/model-signature": fixture["manifest_signature_base64"],
        "saf.example.test/attestations": json.dumps(
            fixture["attestations"], separators=(",", ":"), sort_keys=True
        ),
    }


def _admission_configuration(ca_pem):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": "saf-model-fixture-verifier"},
        "webhooks": [{
            "name": "model-fixture.saf.example.test",
            "admissionReviewVersions": ["v1"], "sideEffects": "None",
            "failurePolicy": "Fail", "matchPolicy": "Equivalent", "timeoutSeconds": 5,
            "clientConfig": {
                "service": {"namespace": NAMESPACE, "name": WEBHOOK, "path": "/validate", "port": 443},
                "caBundle": base64.b64encode(ca_pem).decode("ascii"),
            },
            "namespaceSelector": {"matchLabels": {"saf.example.test/model-verification": "required"}},
            "rules": [{"operations": ["CREATE"], "apiGroups": ["apps"],
                       "apiVersions": ["v1"], "resources": ["deployments"], "scope": "Namespaced"}],
        }],
    }


def _record_runtime(lab, value):
    (lab.evidence / "admission-runtime.json").write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _denial(lab, name, resource, expected_fragment, *, dry_run=False):
    result = lab.create(resource, allow_failure=True, dry_run=dry_run)
    denied = result.returncode == 1 and expected_fragment in result.stderr
    return result, denied


def run(lab):
    fixture = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf.example.test/model-verification=required", "--overwrite")

    red_name = "saf-model-reject-untrusted"
    red_created = lab.create(_resource(red_name, {"saf.example.test/model-digest": "sha256:00"}))
    red_seen = red_created["metadata"]["name"] == red_name
    lab.check("red", "An untrusted fixed Deployment is admitted before the verifier is installed",
              red_seen, {"outcome": "accepted-before-gate", "name_matches": red_seen})
    lab.kubectl("delete", "deployment", red_name, "--wait=true")

    material_dir = lab.kubeconfig.parent / "tls-material"
    material_dir.mkdir(mode=0o700)
    # Keep the generated serving certificate in memory long enough to configure the API webhook.
    cert = material_dir / "tls.crt"
    key = material_dir / "tls.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "2",
                "-subj", f"/CN={WEBHOOK}.{NAMESPACE}.svc",
                "-addext", f"subjectAltName=DNS:{WEBHOOK}.{NAMESPACE}.svc,DNS:{WEBHOOK}.{NAMESPACE}.svc.cluster.local")
    try:
        lab.kubectl("create", "secret", "tls", WEBHOOK + "-tls", f"--cert={cert}", f"--key={key}")
    finally:
        key.unlink(missing_ok=True)
    # _install_source_and_server reuses the TLS Secret and mounts only its certificate.
    _install_source_and_server(lab, fixture)
    lab.create(_admission_configuration(cert.read_bytes()))
    cert.unlink(missing_ok=True)

    unsigned_name = red_name
    deadline = time.monotonic() + 25
    while True:
        _, ready = _denial(lab, unsigned_name,
                           _resource(unsigned_name, {"saf.example.test/model-digest": "sha256:00"}),
                           "SAF fixture verifier: model digest is absent or does not match the signed OCI manifest",
                           dry_run=True)
        if ready:
            break
        if time.monotonic() >= deadline:
            lab.block("Verifier did not return the targeted admission response")
        time.sleep(0.5)
    unsigned, unsigned_denied = _denial(
        lab, unsigned_name, _resource(unsigned_name, {"saf.example.test/model-digest": "sha256:00"}),
        "SAF fixture verifier: model digest is absent or does not match the signed OCI manifest")
    lab.check("green", "The fail-closed webhook denies fixed metadata with an untrusted digest",
              unsigned_denied, {"outcome": "denied", "reason": "model digest mismatch",
                                "expected_controller_decision": unsigned_denied})

    bad_annotations = _trusted_annotations(fixture)
    bad_annotations["saf.example.test/model-signature"] = "AA=="
    bad_name = "saf-model-reject-bad-signature"
    bad_signature, signature_denied = _denial(
        lab, bad_name, _resource(bad_name, bad_annotations),
        "SAF fixture verifier: model signature is absent or does not match the fixed signer")
    lab.check("green", "The webhook denies a tampered fixed signature annotation",
              signature_denied, {"outcome": "denied", "reason": "model signature mismatch",
                                 "expected_controller_decision": signature_denied})

    unsorted_annotations = _trusted_annotations(fixture)
    unsorted_annotations["saf.example.test/attestations"] = json.dumps(
        list(reversed(fixture["attestations"])), separators=(",", ":"), sort_keys=True
    )
    unsorted_name = "saf-model-reject-unsorted-attestations"
    unsorted, attestations_denied = _denial(
        lab, unsorted_name, _resource(unsorted_name, unsorted_annotations),
        "SAF fixture verifier: approval and provenance materials are missing, duplicated, or unsorted")
    lab.check("green", "The webhook denies fixed approval and provenance materials in the wrong order",
              attestations_denied, {"outcome": "denied", "reason": "attestation order mismatch",
                                    "expected_controller_decision": True})

    incomplete = _trusted_annotations(fixture)
    incomplete["saf.example.test/attestations"] = json.dumps(fixture["attestations"][:1])
    missing_name = "saf-model-reject-incomplete-attestations"
    missing, missing_denied = _denial(
        lab, missing_name, _resource(missing_name, incomplete),
        "SAF fixture verifier: attestation set must contain two materials")
    lab.check("green", "The webhook rejects a signed fixture with incomplete attestation evidence",
              missing_denied, {"required_materials": 2, "supplied_materials": 1, "targeted_denial": missing_denied})

    trusted_name = "saf-model-accept-trusted-fixture"
    accepted = lab.create(_resource(trusted_name, _trusted_annotations(fixture)))
    positive = accepted.get("metadata", {}).get("name") == trusted_name
    lab.check("positive", "Kubernetes admits the trusted signed fixture Deployment",
              positive, {"outcome": "accepted", "name_matches": positive,
                         "model_digest": "sha256:" + fixture["manifest_sha256"]})
    _record_runtime(lab, {
        "red": {"outcome": "accepted-before-webhook", "deployment": red_name},
        "unsigned": {"returncode": unsigned.returncode, "stderr": unsigned.stderr.strip()},
        "bad_signature": {"returncode": bad_signature.returncode,
                          "stderr": bad_signature.stderr.strip()},
        "unsorted_attestations": {"returncode": unsorted.returncode,
                                  "stderr": unsorted.stderr.strip()},
        "incomplete": {"returncode": missing.returncode, "stderr": missing.stderr.strip()},
        "positive": {"outcome": "accepted", "deployment": trusted_name},
    })


def _install_source_and_server(lab, fixture):
    """Install verifier source, workload, and Service; caller installs admission configuration."""
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": WEBHOOK + "-source"},
                "data": {"webhook.py": (HERE / "webhook.py").read_text(encoding="utf-8"),
                         "fixtures.json": json.dumps(fixture, sort_keys=True)}})
    labels = {"app": WEBHOOK}
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": WEBHOOK},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                 "template": {"metadata": {"labels": labels}, "spec": {
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                         "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                     "volumes": [{"name": "source", "configMap": {"name": WEBHOOK + "-source"}},
                                 {"name": "tls", "secret": {"secretName": WEBHOOK + "-tls"}}],
                     "containers": [{"name": "verifier", "image": PYTHON_IMAGE,
                                     "command": ["python", "/app/webhook.py"],
                                     "imagePullPolicy": "IfNotPresent",
                                     "ports": [{"name": "https", "containerPort": 8443}],
                                     "readinessProbe": {"httpGet": {"scheme": "HTTPS", "path": "/healthz",
                                                                      "port": "https"}, "periodSeconds": 1},
                                     "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                   "limits": {"cpu": "100m", "memory": "96Mi"}},
                                     "volumeMounts": [{"name": "source", "mountPath": "/app", "readOnly": True},
                                                      {"name": "tls", "mountPath": "/tls", "readOnly": True}],
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}],
                 }}},
    })
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": WEBHOOK},
                "spec": {"selector": labels, "ports": [{"name": "https", "port": 443,
                                                           "targetPort": "https"}]}})
    lab.kubectl("rollout", "status", f"deployment/{WEBHOOK}", "--timeout=60s", timeout=70)
