"""Bind observed fixture bytes to an independently authorized workload."""

import base64
import binascii
import hashlib
import json
from pathlib import Path
import tempfile

SCOPE = "One CI-style artifact handoff between Kubernetes build and evidence Jobs and a local receiver."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
MARKER = "public-handoff-fixture-v1"
BUILD = "handoff-artifact"
EVIDENCE = "handoff-evidence"
IDENTITY = "system:serviceaccount:saf-test:handoff-observer"


def config(lab, name, data):
    return lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": data})


def add_account(lab, user, account_rules):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": user},
                "automountServiceAccountToken": False})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": user},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [resource], "verbs": verbs}
                          for resource, verbs in account_rules]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": user},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": user},
                "subjects": [{"kind": "ServiceAccount", "name": user, "namespace": "saf-test"}]})


def execute(lab, name, mode, *, secret=False):
    volumes = [{"name": "script", "configMap": {"name": "handoff-code"}},
               {"name": "fixture-api", "projected": {"sources": [
                   {"serviceAccountToken": {"expirationSeconds": 600, "path": "token"}},
                   {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
               ]}}]
    mounts = [{"name": "script", "mountPath": "/fixture", "readOnly": True},
              {"name": "fixture-api", "mountPath": "/var/run/fixture-api", "readOnly": True}]
    if secret:
        volumes.append({"name": "signer", "secret": {"secretName": "handoff-fixture-key"}})
        mounts.append({"name": "signer", "mountPath": "/var/run/fixture-signer", "readOnly": True})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 85,
                         "template": {"spec": {"serviceAccountName": name, "restartPolicy": "Never",
                             "automountServiceAccountToken": False, "volumes": volumes,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                 "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "stage", "image": IMAGE, "command": ["python3", "/fixture/stage.py"],
                                             "env": [{"name": "STAGE", "value": mode}], "volumeMounts": mounts,
                                             "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                           "limits": {"cpu": "200m", "memory": "96Mi"}},
                                             "securityContext": {"allowPrivilegeEscalation": False,
                                                                 "readOnlyRootFilesystem": True,
                                                                 "capabilities": {"drop": ["ALL"]}}}],
                         }}}})
    done = lab.kubectl("wait", "--for=condition=complete", f"job/{name}", "--timeout=85s", timeout=95,
                       allow_failure=True)
    output = lab.kubectl("logs", f"job/{name}", allow_failure=True)
    if done.returncode != 0 or output.returncode != 0:
        lab.block(f"Fixture Job {name} did not complete; see the local command log")
    return json.loads(output.stdout)


def promote(lab, name, marker, evidence, public, work):
    if evidence is not None:
        body = evidence.get("statement", "")
        try:
            signed_fields = json.loads(body)
            signature = base64.b64decode(evidence.get("signature", ""), validate=True)
        except (binascii.Error, ValueError):
            return False
        expected = {"identity": IDENTITY, "subject_digest": "sha256:" + hashlib.sha256(marker.encode()).hexdigest()}
        if signed_fields != expected:
            return False
        path = work / "signature"
        path.write_bytes(signature)
        result = lab.command("openssl", "dgst", "-sha256", "-verify", str(public), "-signature", str(path),
                             payload=body, allow_failure=True)
        if result.returncode != 0 or "Verified OK" not in result.stdout:
            return False
    config(lab, name, {"marker": marker})
    return True


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    config(lab, BUILD, {})
    config(lab, EVIDENCE, {})
    config(lab, "handoff-code", {"stage.py": Path(__file__).with_name("stage.py").read_text()})
    add_account(lab, "handoff-builder", [(BUILD, ["patch"])])
    add_account(lab, "handoff-observer", [(BUILD, ["get"]), (EVIDENCE, ["patch"])])
    changed_marker = "different-public-handoff-v2"
    with tempfile.TemporaryDirectory(prefix="saf-handoff-") as temp:
        work = Path(temp)
        private = work / "private.pem"
        public = work / "public.pem"
        lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private))
        lab.command("openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public))
        lab.kubectl("create", "secret", "generic", "handoff-fixture-key", f"--from-file=private.pem={private}")
        private.unlink()
        unchecked = promote(lab, "unchecked-handoff", changed_marker, None, public, work)
        lab.check("red", "Without receiving verification the different marker is published", unchecked,
                  {"unchecked_public_marker_reached_api": unchecked})
        builder = execute(lab, "handoff-builder", "build")
        observer = execute(lab, "handoff-observer", "evidence", secret=True)
        separation = builder == {"artifact_write": 200, "evidence_write": 403, "key_mounted": False} and (
            observer["artifact_read"], observer["artifact_write"], observer["evidence_write"]) == (200, 403, 200)
        lab.check("green", "Actual workload identities enforce different build and evidence rights", separation,
                  {"builder": builder, "observer": observer})
        stored = json.loads(lab.kubectl("get", "configmap", EVIDENCE, "-o", "json").stdout)["data"]
        tampered = {**stored, "signature": base64.b64encode(b"different-fixture-signature").decode()}
        rejected = {"changed_artifact": not promote(lab, "changed-handoff", changed_marker, stored, public, work),
                    "different_signature": not promote(lab, "bad-signature", MARKER, tampered, public, work),
                    "missing_evidence": not promote(lab, "missing-handoff", MARKER, {}, public, work)}
        existing = lab.kubectl("get", "configmap", "changed-handoff", "bad-signature", "missing-handoff",
                               "--ignore-not-found", "-o", "name").stdout.strip()
        lab.check("green", "Receiving verification refuses changed or missing evidence and different bytes",
                  all(rejected.values()) and not existing, rejected)
        accepted = promote(lab, "approved-handoff", MARKER, stored, public, work)
        released = json.loads(lab.kubectl("get", "configmap", "approved-handoff", "-o", "json").stdout)
        lab.check("positive", "Only the authenticated evidence for the exact fixture marker reaches approval",
                  accepted and released["data"]["marker"] == MARKER,
                  {"approved_marker_stored": released["data"]["marker"] == MARKER, "subject": observer["subject_digest"]})
        fingerprint = hashlib.sha256(public.read_bytes()).hexdigest()
    (lab.evidence / "handoff-observations.json").write_text(json.dumps({"builder": builder, "observer": observer,
        "public_key_sha256": fingerprint, "rejected": rejected, "approved_marker_stored": accepted}, indent=2) + "\n")
