"""Live Kubernetes training-data provenance fixture for SAF-K8S-0906-006."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from contextlib import contextmanager

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parent / "SAF-K8S-0908-001" / "case.py"
# Scratch-only fallback lets this candidate resolve the existing helper from
# the current workspace. When copied into the canonical case directory, the
# original adjacent path above is used unchanged.
if not RUNTIME.is_file():
    RUNTIME = (HERE.parents[1] / "saf-k8s-framework" / "tests" / "control-lab" /
               "cases" / "SAF-K8S-0908-001" / "case.py")
NAME = "fixture-training-provenance"
CODE = NAME + "-code"
APPROVAL = NAME + "-approval"
SIGNER = NAME + "-signer"
SIGNER_CODE = NAME + "-signer-code"
SIGNER_SERVICE = NAME + "-signer"
SIGNER_DNS = SIGNER_SERVICE + ".saf-test.svc.cluster.local"
SIGNER_TLS_SECRET = SIGNER + "-tls"
SIGNER_TLS_CA = SIGNER + "-tls-ca"
SIGNER_AUDIENCE = "https://lineage-signer.saf.invalid"
IDENTITY_SAS = {"source": "fixture-lineage-source", "transform": "fixture-lineage-transform",
                "training": "fixture-lineage-training", "unapproved": "fixture-lineage-unapproved",
                "signer": "fixture-lineage-signer"}
CLAIMS = {
    "source": NAME + "-source-bytes",
    "source-receipt": NAME + "-source-receipt",
    "transformed": NAME + "-transformed-bytes",
    "transform-receipt": NAME + "-transform-receipt",
    "artifact": NAME + "-artifact",
}
SOURCE_DIGEST = "d3a5fcb54688a9377553f913caea54717e6a5862c8bc4f5255972571adecba9c"
TRANSFORMED_DIGEST = "f4888552d6e0bb9225ad22339a949faa3951bd99ff2493f1531bc415f72c994b"
EXPECTED_ARTIFACT_DIGEST = "e2837c803d89486e982d2cbd64023f657f959529a13faf86556d1b22dcb169dc"
UNGOVERNED_SOURCE_DIGEST = "c968d3d5d5bab4fb24b9f13c46add56b38974d02edf33b96c7704dc08395a72b"
UNKNOWN_SOURCE_DIGEST = "2c92c16e5bf40fe9a6b21ee23cc15b7796f8da031fe16f6a6a812e94ec4d999c"
TRANSFORM_ID = "normalize-token-order-v1"
SCOPE = (
    "A live, local Kind fixture persists invented source bytes, source receipt, transformed bytes, "
    "transformation receipt, and trained artifact on separate PVCs. It compares a benign ungoverned "
    "training job with missing provenance, denies training and release binding before approval, then "
    "trains and binds an artifact only when approval digests and receipt lineage match exactly. Three "
    "distinct producer ServiceAccounts request case-signer signatures after audience-bound TokenReview; "
    "only signatures over exact fixed receipts are returned."
)


def load_runtime(lab):
    """Use the actual adjacent published runtime loader; do not copy its setup."""
    if not RUNTIME.is_file():
        lab.block("Required adjacent SAF-K8S-0908-001/case.py runtime helper is unavailable")
    spec = importlib.util.spec_from_file_location("saf_k8s_0908_001_runtime", RUNTIME)
    if spec is None or spec.loader is None:
        lab.block("Could not load adjacent SAF-K8S-0908-001/case.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime(lab)


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


@contextmanager
def _temporary_signer_tls():
    """Create short-lived CA/server keys with private outputs written only to files."""
    directory = tempfile.TemporaryDirectory(prefix="saf-0906-006-tls-")
    root = Path(directory.name)
    os.chmod(root, 0o700)
    ca_key, ca_csr, ca_cert = root / "ca.key", root / "ca.csr", root / "ca.pem"
    server_key, server_csr, server_cert = root / "server.key", root / "server.csr", root / "server.crt"
    ca_ext, server_ext = root / "ca.ext", root / "server.ext"
    ca_ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\n"
                      "keyUsage=critical,keyCertSign,cRLSign\n"
                      "subjectKeyIdentifier=hash\n"
                      "authorityKeyIdentifier=keyid:always,issuer\n")
    server_ext.write_text(
        f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{SIGNER_DNS}\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    commands = [
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
         "-out", str(ca_csr), "-subj", "/CN=SAF-K8S-0906-006 ephemeral fixture CA"],
        ["openssl", "x509", "-req", "-in", str(ca_csr), "-signkey", str(ca_key), "-days", "2",
         "-extfile", str(ca_ext), "-out", str(ca_cert)],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(server_key),
         "-out", str(server_csr), "-subj", f"/CN={SIGNER_SERVICE}.saf-test.svc"],
        ["openssl", "x509", "-req", "-in", str(server_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
         "-CAcreateserial", "-days", "2", "-extfile", str(server_ext), "-out", str(server_cert)],
        ["openssl", "verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", str(ca_cert), str(server_cert)],
    ]
    try:
        for command in commands:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(ca_key, 0o600)
        os.chmod(server_key, 0o600)
        yield {"ca_cert": ca_cert, "server_cert": server_cert, "server_key": server_key}
    except (OSError, subprocess.CalledProcessError):
        raise RuntimeError("ephemeral signer TLS material generation failed") from None
    finally:
        directory.cleanup()


def _volumes(identity=False):
    volumes = ([{"name": "code", "configMap": {"name": CODE, "defaultMode": 0o444}},
                {"name": "trust", "configMap": {"name": "fixture-training-provenance-signer-trust"}},
                {"name": "tls-ca", "configMap": {"name": SIGNER_TLS_CA}}] +
               [{"name": key, "persistentVolumeClaim": {"claimName": claim}}
                for key, claim in CLAIMS.items()])
    if identity:
        volumes.append({"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
            "audience": SIGNER_AUDIENCE, "expirationSeconds": 600, "path": "token"}}]}})
    return volumes


def _mounts(operation, identity=False):
    writable = {
        "baseline": {"artifact"}, "ingest": {"source", "source-receipt"},
        "transform": {"transformed", "transform-receipt"}, "train": {"artifact"},
        "release": {"artifact"}, "write-mismatched-receipt": {"transform-receipt"},
    }.get(operation, set())
    paths = {"source": "/source", "source-receipt": "/source-receipt",
             "transformed": "/transformed", "transform-receipt": "/transform-receipt",
             "artifact": "/artifact"}
    return ([{"name": "code", "mountPath": "/fixture", "readOnly": True}] +
            [{"name": "trust", "mountPath": "/trust", "readOnly": True}] +
            [{"name": "tls-ca", "mountPath": "/tls-ca", "readOnly": True}] +
            ([{"name": "identity", "mountPath": "/identity", "readOnly": True}] if identity else []) +
            [{"name": key, "mountPath": path, "readOnly": key not in writable} for key, path in paths.items()])


def _job(lab, image, name, operation, approval=False, extra_env=None, identity_account=None):
    unit = {"name": "fixture", "image": image, "imagePullPolicy": "Never",
            "command": ["python", "/fixture/training_fixture.py", operation],
            "volumeMounts": _mounts(operation, identity=identity_account is not None),
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                          "limits": {"cpu": "100m", "memory": "64Mi"}}}
    if approval:
        unit["env"] = [{"name": "APPROVAL_JSON", "valueFrom": {"configMapKeyRef": {
            "name": APPROVAL, "key": "approval.json", "optional": True}}}]
    if extra_env:
        unit.setdefault("env", []).extend(
            {"name": key, "value": value} for key, value in extra_env.items())
    if operation in {"ingest", "transform", "train", "identity-probe"}:
        unit.setdefault("env", []).append({"name": "SIGNER_URL", "value": f"https://{SIGNER_DNS}:8080"})
    if identity_account:
        pod_service_account = identity_account
    else:
        pod_service_account = "default"
    return create(lab, "Job", name, "batch/v1", spec={
        "backoffLimit": 0, "ttlSecondsAfterFinished": 3600,
        "template": {"metadata": {"labels": {"app": name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "serviceAccountName": pod_service_account,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [unit], "volumes": _volumes(identity=identity_account is not None)}}})


def _result(lab, name):
    lab.kubectl("wait", "--for=condition=complete", "job/" + name, "--timeout=90s", timeout=100)
    lines = [line for line in lab.kubectl("logs", "job/" + name, timeout=20).stdout.splitlines() if line]
    return json.loads(lines[-1])


def _create_claims(lab):
    for claim in CLAIMS.values():
        create(lab, "PersistentVolumeClaim", claim, spec={
            "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}})


def _create_identity_signer(lab, image):
    for account in IDENTITY_SAS.values():
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                    "metadata": {"name": account, "namespace": "saf-test"},
                    "automountServiceAccountToken": False})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": NAME + "-tokenreview"},
                "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"],
                           "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": NAME + "-tokenreview"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                            "name": NAME + "-tokenreview"},
                "subjects": [{"kind": "ServiceAccount", "name": IDENTITY_SAS["signer"],
                              "namespace": "saf-test"}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": NAME + "-trust-write", "namespace": "saf-test"},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": NAME + "-trust-write", "namespace": "saf-test"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": NAME + "-trust-write"},
                "subjects": [{"kind": "ServiceAccount", "name": IDENTITY_SAS["signer"],
                              "namespace": "saf-test"}]})
    create(lab, "ConfigMap", SIGNER_CODE, immutable=True, data={
        "identity_signer.py": (HERE / "identity_signer.py").read_text(),
        "training_fixture.py": (HERE / "training_fixture.py").read_text(),
        "lineage_crypto.py": (HERE / "lineage_crypto.py").read_text(),
        "signature_crypto_base.py": (HERE / "signature_crypto_base.py").read_text(),
        "signature_format.py": (HERE / "signature_format.py").read_text(),
    })
    signer_unit = container("signer", image=image, imagePullPolicy="Never",
                            command=["python", "/fixture/identity_signer.py"],
                            env=[{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                            volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                          {"name": "tls-server", "mountPath": "/tls-server", "readOnly": True},
                                          {"name": "source", "mountPath": "/source", "readOnly": True},
                                          {"name": "source-receipt", "mountPath": "/source-receipt", "readOnly": True},
                                          {"name": "transformed", "mountPath": "/transformed", "readOnly": True},
                                          {"name": "transform-receipt", "mountPath": "/transform-receipt", "readOnly": True},
                                          {"name": "artifact", "mountPath": "/artifact", "readOnly": True}],
                            securityContext={"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                            resources={"requests": {"cpu": "25m", "memory": "32Mi"},
                                       "limits": {"cpu": "200m", "memory": "128Mi"}})
    signer_unit["readinessProbe"] = {"httpGet": {"path": "/readyz", "port": 8080, "scheme": "HTTPS"},
                                     "periodSeconds": 1, "timeoutSeconds": 2,
                                     "failureThreshold": 30}
    signer_pod = pod(SIGNER, [signer_unit], serviceAccountName=IDENTITY_SAS["signer"],
                     automountServiceAccountToken=True,
                     securityContext={"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                      "seccompProfile": {"type": "RuntimeDefault"}},
                     volumes=[{"name": "code", "configMap": {"name": SIGNER_CODE}},
                              {"name": "tls-server", "secret": {"secretName": SIGNER_TLS_SECRET,
                                                                    "defaultMode": 0o440}},
                              *[{"name": key, "persistentVolumeClaim": {"claimName": claim}}
                                for key, claim in CLAIMS.items()]])
    signer_pod["metadata"]["labels"] = {"app": SIGNER}
    lab.create(signer_pod)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SIGNER_SERVICE},
                "spec": {"selector": {"app": SIGNER},
                         "ports": [{"name": "https", "port": 8080, "targetPort": 8080}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + SIGNER, "--timeout=90s", timeout=95)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if lab.kubectl("get", "configmap", "fixture-training-provenance-signer-trust",
                       allow_failure=True).returncode == 0:
            return
        time.sleep(0.25)
    lab.block("The signer did not publish its immutable public trust pin")


def run(lab):
    image = load_runtime(lab)
    source = (HERE / "training_fixture.py").read_text()
    create(lab, "ConfigMap", CODE, immutable=True, data={
        "training_fixture.py": source,
        "lineage_crypto.py": (HERE / "lineage_crypto.py").read_text(),
        "signature_crypto_base.py": (HERE / "signature_crypto_base.py").read_text(),
        "signature_format.py": (HERE / "signature_format.py").read_text(),
    })
    _create_claims(lab)
    with _temporary_signer_tls() as tls:
        create(lab, "ConfigMap", SIGNER_TLS_CA, immutable=True,
               data={"ca.pem": tls["ca_cert"].read_text()})
        lab.kubectl("create", "secret", "tls", SIGNER_TLS_SECRET,
                    "--cert", str(tls["server_cert"]), "--key", str(tls["server_key"]))
        _create_identity_signer(lab, image)

    # This actual workload consumes every claim before a WaitForFirstConsumer
    # provisioner is asked to report Bound; the signer may also be the first consumer.
    _job(lab, image, NAME + "-volume-consumer", "bootstrap")
    for claim in CLAIMS.values():
        lab.kubectl("wait", "--for=jsonpath={.status.phase}=Bound", "pvc/" + claim,
                    "--timeout=120s", timeout=130)
    _result(lab, NAME + "-volume-consumer")
    identity_probe_name = NAME + "-wrong-producer"
    _job(lab, image, identity_probe_name, "identity-probe",
         identity_account=IDENTITY_SAS["unapproved"])
    wrong_identity = _result(lab, identity_probe_name)

    baseline_job = NAME + "-ungoverned"
    _job(lab, image, baseline_job, "baseline")
    baseline = _result(lab, baseline_job)
    denial_job = NAME + "-training-denied"
    release_denial_job = NAME + "-release-denied"
    _job(lab, image, denial_job, "train", approval=True)
    denial = _result(lab, denial_job)
    _job(lab, image, release_denial_job, "release", approval=True)
    release_denial = _result(lab, release_denial_job)
    inspect_job = NAME + "-inspect-denial"
    _job(lab, image, inspect_job, "inspect-denial")
    denied_state = _result(lab, inspect_job)

    red = {
        "ungoverned_job_accepted_missing_linkage": baseline["accepted_without_linkage"] and
            baseline["read_mismatched_benign_fixture"],
        "ungoverned_input_differs_from_approved_source": baseline["input_sha256"] != SOURCE_DIGEST,
    }
    lab.check("red", "The ungoverned comparison accepts a benign mismatched fixture without provenance linkage",
              all(red.values()), red)

    approval = {"approval_id": "synthetic-approval-v1", "source_sha256": SOURCE_DIGEST,
                "transformed_sha256": TRANSFORMED_DIGEST}
    green = {
        "training_denied_before_approval": denial["decision"] == "denied" and
            denial["reason"] == "approval-absent",
        "release_denied_before_training_or_approval": release_denial["decision"] == "denied" and
            release_denial["reason"] == "approval-absent" and
            not release_denial["model_exists_before_release"] and
            not release_denial["release_binding_created"],
        "denied_attempts_left_no_governed_model_or_binding": denied_state["governed_model_absent"] and
            denied_state["release_binding_absent"],
    }
    # Add approved digest binding only after observing both pre-training denials.
    create(lab, "ConfigMap", APPROVAL, immutable=True,
           data={"approval.json": json.dumps(approval, sort_keys=True, separators=(",", ":"))})
    ingest_name = NAME + "-ingest"
    transform_name = NAME + "-transform"
    train_name = NAME + "-train"
    release_name = NAME + "-release"
    _job(lab, image, ingest_name, "ingest", identity_account=IDENTITY_SAS["source"])
    ingested = _result(lab, ingest_name)
    _job(lab, image, transform_name, "transform", identity_account=IDENTITY_SAS["transform"])
    transformed = _result(lab, transform_name)
    _job(lab, image, NAME + "-bad-edge", "write-mismatched-receipt")
    _result(lab, NAME + "-bad-edge")
    _job(lab, image, NAME + "-reject-edge", "train", approval=True)
    mismatch = _result(lab, NAME + "-reject-edge")
    _job(lab, image, NAME + "-restore-edge", "transform",
         identity_account=IDENTITY_SAS["transform"])
    _result(lab, NAME + "-restore-edge")
    _job(lab, image, train_name, "train", approval=True,
         identity_account=IDENTITY_SAS["training"])
    trained = _result(lab, train_name)
    _job(lab, image, release_name, "release", approval=True)
    released = _result(lab, release_name)
    green.update({
        "source_bytes_digest_matches_approval": ingested["source_sha256"] == SOURCE_DIGEST,
        "transformation_receipt_matches_approved_digest": transformed["transformed"] and
            transformed["output_sha256"] == TRANSFORMED_DIGEST,
        "valid_approval_still_rejects_mismatched_receipt": mismatch["decision"] == "denied"
            and mismatch["checks"]["source_linked"] is False
            and mismatch["checks"]["approved_source_digest"] is True
            and mismatch["checks"]["approved_transformed_digest"] is True
            and not mismatch["artifact_created"],
        "training_checks_all_pass": trained["decision"] == "trained" and all(trained["checks"].values()),
        "training_receipt_signed_after_tokenreview": trained.get("producer_signature_written") is True,
        "release_binding_created_after_lineage_validation": released["decision"] == "released" and
            released["release_binding_created"] and all(released["checks"].values()),
        "release_binding_contains_exact_approved_edges":
            released["binding"]["source_sha256"] == SOURCE_DIGEST and
            released["binding"]["transformed_sha256"] == TRANSFORMED_DIGEST and
            released["binding"]["artifact_sha256"] == trained["artifact_sha256"] and
            released["binding"]["approval_id"] == approval["approval_id"] and
            all(len(trained[field]) == 64 and released["binding"][field] == trained[field]
                for field in ("source_receipt_sha256", "transformation_receipt_sha256")) and
            released["binding"]["training_receipt_sha256"] != "",
    })
    lab.check("green", "Training and release bind the artifact to the exact approved data and receipt lineage",
              all(green.values()), green)

    positive = {
        "separate_persistent_objects_used": len(CLAIMS) == 5,
        "approved_source_digest": SOURCE_DIGEST,
        "approved_transformed_digest": TRANSFORMED_DIGEST,
        "artifact_digest_present": bool(trained.get("artifact_sha256")),
        "training_receipt_digest": released.get("binding", {}).get("training_receipt_sha256"),
        "source_receipt_digest": trained.get("source_receipt_sha256"),
        "transformation_receipt_digest": trained.get("transformation_receipt_sha256"),
        "binding_artifact_digest": released.get("binding", {}).get("artifact_sha256"),
        "approved_release_decision": released["decision"] == "released",
    }
    lab.check("positive", "A fully linked approved training artifact reaches the fixture release binding",
              positive["separate_persistent_objects_used"] and positive["artifact_digest_present"] and
              positive["approved_release_decision"] and all(
                  len(positive.get(key) or "") == 64 for key in (
                      "training_receipt_digest", "source_receipt_digest", "transformation_receipt_digest",
                  )), positive)

    # Independent, read-only query of only this case's persisted records.
    # Inputs are fixed hashes known by the fixture, not values discovered from
    # the query response.
    query_name = NAME + "-trace-query"
    _job(lab, image, query_name, "trace-query", extra_env={
        "TRACE_ARTIFACT_SHA256": EXPECTED_ARTIFACT_DIGEST,
        "TRACE_SOURCE_SHA256": SOURCE_DIGEST,
        "TRACE_TRANSFORM_ID": TRANSFORM_ID,
        "TRACE_TRANSFORMED_SHA256": TRANSFORMED_DIGEST,
        "TRACE_UNGOVERNED_SOURCE_SHA256": UNGOVERNED_SOURCE_DIGEST,
        "TRACE_UNKNOWN_SOURCE_SHA256": UNKNOWN_SOURCE_DIGEST,
        "TRACE_EXPECTED_ARTIFACT_SHA256": EXPECTED_ARTIFACT_DIGEST,
    })
    queried = _result(lab, query_name)
    query_expected = {
        "stored_binding_count": 1,
        "all_stored_records_validate": True,
        "forward_artifact_resolved": True,
        "forward_source_edge_matches": True,
        "forward_transform_edge_matches": True,
        "reverse_source_match_count": 1,
        "reverse_source_returns_exact_artifact": True,
        "reverse_transform_match_count": 1,
        "reverse_transform_returns_exact_artifact": True,
        "ungoverned_source_match_count": 0,
        "unknown_source_match_count": 0,
        "all_producer_signatures_valid": True,
    }
    query_observed = {key: queried.get(key) for key in query_expected}
    lab.check("positive", "Read-only stored lineage queries resolve approved edges in both directions and exclude ungoverned or unknown inputs",
              query_observed == query_expected, query_observed)

    identity_check = {
        "valid_token_from_wrong_producer_denied": wrong_identity.get("wrong_producer_denied") is True,
        "wrong_producer_created_no_signature": wrong_identity.get("signature_created") is False,
        "release_and_stored_query_verify_all_three_producer_signatures":
            released["checks"].get("all_producer_signatures_valid") is True
            and query_observed.get("all_producer_signatures_valid") is True,
        "pinned_public_key_verifies_release_signatures":
            released["decision"] == "released"
            and released["checks"].get("all_producer_signatures_valid") is True
            and query_observed.get("all_producer_signatures_valid") is True,
    }
    lab.check("positive", "TokenReview-bound producer identities receive verifiable signatures over exact fixed receipts",
              all(identity_check.values()), identity_check)

    evidence = {
        "scope": "synthetic-local-kind-training-provenance",
        "red": red,
        "green": green,
        "positive": positive,
        "observations": {"ungoverned": baseline, "training_without_approval": denial,
                         "release_without_approval": release_denial, "denied_state": denied_state,
                         "wrong_producer_identity": wrong_identity,
                         "ingest": ingested, "transform": transformed,
                         "training": trained, "release": released, "mismatched_edge": mismatch,
                         "read_only_lineage_query": query_observed},
        "identity_check": identity_check,
    }
    (lab.evidence / "training-data-provenance.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n")
