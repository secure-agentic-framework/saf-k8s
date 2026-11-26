"""Live Kubernetes fixture for classification-aware RAG chunking and isolation."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = "saf-test"
APP = "fixture-rag-indexer"
BASELINE = "fixture-rag-baseline"
WRITER = "fixture-rag-approved-writer"
CLIENT_PUBLIC = "fixture-rag-public-reader"
CLIENT_CONFIDENTIAL = "fixture-rag-confidential-reader"
VERIFIER = "fixture-rag-tokenreview"
CODE = "fixture-rag-code"
APPROVAL = "fixture-rag-approved-mapping"
TLS = "fixture-rag-tls"
TRUST = "fixture-rag-trust"
PVC = "fixture-rag-data"
SERVICE = "fixture-rag"
AUDIENCE = "saf-rag-fixture"
RBAC = "rbac.authorization.k8s.io/v1"
SCOPE = (
    "A temporary Kubernetes workload indexes only fixed approved synthetic documents in SQLite "
    "on separate PVCs. Kubernetes TokenReview authenticates three projected service-account tokens to an "
    "internal TLS service. Immutable trusted mappings drive deterministic section-local chunks, "
    "classification metadata, isolated per-class tables, and retrieval authorization. Red shows "
    "one confidential marker visible from a shared collection without the guard; green rejects "
    "missing/misclassified labels and a wrong destination without changing storage; positive "
    "checks each authorized principal's own classification output. The authenticated route "
    "also compares exact source-bound writes and independent class-specific readback."
)
APPROVED = {
    "chunk_words": 2,
    "destinations": {"public": "public", "confidential": "confidential"},
    "principals": {
        "fixture-rag-public-reader": {"classifications": ["public"]},
        "fixture-rag-confidential-reader": {"classifications": ["confidential"]},
        "fixture-rag-approved-writer": {"classifications": [], "writer": True},
    },
    "documents": [{
        "id": "doc-cedar-mixed",
        "sections": [
            {"id": "abstract", "classification": "public", "text": "cedar synthetic public summary"},
            {"id": "detail", "classification": "confidential", "text": "amber synthetic confidential marker"},
        ],
    }],
    "write_contracts": [
        {"id": "doc-pine-approved-write", "sections": [
            {"id": "approved-public-write", "classification": "public",
             "text": "pine synthetic public marker"},
        ]},
        {"id": "doc-amber-approved-write", "sections": [
            {"id": "approved-confidential-write", "classification": "confidential",
             "text": "amber neutral confidential marker"},
        ]},
    ],
}


def create(lab, kind, name, api="v1", **fields):
    namespaced = kind not in {"Namespace", "ClusterRole", "ClusterRoleBinding"}
    return lab.create({"apiVersion": api, "kind": kind,
                       "metadata": {"name": name, **({"namespace": NS} if namespaced else {})},
                       **fields})


def load_runtime(lab):
    source = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    if not source.is_file():
        lab.block("The adjacent pinned runtime helper is unavailable")
    spec = importlib.util.spec_from_file_location("saf_k8s_0908_001_runtime", source)
    if spec is None or spec.loader is None:
        lab.block("Could not load the actual adjacent SAF-K8S-0908-001 runtime helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime(lab)


def setup(lab, image):
    for account in (CLIENT_PUBLIC, CLIENT_CONFIDENTIAL, WRITER):
        create(lab, "ServiceAccount", account, automountServiceAccountToken=False)
    create(lab, "ServiceAccount", VERIFIER)
    create(lab, "ClusterRole", VERIFIER, RBAC, rules=[{
        "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]
    }])
    create(lab, "ClusterRoleBinding", VERIFIER, RBAC,
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": VERIFIER},
           subjects=[{"kind": "ServiceAccount", "name": VERIFIER, "namespace": NS}])

    key, cert = lab.kubeconfig.parent / "rag-fixture.key", lab.kubeconfig.parent / "rag-fixture.crt"
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", f"/CN={SERVICE}.{NS}.svc", "-addext",
                f"subjectAltName=DNS:{SERVICE}.{NS}.svc,DNS:{BASELINE}.{NS}.svc", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-keyout", str(key), "-out", str(cert))
    lab.kubectl("-n", NS, "create", "secret", "tls", TLS,
                "--key=" + str(key), "--cert=" + str(cert), "-o", "name")
    create(lab, "ConfigMap", TRUST, immutable=True, data={"ca.crt": cert.read_text()})
    create(lab, "ConfigMap", APPROVAL, immutable=True,
           data={"approved.json": json.dumps(APPROVED, sort_keys=True, separators=(",", ":"))})
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"chunk_fixture.py": (HERE / "chunk_fixture.py").read_text()})
    for volume in (PVC, PVC+"-baseline"):
        create(lab, "PersistentVolumeClaim", volume, spec={
            "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}
        })

    def pod(name, account, mode=None):
        server = mode is not None
        mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
        volumes = [{"name": "code", "configMap": {"name": CODE}}]
        if server:
            mounts += [{"name": "approval", "mountPath": "/approval", "readOnly": True},
                       {"name": "data", "mountPath": "/data"},
                       {"name": "tls", "mountPath": "/tls", "readOnly": True}]
            volumes += [{"name": "approval", "configMap": {"name": APPROVAL, "defaultMode": 0o444}},
                        {"name": "data", "persistentVolumeClaim": {"claimName": PVC+"-baseline" if mode == "baseline" else PVC}},
                        {"name": "tls", "secret": {"secretName": TLS, "defaultMode": 0o440}}]
        else:
            mounts += [{"name": "trust", "mountPath": "/trust", "readOnly": True},
                       {"name": "identity", "mountPath": "/var/run/fixture-token", "readOnly": True}]
            volumes += [{"name": "trust", "configMap": {"name": TRUST}},
                        {"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
                            "path": "token", "audience": AUDIENCE, "expirationSeconds": 600}}]}}]
        container = {"name": "fixture", "image": image, "imagePullPolicy": "Never",
                     "command": ["python", "/fixture/chunk_fixture.py", "serve", mode] if server else ["sleep", "3600"],
                     "volumeMounts": mounts, "securityContext": {"allowPrivilegeEscalation": False,
                     "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                     "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                   "limits": {"cpu": "200m", "memory": "128Mi"}}}
        if server:
            container["ports"] = [{"containerPort": 8443}]
            container["readinessProbe"] = {"tcpSocket": {"port": 8443}, "periodSeconds": 1,
                                            "failureThreshold": 30}
        else:
            # The application reads a projected audience-bound token from the standard path.
            container["volumeMounts"][-1]["mountPath"] = "/var/run/secrets/kubernetes.io/serviceaccount"
        spec = {"restartPolicy": "Never", "serviceAccountName": account,
                "automountServiceAccountToken": server,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [container], "volumes": volumes}
        if not server:
            spec["automountServiceAccountToken"] = False
        lab.create({"apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": name, "namespace": NS, "labels": {"app": name}}, "spec": spec})

    pod(APP, VERIFIER, "governed")
    pod(BASELINE, VERIFIER, "baseline")
    for identity in (CLIENT_PUBLIC, CLIENT_CONFIDENTIAL, WRITER):
        pod(identity, identity)
    for service, target in ((SERVICE, APP), (BASELINE, BASELINE)):
        create(lab, "Service", service, spec={"selector": {"app": target},
               "ports": [{"name": "https", "port": 8443, "targetPort": 8443}]})
    for name in (APP, BASELINE, CLIENT_PUBLIC, CLIENT_CONFIDENTIAL, WRITER):
        lab.kubectl("wait", "--for=condition=Ready", "pod/" + name,
                    "--timeout=95s", timeout=105)


def call(lab, client, op, service=SERVICE):
    result = lab.kubectl("-n", NS, "exec", "pod/" + client, "--", "python",
                         "/fixture/chunk_fixture.py", op,
                         f"https://{service}.{NS}.svc:8443", timeout=25)
    return json.loads(result.stdout)


def run(lab):
    image = load_runtime(lab)
    setup(lab, image)
    for service in (BASELINE, SERVICE):
        for _ in range(12):
            if call(lab, CLIENT_PUBLIC, "ready", service) == {"status": 200}:
                break
            time.sleep(1)
        else:
            lab.block(f"The isolated {service} HTTPS route is not ready")
    baseline = call(lab, CLIENT_PUBLIC, "retrieve/public", BASELINE)
    red = {"shared_baseline_returns_confidential_fixture_marker":
               baseline.get("status") == 200 and baseline.get("texts") == ["amber"]}
    lab.check("red", "The ungoverned shared collection returns a confidential fixture marker",
              all(red.values()), red)
    writer = call(lab, WRITER, "ingest")
    forbidden = call(lab, CLIENT_PUBLIC, "ingest")
    green = {
        "governed_writes_require_writer_identity": forbidden["status"] == 403,
        "trusted_section_and_destination_checks_reject_bad_writes":
            writer.get("rejections") == ["misclassified", "missing-label", "wrong-destination"],
        "denied_writes_preserved_state": writer.get("state_unchanged") is True,
        "governed_index_contains_expected_per_class_chunk_counts":
            writer.get("counts") == {"public": 2, "confidential": 2},
        "public_cannot_retrieve_confidential": call(lab, CLIENT_PUBLIC, "retrieve/confidential")["status"] == 403,
        "confidential_cannot_retrieve_public": call(lab, CLIENT_CONFIDENTIAL, "retrieve/public")["status"] == 403,
    }
    lab.check("green", "The governed path enforces trusted writer, label, collection and retrieval scope",
              all(green.values()), green)
    public = call(lab, CLIENT_PUBLIC, "retrieve/public")
    confidential = call(lab, CLIENT_CONFIDENTIAL, "retrieve/confidential")
    positive = {
        "public_sections_are_exact": public.get("rows") == [
            ["abstract", 0, "public", "cedar synthetic", [2, 14]],
            ["abstract", 1, "public", "public summary", [2, 13]],
        ],
        "confidential_sections_are_exact": confidential.get("rows") == [
            ["detail", 0, "confidential", "amber synthetic", [2, 14]],
            ["detail", 1, "confidential", "confidential marker", [2, 18]],
        ],
    }
    lab.check("positive", "Each approved principal retrieves the exact section-local vectors for its class",
              all(positive.values()), positive)

    verifier_subject = f"system:serviceaccount:{NS}:{VERIFIER}"
    can_create_tokenreview = lab.kubectl("auth", "can-i", "create", "tokenreviews.authentication.k8s.io",
                                         f"--as={verifier_subject}").stdout.strip() == "yes"
    can_patch_approval = lab.kubectl("auth", "can-i", "patch", f"configmaps/{APPROVAL}",
                                     f"--as={verifier_subject}", allow_failure=True)
    approved_before = json.loads(lab.kubectl("get", "configmap", APPROVAL, "-o", "json").stdout)
    patch_request = lab.kubectl("exec", "pod/" + APP, "--", "python",
                                "/fixture/chunk_fixture.py", "probe-approval-patch", timeout=15)
    patch_result = json.loads(patch_request.stdout)
    approved_after = json.loads(lab.kubectl("get", "configmap", APPROVAL, "-o", "json").stdout)
    authority = {
        "tokenreview_verifier_can_create_tokenreviews": can_create_tokenreview,
        "tokenreview_verifier_cannot_patch_approved_metadata": can_patch_approval.returncode == 1
        and can_patch_approval.stdout.strip() == "no",
        "actual_patch_was_forbidden": patch_result == {
            "http_status": 403, "reason": "Forbidden", "patch_verb_was_denied": True,
        },
        "approved_metadata_is_immutable": approved_before.get("immutable") is True,
        "approved_metadata_unchanged": approved_before == approved_after,
        "approved_metadata_digest_unchanged": hashlib.sha256(
            approved_before["data"]["approved.json"].encode()).hexdigest()
            == hashlib.sha256(approved_after["data"]["approved.json"].encode()).hexdigest(),
    }
    allowed_write = call(lab, WRITER, "write-approved")
    mismatched_label = call(lab, WRITER, "write-confidential-as-public")
    wrong_destination = call(lab, WRITER, "write-public-to-confidential")
    body_claim = call(lab, CLIENT_PUBLIC, "write-claimed-writer")
    public_after = call(lab, CLIENT_PUBLIC, "retrieve/public")
    confidential_after = call(lab, CLIENT_CONFIDENTIAL, "retrieve/confidential")
    writes = {
        "authenticated_writer_writes_exact_approved_public_chunk":
            allowed_write == {"status": 200, "accepted": True, "collection": "public",
                              "row": ["doc-pine-approved-write", "approved-public-write", 0,
                                      "public", "pine synthetic", [2, 13]],
                              "counts": {"public": 3, "confidential": 2}},
        "classification_mismatch_is_denied_without_storage_change":
            mismatched_label.get("status") == 403 and mismatched_label.get("reason") == "metadata_mismatch"
            and mismatched_label.get("state_unchanged") is True,
        "wrong_destination_is_denied_without_storage_change":
            wrong_destination.get("status") == 403 and wrong_destination.get("reason") == "metadata_mismatch"
            and wrong_destination.get("state_unchanged") is True,
        "body_claimed_writer_does_not_elevate_public_reader":
            body_claim.get("status") == 403 and body_claim.get("reason") == "writer_identity_required",
        "public_retrieval_returns_exact_written_public_chunk":
            public_after.get("status") == 200 and public_after.get("rows") == [
                ["abstract", 0, "public", "cedar synthetic", [2, 14]],
                ["abstract", 1, "public", "public summary", [2, 13]],
                ["approved-public-write", 0, "public", "pine synthetic", [2, 13]],
            ],
        "confidential_retrieval_remains_exact_and_private":
            confidential_after.get("status") == 200 and confidential_after.get("rows") == [
                ["detail", 0, "confidential", "amber synthetic", [2, 14]],
                ["detail", 1, "confidential", "confidential marker", [2, 18]],
            ],
    }
    lab.check("positive", "Authenticated source contract controls mixed-class writes and preserves authorized retrieval separation",
              all(authority.values()) and all(writes.values()),
              {"metadata_authority": authority, "writes_and_retrieval": writes,
               "denial_reasons": {"mismatched_label": mismatched_label.get("reason"),
                                  "wrong_destination": wrong_destination.get("reason"),
                                  "body_claim": body_claim.get("reason")}})
    (lab.evidence / "rag-classification-observations.json").write_text(json.dumps(
        {"red": red, "green": green, "positive": positive,
         "metadata_authority": authority, "writes_and_retrieval": writes,
         "scope": "fixed owned document and two logical SQLite class collections"},
        sort_keys=True, indent=2) + "\n")
