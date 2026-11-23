"""Live Kind case: verify document provenance before persistent RAG indexing."""
import importlib.util
import base64
import hashlib
import json
import re
from tempfile import TemporaryDirectory
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = "saf-test"
CODE = "saf-rag-code"
ARTIFACTS = "saf-rag-corpus"
RUNS = {
    "red": ("unlocked", "alternate.txt", "rag-red-pvc"),
    "green": ("governed", "alternate.txt", "rag-green-pvc"),
    "positive": ("governed", "approved.txt", "rag-positive-pvc"),
}
EXPECTED_CHUNKS = [
    "The orchid archive rests beside the quiet river garden.",
    "The field team records a blue signal at the river gate.",
]
EXPECTED_FILES = ["approval-manifest.json", "approval.sig", "chunks.json",
                  "source-receipt.json", "vector-index.json"]
RFC3339 = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

SCOPE = (
    "An offline Cosign init checks a signed approval before ingestion starts. "
    "The workload binds the signed source and digest to an owned synthetic document before "
    "chunking. A separate read-only Pod observes unchanged rejected storage or approved chunks, "
    "vectors, the source receipt and a known retrieval."
)


def _load_module(suffix):
    source = HERE.parent / ("SAF-K8S-"+suffix) / "case.py"
    spec = importlib.util.spec_from_file_location("saf_runtime_"+suffix, source)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load the adjacent case helper: {source}")
    registry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(registry)
    return registry


def _create(lab, kind, name, api="v1", **fields):
    metadata = {"name": name}
    if kind != "Namespace":
        metadata["namespace"] = NS
    return lab.create({"apiVersion": api, "kind": kind, "metadata": metadata, **fields})


def _pod(lab, image, name, command, pvc=None, readonly=False, verifier=None):
    from fixtures import container, pod

    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": CODE}}]
    mounts.append({"name": "artifacts", "mountPath": "/artifacts", "readOnly": True})
    volumes.append({"name": "artifacts", "configMap": {"name": ARTIFACTS}})
    if pvc:
        mounts.append({"name": "store", "mountPath": "/store", "readOnly": readonly})
        volumes.append({"name": "store", "persistentVolumeClaim":
                        {"claimName": pvc, "readOnly": readonly}})
    if command[0] != "python" or command[1] != "/fixture/ingest_fixture.py":
        raise ValueError("Unexpected fixture command")
    unit = container("fixture", image=image, imagePullPolicy="Never", command=command,
                     volumeMounts=mounts,
                     securityContext={"allowPrivilegeEscalation": False,
                                      "readOnlyRootFilesystem": True,
                                      "capabilities": {"drop": ["ALL"]}})
    request = pod(name, [unit], automountServiceAccountToken=False,
                  volumes=volumes,
                  securityContext={"runAsNonRoot": True, "runAsUser": 65534,
                                   "fsGroup": 65534,
                                   "seccompProfile": {"type": "RuntimeDefault"}})
    request["metadata"]["namespace"] = NS
    if verifier:
        init = container("verify-approval", image=verifier, imagePullPolicy="Never",
                          command=["/ko-app/cosign", "verify-blob", "--key", "/fixture/authority.pub",
                                   "--signature", "/artifacts/manifest.sig.b64", "--insecure-ignore-tlog",
                                   "--insecure-ignore-sct", command[4]],
                          volumeMounts=mounts[:2])
        request["spec"]["initContainers"] = [init]
    lab.create(request)


def _wait_succeeded(lab, name):
    lab.kubectl("-n", NS, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                f"pod/{name}", "--timeout=120s", timeout=130)
    return json.loads(lab.kubectl("-n", NS, "logs", f"pod/{name}").stdout.strip())


def _observer(lab, image, name, pvc):
    _pod(lab, image, name, ["python", "/fixture/ingest_fixture.py", "observe", "/store"],
         pvc, readonly=True)
    return _wait_succeeded(lab, name)


def _start_ingest(lab, image, label, mode, document, pvc, verifier=None, *, bad_signature=False):
    _create(lab, "PersistentVolumeClaim", pvc, spec={
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "16Mi"}}})
    name = f"rag-{label}-ingest"
    manifest = "altered-manifest.json" if bad_signature else "manifest.json"
    _pod(lab, image, name, ["python", "/fixture/ingest_fixture.py", mode,
                            f"/artifacts/{document}", f"/artifacts/{manifest}",
                            "/artifacts/manifest.sig", "/store"], pvc, verifier=verifier)
    if not bad_signature:
        return _wait_succeeded(lab, name)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Failed", "pod/"+name,
                "--timeout=95s", timeout=105)
    status = json.loads(lab.kubectl("get", "pod/"+name, "-o", "json").stdout)["status"]
    logs = lab.kubectl("logs", "pod/"+name, "-c", "verify-approval").stdout
    return {"cryptographic_rejection_observed": "invalid signature" in logs.lower(),
            "verifier_failed": status["initContainerStatuses"][0]["state"]["terminated"]["exitCode"] != 0,
            "ingestion_did_not_start": not any(row.get("containerID") for row in status.get("containerStatuses", []))}


def _publish(lab):
    with TemporaryDirectory(dir=lab.kubeconfig.parent) as temp:
        root = Path(temp)
        key, public, signature = (root / name for name in ("authority.pem", "authority.pub", "manifest.sig"))
        lab.command("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
        lab.command("openssl", "ec", "-in", str(key), "-pubout", "-out", str(public))
        lab.command("openssl", "dgst", "-sha256", "-sign", str(key), "-out",
                    str(signature), str(HERE/"manifest.json"))
        approved_signature = base64.b64encode(signature.read_bytes()).decode("ascii")
        signature_hash = hashlib.sha256(signature.read_bytes()).hexdigest()
        _create(lab, "ConfigMap", CODE, immutable=True, data={
            "ingest_fixture.py": (HERE/"ingest_fixture.py").read_text(), "authority.pub": public.read_text()})
    manifest = (HERE / "manifest.json").read_text()
    _create(lab, "ConfigMap", ARTIFACTS, immutable=True,
            data={"approved.txt": (HERE / "approved_document.txt").read_text(),
                  "alternate.txt": (HERE / "alternate_document.txt").read_text(),
                  "manifest.json": manifest, "manifest.sig.b64": approved_signature,
                  "altered-manifest.json": manifest.replace("Synthetic Data Steward", "Alternate Fixture Steward")},
            binaryData={"manifest.sig": approved_signature})
    return signature_hash


def _receipt_time_valid(value):
    if not isinstance(value, str) or not RFC3339.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo == timezone.utc
    except ValueError:
        return False


def run(lab):
    image = _load_module("0908-001").load_runtime(lab)
    verifier = _load_module("0909-002").verifier_image(lab)
    signature_hash = _publish(lab)
    red = _start_ingest(lab, image, "red", *RUNS["red"][:2], RUNS["red"][2])
    red_store = _observer(lab, image, "rag-red-observer", RUNS["red"][2])
    red_ok = (red.get("event") == "ingested" and red.get("signature_verified") is False
              and red.get("chunk_count") == 2 and red.get("writes") == 3
              and red_store.get("receipt", {}).get("signature_verified") is False
              and [row.get("text") for row in red_store.get("chunks", [])] == [
                  EXPECTED_CHUNKS[0], EXPECTED_CHUNKS[1].replace("blue", "green")])
    lab.check("red", "The unlocked fixed-source baseline indexes the benign alternate document",
              red_ok, {"alternate_accepted": red_ok,
                       "signature_verification_disabled": red.get("signature_verified") is False,
                       "chunks_persisted": len(red_store.get("chunks", [])),
                       "source_id_fixed": red.get("source_id") ==
                       "synthetic://field-notes/orchid-river/42"})

    invalid = _start_ingest(lab, image, "signature", "governed", "approved.txt",
                            "rag-invalid-signature-pvc", verifier, bad_signature=True)
    invalid_store = _observer(lab, image, "rag-invalid-signature-observer", "rag-invalid-signature-pvc")
    invalid["invalid_approval_pvc_remains_empty"] = invalid_store.get("files") == []
    lab.check("green", "An altered signed manifest fails verification before ingestion starts",
              all(invalid.values()), invalid)
    green = _start_ingest(lab, image, "green", *RUNS["green"], verifier)
    green_store = _observer(lab, image, "rag-green-observer", RUNS["green"][2])
    green_ok = (green.get("event") == "document_rejected"
                and green.get("reason") == "document_digest_mismatch"
                and green.get("signature_verified") is True
                and green.get("chunk_calls") == 0 and green.get("writes") == 0
                and green_store.get("files") == [] and green_store.get("chunks") == [])
    lab.check("green", "The signed path rejects the alternate bytes before chunking or writes",
              green_ok, {"signature_valid_manifest_rejected_for_bytes": green_ok,
                         "reason": green.get("reason"),
                         "chunk_calls": green.get("chunk_calls"),
                         "writes": green.get("writes"),
                         "persisted_files": green_store.get("files", [])})

    positive = _start_ingest(lab, image, "positive", *RUNS["positive"], verifier)
    persisted = _observer(lab, image, "rag-positive-observer", RUNS["positive"][2])
    receipt = persisted.get("receipt", {})
    vectors = persisted.get("index", {}).get("vectors", [])
    retrieval = persisted.get("retrieval", {})
    approved_hash = hashlib.sha256(
        (HERE / "approved_document.txt").read_bytes()).hexdigest()
    manifest_hash = hashlib.sha256((HERE / "manifest.json").read_bytes()).hexdigest()
    positive_ok = (
        positive.get("event") == "ingested" and positive.get("signature_verified") is True
        and positive.get("chunk_count") == 2 and positive.get("writes") == 5
        and persisted.get("files") == EXPECTED_FILES
        and [row.get("text") for row in persisted.get("chunks", [])] == EXPECTED_CHUNKS
        and receipt.get("source_id") == "synthetic://field-notes/orchid-river/42"
        and receipt.get("document_sha256") == approved_hash
        and receipt.get("signature_verified") is True
        and receipt.get("issuer") == "Synthetic Data Steward"
        and receipt.get("key_id") == "saf-rag-lab-ecdsa-v1"
        and receipt.get("issued_at") == "2026-01-01T00:00:00Z"
        and receipt.get("expires_at") == "2035-01-01T00:00:00Z"
        and _receipt_time_valid(receipt.get("retrieved_at"))
        and receipt.get("manifest_sha256") == manifest_hash
        and receipt.get("signature_sha256") == signature_hash
        and receipt.get("chunk_digests") == [
            {"chunk_id": row["chunk_id"], "chunk_sha256": row["chunk_sha256"]}
            for row in persisted.get("chunks", [])]
        and receipt.get("vector_index_sha256") == hashlib.sha256(
            json.dumps(persisted.get("index", {}), sort_keys=True,
                       separators=(",", ":")).encode("utf-8")).hexdigest()
        and vectors == [
            {"chunk_id": "chunk-001", "chunk_sha256": persisted["chunks"][0]["chunk_sha256"],
             "vector": [1, 1, 1, 1, 0, 0, 0]},
            {"chunk_id": "chunk-002", "chunk_sha256": persisted["chunks"][1]["chunk_sha256"],
             "vector": [0, 1, 0, 0, 1, 1, 0]},
        ]
        and retrieval.get("chunk_id") == "chunk-001" and retrieval.get("score") == 1
        and retrieval.get("chunk_sha256") == persisted["chunks"][0]["chunk_sha256"]
    )
    lab.check("positive", "The approved document persists expected chunks, vectors, receipt, and retrieval",
              positive_ok, {"approved_digest_match": receipt.get("document_sha256") == approved_hash,
                            "expected_chunks_persisted":
                            [row.get("text") for row in persisted.get("chunks", [])] == EXPECTED_CHUNKS,
                            "source_receipt_valid": positive_ok and _receipt_time_valid(
                                receipt.get("retrieved_at")),
                            "vector_index_persisted": len(vectors) == 2,
                            "retrieval_access_verified": retrieval.get("chunk_id") == "chunk-001",
                            "storage_files": persisted.get("files", [])})

    evidence = {
        "schema": "saf-k8s-0909-014-observations/1",
        "source_id": "synthetic://field-notes/orchid-river/42",
        "red": {"alternate_accepted_without_signature_check": red_ok,
                "chunks_persisted": len(red_store.get("chunks", []))},
        "green": {"signature_gate": invalid, "valid_manifest_rejected_for_document_digest_mismatch": green_ok,
                  "chunk_calls": green.get("chunk_calls", 0),
                  "writes": green.get("writes", 0),
                  "persisted_files": green_store.get("files", [])},
        "positive": {"approved_document_accepted": positive_ok,
                     "expected_chunks_persisted":
                     [row.get("text") for row in persisted.get("chunks", [])] == EXPECTED_CHUNKS,
                     "source_receipt_present": bool(receipt),
                     "retrieval_chunk_id": retrieval.get("chunk_id"),
                     "vector_entries": len(vectors)},
    }
    (lab.evidence / "rag-provenance-observations.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n")
