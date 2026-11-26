"""Live Kubernetes training-data provenance fixture for SAF-K8S-0906-006."""
import importlib.util
import json
from pathlib import Path

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
    "trains and binds an artifact only when approval digests and receipt lineage match exactly."
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


def _volumes():
    return ([{"name": "code", "configMap": {"name": CODE, "defaultMode": 0o444}}] +
            [{"name": key, "persistentVolumeClaim": {"claimName": claim}}
             for key, claim in CLAIMS.items()])


def _mounts(operation):
    writable = {
        "baseline": {"artifact"}, "ingest": {"source", "source-receipt"},
        "transform": {"transformed", "transform-receipt"}, "train": {"artifact"},
        "release": {"artifact"}, "write-mismatched-receipt": {"transform-receipt"},
    }.get(operation, set())
    paths = {"source": "/source", "source-receipt": "/source-receipt",
             "transformed": "/transformed", "transform-receipt": "/transform-receipt",
             "artifact": "/artifact"}
    return ([{"name": "code", "mountPath": "/fixture", "readOnly": True}] +
            [{"name": key, "mountPath": path, "readOnly": key not in writable} for key, path in paths.items()])


def _job(lab, image, name, operation, approval=False, extra_env=None):
    unit = {"name": "fixture", "image": image, "imagePullPolicy": "Never",
            "command": ["python", "/fixture/training_fixture.py", operation],
            "volumeMounts": _mounts(operation),
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
    return create(lab, "Job", name, "batch/v1", spec={
        "backoffLimit": 0, "ttlSecondsAfterFinished": 3600,
        "template": {"metadata": {"labels": {"app": name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [unit], "volumes": _volumes()}}})


def _result(lab, name):
    lab.kubectl("wait", "--for=condition=complete", "job/" + name, "--timeout=90s", timeout=100)
    lines = [line for line in lab.kubectl("logs", "job/" + name, timeout=20).stdout.splitlines() if line]
    return json.loads(lines[-1])


def _create_claims(lab):
    for claim in CLAIMS.values():
        create(lab, "PersistentVolumeClaim", claim, spec={
            "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}})


def run(lab):
    image = load_runtime(lab)
    source = (HERE / "training_fixture.py").read_text()
    create(lab, "ConfigMap", CODE, immutable=True, data={"training_fixture.py": source})
    _create_claims(lab)

    # This actual workload consumes every claim before a WaitForFirstConsumer
    # provisioner is asked to report Bound.
    _job(lab, image, NAME + "-volume-consumer", "bootstrap")
    for claim in CLAIMS.values():
        lab.kubectl("wait", "--for=jsonpath={.status.phase}=Bound", "pvc/" + claim,
                    "--timeout=120s", timeout=130)
    _result(lab, NAME + "-volume-consumer")

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
    _job(lab, image, ingest_name, "ingest")
    ingested = _result(lab, ingest_name)
    _job(lab, image, transform_name, "transform")
    transformed = _result(lab, transform_name)
    _job(lab, image, NAME + "-bad-edge", "write-mismatched-receipt")
    _result(lab, NAME + "-bad-edge")
    _job(lab, image, NAME + "-reject-edge", "train", approval=True)
    mismatch = _result(lab, NAME + "-reject-edge")
    _job(lab, image, NAME + "-restore-edge", "transform")
    _result(lab, NAME + "-restore-edge")
    _job(lab, image, train_name, "train", approval=True)
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
    }
    query_observed = {key: queried.get(key) for key in query_expected}
    lab.check("positive", "Read-only stored lineage queries resolve approved edges in both directions and exclude ungoverned or unknown inputs",
              query_observed == query_expected, query_observed)

    evidence = {
        "scope": "synthetic-local-kind-training-provenance",
        "red": red,
        "green": green,
        "positive": positive,
        "observations": {"ungoverned": baseline, "training_without_approval": denial,
                         "release_without_approval": release_denial, "denied_state": denied_state,
                         "ingest": ingested, "transform": transformed,
                         "training": trained, "release": released, "mismatched_edge": mismatch,
                         "read_only_lineage_query": query_observed},
    }
    (lab.evidence / "training-data-provenance.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n")
