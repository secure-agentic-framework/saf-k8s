"""Bind workload purpose to a fixed synthetic reviewed record."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path

from fixtures import BUSYBOX_IMAGE

SCOPE = 'A live Job, Deployment, Pods, Node and EndpointSlice are correlated with a reviewed fixture purpose record and fictional node and container inventories. A private in-cluster request reaches the actual inference fixture. GPU/driver presence and public reachability require separate evidence. A scoped immutable synthetic purpose record binds exact workload, Pod, image and owner identities. Missing, expired and mismatched records receive unknown or conflict outcomes. Live organizational authorization and real inventory are separate assessment responsibilities.'
HERE = Path(__file__).resolve().parent
BASE_CASE = HERE / "base_case.py"
RECORD_NAME = "saf-0604-008-reviewed-purpose-record"
SOURCE_URI = "fixture://saf-k8s/SAF-K8S-0604-008/purpose-ledger"
SOURCE_REVISION = "fixture-purpose-ledger-v1"
AS_OF = "2026-11-26T00:00:00Z"
REVIEWED_AT = "2026-11-25T00:00:00Z"
VALID_UNTIL = "2026-12-02T00:00:00Z"
ALLOWED_PURPOSES = {"training", "inference"}


def load_base():
    spec = importlib.util.spec_from_file_location("saf_0604_008_published_base", BASE_CASE)
    if spec is None or spec.loader is None:
        raise RuntimeError("Published 0604-008 case snapshot could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def controller_refs(obj):
    return [{"api_version": row.get("apiVersion"), "kind": row.get("kind"),
             "name": row.get("name"), "uid": row.get("uid")}
            for row in obj.get("metadata", {}).get("ownerReferences", [])
            if row.get("controller") is True]


def live_subject(workload, pod, owner_chain):
    container_spec = workload["spec"].get("template", {}).get("spec", {}).get("containers", [])
    statuses = pod.get("status", {}).get("containerStatuses", [])
    image_ref = container_spec[0].get("image") if len(container_spec) == 1 else None
    image_id = statuses[0].get("imageID") if len(statuses) == 1 else None
    return {
        "kind": workload["kind"],
        "name": workload["metadata"].get("name"),
        "workload_uid": workload["metadata"].get("uid"),
        "pod_uid": pod["metadata"].get("uid"),
        "image_ref": image_ref,
        "image_id": image_id,
        "owner_chain": owner_chain,
    }


def classify_record(raw_bytes, expected_sha256, live, as_of=AS_OF):
    if not raw_bytes or not expected_sha256:
        return "unknown"
    if hashlib.sha256(raw_bytes).hexdigest() != expected_sha256:
        return "unknown"
    try:
        record = json.loads(raw_bytes)
        decision_time = iso(as_of)
        reviewed_at = iso(record["reviewed_at"])
        valid_until = iso(record["valid_until"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return "unknown"
    if (record.get("schema_version") != 1
            or record.get("source_uri") != SOURCE_URI
            or record.get("source_revision") != SOURCE_REVISION
            or reviewed_at > decision_time or decision_time >= valid_until):
        return "unknown"
    entries = [row for row in record.get("entries", [])
               if row.get("kind") == live.get("kind") and row.get("name") == live.get("name")]
    if not entries:
        return "unknown"
    if len(entries) != 1:
        return "conflict"
    entry, = entries
    exact_fields = ("workload_uid", "pod_uid", "image_ref", "image_id", "owner_chain")
    if any(not live.get(field) for field in exact_fields):
        return "unknown"
    if any(entry.get(field) != live.get(field) for field in exact_fields):
        return "conflict"
    purpose = entry.get("purpose")
    return purpose if purpose in ALLOWED_PURPOSES else "unknown"


def make_entry(purpose, subject):
    return {"kind": subject["kind"], "name": subject["name"], "purpose": purpose,
            **{field: subject[field] for field in (
                "workload_uid", "pod_uid", "image_ref", "image_id", "owner_chain")}}


def expected_matrix(record_bytes, record_sha, training, inference):
    record = json.loads(record_bytes)
    expired = deepcopy(record)
    expired["valid_until"] = "2026-11-25T23:59:59Z"
    wrong_revision = deepcopy(record)
    wrong_revision["source_revision"] = "fixture-purpose-ledger-old"
    wrong_image = deepcopy(record)
    next(row for row in wrong_image["entries"] if row["name"] == inference["name"])["image_ref"] = (
        "docker.io/library/busybox:wrong@sha256:" + "0" * 64)
    wrong_owner = deepcopy(record)
    next(row for row in wrong_owner["entries"] if row["name"] == training["name"])["owner_chain"][0]["uid"] = (
        "00000000-0000-0000-0000-000000000000")
    duplicate = deepcopy(record)
    duplicate["entries"].append(deepcopy(duplicate["entries"][0]))
    tampered_bytes = record_bytes.replace(b"fixture-purpose-ledger-v1", b"fixture-purpose-ledger-v2")
    return {
        "valid_training": classify_record(record_bytes, record_sha, training),
        "valid_inference": classify_record(record_bytes, record_sha, inference),
        "missing_record": classify_record(None, None, inference),
        "expired_record": classify_record(canonical_bytes(expired),
                                          hashlib.sha256(canonical_bytes(expired)).hexdigest(), inference),
        "unknown_revision": classify_record(canonical_bytes(wrong_revision),
                                             hashlib.sha256(canonical_bytes(wrong_revision)).hexdigest(), inference),
        "misbound_image": classify_record(canonical_bytes(wrong_image),
                                           hashlib.sha256(canonical_bytes(wrong_image)).hexdigest(), inference),
        "misbound_owner": classify_record(canonical_bytes(wrong_owner),
                                           hashlib.sha256(canonical_bytes(wrong_owner)).hexdigest(), training),
        "duplicate_subject": classify_record(canonical_bytes(duplicate),
                                              hashlib.sha256(canonical_bytes(duplicate)).hexdigest(), training),
        "tampered_record_bytes": classify_record(tampered_bytes, record_sha, inference),
        "wrong_exact_image_pin": classify_record(record_bytes, record_sha,
                                                   {**inference, "image_ref": BUSYBOX_IMAGE + "-other"}),
    }


def run(lab):
    base = load_base()
    base.run(lab)
    training_job = base.load(lab, "job", base.TRAIN)
    inference_deployment = base.load(lab, "deployment", base.SERVE)
    training_pod, = base.load(lab, "pods", "-l", f"app={base.TRAIN}")["items"]
    inference_pod, = base.load(lab, "pods", "-l", f"app={base.SERVE}")["items"]
    inference_rs, = base.load(lab, "rs", "-l", f"app={base.SERVE}")["items"]

    training_owner_chain = controller_refs(training_pod)
    inference_owner_chain = controller_refs(inference_pod) + controller_refs(inference_rs)
    if (not base.owner_is(training_pod, training_job)
            or not base.owner_is(inference_pod, inference_rs)
            or not base.owner_is(inference_rs, inference_deployment)
            or not training_owner_chain or len(inference_owner_chain) != 2):
        lab.block("The case-owned owner chains cannot be bound into the synthetic purpose record")

    training = live_subject(training_job, training_pod, training_owner_chain)
    inference = live_subject(inference_deployment, inference_pod, inference_owner_chain)
    if (training["image_ref"] != BUSYBOX_IMAGE or inference["image_ref"] != BUSYBOX_IMAGE
            or not training["image_id"] or not inference["image_id"]):
        lab.block("Purpose record requires the exact pinned fixture image and observed runtime IDs")

    record = {
        "schema_version": 1,
        "source_uri": SOURCE_URI,
        "source_revision": SOURCE_REVISION,
        "reviewed_at": REVIEWED_AT,
        "valid_until": VALID_UNTIL,
        "evaluation_time": AS_OF,
        "entries": [make_entry("training", training), make_entry("inference", inference)],
    }
    record_bytes = canonical_bytes(record)
    record_sha = hashlib.sha256(record_bytes).hexdigest()
    created = lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                          "metadata": {"name": RECORD_NAME}, "immutable": True,
                          "data": {"record.json": record_bytes.decode("utf-8")}})
    persisted = base.load(lab, "configmap", RECORD_NAME)
    persisted_bytes = persisted.get("data", {}).get("record.json", "").encode("utf-8")
    readback_exact = (persisted_bytes == record_bytes
                      and hashlib.sha256(persisted_bytes).hexdigest() == record_sha)
    immutable_named = (persisted.get("immutable") is True
                       and persisted.get("metadata", {}).get("name") == RECORD_NAME
                       and persisted.get("metadata", {}).get("uid") ==
                       created.get("metadata", {}).get("uid"))

    matrix = expected_matrix(persisted_bytes, record_sha, training, inference)
    expected = {
        "valid_training": "training",
        "valid_inference": "inference",
        "missing_record": "unknown",
        "expired_record": "unknown",
        "unknown_revision": "unknown",
        "misbound_image": "conflict",
        "misbound_owner": "conflict",
        "duplicate_subject": "conflict",
        "tampered_record_bytes": "unknown",
        "wrong_exact_image_pin": "conflict",
    }
    matched = immutable_named and readback_exact and matrix == expected
    lab.check("supplement", "Immutable reviewed purpose record binds exact workload, owner and image identities",
              matched,
              {"record_named_and_immutable": immutable_named,
               "record_readback_hash_matches": readback_exact,
               "valid_training_record": matrix["valid_training"],
               "valid_inference_record": matrix["valid_inference"],
               "missing_or_expired_record_unknown": matrix["missing_record"] == "unknown"
               and matrix["expired_record"] == "unknown",
               "unknown_source_revision_unknown": matrix["unknown_revision"] == "unknown",
               "misbound_owner_or_image_conflict": matrix["misbound_image"] == "conflict"
               and matrix["misbound_owner"] == "conflict"
               and matrix["wrong_exact_image_pin"] == "conflict",
               "duplicate_subject_conflict": matrix["duplicate_subject"] == "conflict",
               "tampered_record_unknown": matrix["tampered_record_bytes"] == "unknown"})

    (lab.evidence / "purpose-provenance.raw.json").write_text(json.dumps({
        "configmap_uid": persisted.get("metadata", {}).get("uid"),
        "configmap_resource_version": persisted.get("metadata", {}).get("resourceVersion"),
        "record_sha256": record_sha,
        "record_persisted_exact": readback_exact,
        "record_immutable": immutable_named,
        "record": record,
        "live_training_subject": training,
        "live_inference_subject": inference,
        "counterfactual_matrix": matrix,
    }, sort_keys=True, indent=2) + "\n")
