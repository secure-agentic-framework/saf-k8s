"""Exercise built-in PVC protection and fixed synthetic model lineage in saf-test."""
import hashlib
import json
import time


NAMESPACE = "saf-test"
PV_NAME = "saf-0905-006-model-volume"
PVC_NAME = "saf-0905-006-model-claim"
POD_NAME = "saf-0905-006-active-release"
NOTICE_ID = "fixture-dataset-deletion-001"
NOTICE_ANNOTATION = "saf-k8s.example/data-deletion-notice"
CORRECTION_ID = "fixture-dataset-correction-001"
CORRECTION_ANNOTATION = "saf-k8s.example/data-correction-notice"
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
ARCHIVE_BYTES = b"SAF inert model artifact fixture v1\n"
LINEAGE_VERSION = "fixture-lineage-v1"

# Explicit, fixed lineage graph. Edges point from source to every dependent.
# The archive copy is a dependent and receives the notice; control-unrelated is not.
LINEAGE = {
    "version": LINEAGE_VERSION,
    "nodes": [
        "fixture-dataset", "model-base", "model-derived", "release-active",
        "model-archive", "control-unrelated",
    ],
    "edges": {
        "fixture-dataset": ["model-base"],
        "model-base": ["model-derived", "model-archive"],
        "model-derived": ["release-active"],
        "release-active": [],
        "model-archive": [],
        "control-unrelated": [],
    },
    "dataset": "fixture-dataset",
    "unrelated": "control-unrelated",
}

SCOPE = (
    "Kubernetes v1.36.1 in the lab-created Kind cluster and namespace saf-test. "
    "A fixed static hostPath PV/PVC and one pinned BusyBox Pod prove that the built-in "
    "PVC-protection finalizer keeps a namespaced claim terminating while a nonterminal "
    "Pod references it, and that the claim and PV API objects can be removed after the Pod "
    "is gone. Separately, case-local fixture logic traverses the embedded fixture-lineage-v1 "
    "graph, annotates its source and every direct/transitive dependent ConfigMap, retrieves "
    "an inert archived ConfigMap value and compares its SHA-256, and leaves one unrelated "
    "control ConfigMap unmarked. This does not prove a model registry, production release "
    "controller, CycloneDX schema validation, ML-BOM ingestion, a general propagation service, "
    "cold or external storage, retention policy, physical or backup erasure, cryptographic "
    "erasure, regulatory compliance, or deletion outside these fixture Kubernetes objects."
)


def _save(lab, filename, value):
    (lab.evidence / filename).write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def direct_dependents(graph, source):
    return set(graph["edges"].get(source, []))


def transitive_dependents(graph, source):
    visited = set()
    pending = list(graph["edges"].get(source, []))
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        pending.extend(graph["edges"].get(current, []))
    return visited


def _get_json(lab, resource):
    return json.loads(lab.kubectl("get", resource, "-o", "json").stdout)


def _wait_for(lab, predicate, description, timeout=20):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(0.25)
    lab.block(f"Timed out waiting for {description}")


def _config_map(name, data, annotations=None):
    metadata = {"name": name, "namespace": NAMESPACE}
    if annotations:
        metadata["annotations"] = annotations
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata, "data": data}


def _make_lineage_objects(lab):
    initial = {
        "fixture-dataset": {"kind": "dataset", "lifecycle": "fixture"},
        "model-base": {"kind": "model", "lifecycle": "deprecated", "version": "1.0.0"},
        "model-derived": {"kind": "model", "lifecycle": "active", "version": "2.0.0"},
        "release-active": {"kind": "release", "lifecycle": "active", "version": "2.0.0"},
        "model-archive": {"kind": "archive-copy", "lifecycle": "archived", "version": "1.0.0"},
        "control-unrelated": {"kind": "unrelated-control", "lifecycle": "active", "version": "9.9.9"},
    }
    for name, values in initial.items():
        if name == "model-archive":
            values = {**values, "artifact.txt": ARCHIVE_BYTES.decode("utf-8"),
                      "artifactSha256": hashlib.sha256(ARCHIVE_BYTES).hexdigest()}
        lab.create(_config_map(name, values))

    archived = _get_json(lab, "configmap/model-archive")
    # This is fixed inert text, not model weights.
    actual = archived["data"]["artifact.txt"].encode("utf-8")
    expected = hashlib.sha256(ARCHIVE_BYTES).hexdigest()
    observed = hashlib.sha256(actual).hexdigest()
    checksum_ok = actual == ARCHIVE_BYTES and observed == expected
    _save(lab, "archive-checksum-retrieval.json", {
        "configmap": "model-archive", "fixture_bytes_utf8": actual.decode("utf-8"),
        "expected_sha256": expected, "retrieved_sha256": observed,
        "matched": checksum_ok, "claim": "retrieved inert ConfigMap value matches fixture digest",
    })
    lab.check("green", "The retrieved inert archive value matches its fixed SHA-256",
              checksum_ok, {"matched": checksum_ok, "sha256": observed})
    return archived


def _lineage_notice(lab):
    source = LINEAGE["dataset"]
    expected = {source, "model-base", "model-derived", "release-active", "model-archive"}
    baseline = {source, *direct_dependents(LINEAGE, source)}

    def mark(names):
        for name in sorted(names):
            lab.kubectl("annotate", "configmap", name, f"{NOTICE_ANNOTATION}={NOTICE_ID}", "--overwrite")

    def read_notices():
        observed = {}
        for name in sorted(LINEAGE["nodes"]):
            obj = _get_json(lab, f"configmap/{name}")
            observed[name] = obj.get("metadata", {}).get("annotations", {}).get(NOTICE_ANNOTATION)
        return observed

    mark(baseline)
    before = read_notices()
    recorded = {name for name, notice in before.items() if notice == NOTICE_ID}
    _save(lab, "lineage-graph.json", LINEAGE)
    _save(lab, "lineage-direct-only-baseline.json", {"direct_only": sorted(recorded), "missed": sorted(expected - recorded)})
    lab.check("red", "Persisting notices for only immediate lineage edges misses the known downstream artifacts",
              recorded == {source, "model-base"} and expected - recorded == {"model-derived", "release-active", "model-archive"},
              {"direct_only": sorted(recorded), "missed_transitive": sorted(expected - recorded)})

    mark({source, *transitive_dependents(LINEAGE, source)})
    observed = read_notices()
    expected_marked = expected
    actual_marked = {name for name, notice in observed.items() if notice == NOTICE_ID}
    complete = actual_marked == expected_marked
    _save(lab, "lineage-notice-runtime-evidence.json", {
        "lineage_version": LINEAGE_VERSION, "notice_id": NOTICE_ID,
        "expected_marked": sorted(expected_marked), "observed_notice_by_node": observed,
        "complete_and_bounded": complete,
    })
    lab.check("green", "The fixture traversal marks source plus every direct/transitive dependent",
              complete, {"expected": sorted(expected_marked), "observed": sorted(actual_marked)})
    lab.check("positive", "The unrelated control fixture remains unmarked",
              observed[LINEAGE["unrelated"]] is None,
              {"node": LINEAGE["unrelated"], "notice": observed[LINEAGE["unrelated"]]})

    # Reuse only the fixed synthetic graph to check the separate correction
    # notice type. This marks API metadata; it does not alter or retrain data.
    def mark_correction(names):
        for name in sorted(names):
            lab.kubectl("annotate", "configmap", name,
                        f"{CORRECTION_ANNOTATION}={CORRECTION_ID}", "--overwrite")

    def read_correction_notices():
        return {
            name: (_get_json(lab, f"configmap/{name}")
                   .get("metadata", {}).get("annotations", {})
                   .get(CORRECTION_ANNOTATION))
            for name in sorted(LINEAGE["nodes"])
        }

    correction_expected = {source, *transitive_dependents(LINEAGE, source)}
    correction_direct = {source, *direct_dependents(LINEAGE, source)}
    mark_correction(correction_direct)
    correction_before = read_correction_notices()
    correction_missed = {
        name for name in correction_expected
        if correction_before[name] != CORRECTION_ID
    }
    mark_correction(correction_expected)
    correction_after = read_correction_notices()
    correction_recorded = {
        name for name, notice in correction_after.items()
        if notice == CORRECTION_ID
    }
    correction_ok = (correction_missed == correction_expected - correction_direct
                     and correction_recorded == correction_expected
                     and correction_after[LINEAGE["unrelated"]] is None)
    _save(lab, "lineage-correction-notice-runtime-evidence.json", {
        "lineage_version": LINEAGE_VERSION,
        "notice_type": "synthetic-data-correction",
        "expected_marked": sorted(correction_expected),
        "direct_only_missed": sorted(correction_missed),
        "observed_marked": sorted(correction_recorded),
        "unrelated_unmarked": correction_after[LINEAGE["unrelated"]] is None,
        "meaning": "metadata notice propagation on a fixed synthetic graph only",
    })
    lab.check("green", "Correction notice reaches all fixed transitive dependents and leaves unrelated record unmarked",
              correction_ok,
              {"expected": sorted(correction_expected),
               "direct_only_missed": sorted(correction_missed),
               "observed": sorted(correction_recorded),
               "unrelated_unmarked": correction_after[LINEAGE["unrelated"]] is None})


def _lifecycle_objects(lab):
    pv = {
        "apiVersion": "v1", "kind": "PersistentVolume",
        "metadata": {"name": PV_NAME, "labels": {"saf-k8s.example/fixture": "0905-006"}},
        "spec": {
            "capacity": {"storage": "1Mi"}, "accessModes": ["ReadWriteOnce"],
            "persistentVolumeReclaimPolicy": "Retain", "storageClassName": "",
            "hostPath": {"path": "/tmp/saf-0905-006-fixture", "type": "DirectoryOrCreate"},
        },
    }
    claim = {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": PVC_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/fixture": "0905-006"}},
        "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Mi"}},
                 "storageClassName": "", "volumeName": PV_NAME},
    }
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": POD_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/model-release": "release-active"}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "containers": [{
            "name": "fixture-reference", "image": BUSYBOX_IMAGE,
            "command": ["sh", "-c", "sleep 3600"],
            "securityContext": {"allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                                "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumeMounts": [{"name": "model", "mountPath": "/fixture", "readOnly": True}],
        }], "volumes": [{"name": "model", "persistentVolumeClaim": {"claimName": PVC_NAME}}]},
    }
    lab.create(pv)
    lab.create(claim)
    lab.create(pod)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{POD_NAME}", "--timeout=90s", timeout=100)
    stored = _get_json(lab, f"pvc/{PVC_NAME}")
    bound = stored.get("status", {}).get("phase") == "Bound"
    protected = "kubernetes.io/pvc-protection" in stored.get("metadata", {}).get("finalizers", [])
    _save(lab, "release-reference-before-delete.json", {
        "pod": POD_NAME, "pod_phase": _get_json(lab, f"pod/{POD_NAME}").get("status", {}).get("phase"),
        "claim": PVC_NAME, "claim_phase": stored.get("status", {}).get("phase"),
        "finalizers": stored.get("metadata", {}).get("finalizers", []),
        "bound_and_protected": bound and protected,
    })
    if not (bound and protected):
        lab.block("Fixture Pod did not become Ready with a bound, PVC-protected claim")

    lab.kubectl("delete", "pvc", PVC_NAME, "--wait=false")
    deleting = _wait_for(lab, lambda: _get_json(lab, f"pvc/{PVC_NAME}")
                         if _has_deletion_timestamp(lab, PVC_NAME) else None,
                         "PVC deletion timestamp while its release Pod still references it")
    still_protected = ("kubernetes.io/pvc-protection" in deleting.get("metadata", {}).get("finalizers", [])
                       and deleting.get("metadata", {}).get("deletionTimestamp") is not None)
    _save(lab, "pvc-retirement-blocked-runtime-evidence.json", {
        "pod": POD_NAME, "claim": PVC_NAME,
        "deletion_timestamp": deleting.get("metadata", {}).get("deletionTimestamp"),
        "finalizers": deleting.get("metadata", {}).get("finalizers", []),
        "claim_still_exists_while_referenced": True,
    })
    lab.check("green", "PVC retirement remains pending while the active release Pod references the claim",
              still_protected, {"deletion_timestamp_present": bool(deleting.get("metadata", {}).get("deletionTimestamp")),
                                "pvc_protection_finalizer": still_protected})

    lab.kubectl("delete", "pod", POD_NAME, "--wait=true", "--timeout=60s", timeout=70)
    _wait_for(lab, lambda: _not_found(lab, f"pvc/{PVC_NAME}"),
              "PVC protection controller to remove the claim after Pod release", timeout=30)
    lab.kubectl("delete", "pv", PV_NAME, "--wait=true", "--timeout=30s", timeout=40)
    _wait_for(lab, lambda: _not_found(lab, f"pv/{PV_NAME}"), "fixture PV API object deletion", timeout=20)
    _save(lab, "logical-deletion-runtime-evidence.json", {
        "pod_deleted": True, "pvc_api_object_absent": True, "pv_api_object_absent": True,
        "reclaim_policy": "Retain",
        "meaning": "fixture Kubernetes API objects were removed; backing node data was not inspected or erased",
    })
    lab.check("positive", "After the Pod reference ends, the claim and fixture PV API objects can be removed",
              True, {"pod_deleted": True, "pvc_api_object_absent": True, "pv_api_object_absent": True,
                     "physical_erasure_claimed": False})


def _has_deletion_timestamp(lab, name):
    try:
        return bool(_get_json(lab, f"pvc/{name}").get("metadata", {}).get("deletionTimestamp"))
    except Exception:
        return False


def _not_found(lab, resource):
    result = lab.kubectl("get", resource, allow_failure=True)
    if result.returncode == 0:
        return False
    response = (result.stdout + result.stderr).lower()
    if "notfound" in response or "not found" in response:
        return True
    lab.block(f"Could not confirm absence of fixture object {resource}")


def run(lab):
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server_version = version.get("serverVersion", {}).get("gitVersion")
    if server_version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server_version!r}")
    _save(lab, "kubernetes-version.json", version)

    # All names and content below are inert fixture strings or API objects.
    _make_lineage_objects(lab)
    _lineage_notice(lab)
    _lifecycle_objects(lab)

    # Retirement of synthetic model ConfigMaps is API-object deletion only.
    for name in ("release-active", "model-derived", "model-base"):
        lab.kubectl("delete", "configmap", name, "--wait=true", "--timeout=20s", timeout=30)
    archive = _get_json(lab, "configmap/model-archive")
    retained = (archive["data"].get("artifact.txt") == ARCHIVE_BYTES.decode()
                and archive["metadata"].get("annotations", {}).get(NOTICE_ANNOTATION) == NOTICE_ID)
    retired = all(_not_found(lab, f"configmap/{name}") for name in ("release-active", "model-derived", "model-base"))
    lab.check("positive", "After logical retirement the archived bytes and propagated notice are still retrievable",
              retained and retired, {"archive_preserved": retained, "retired_api_objects_absent": retired})
    _save(lab, "retired-model-api-objects.json", {
        "logically_deleted_configmaps": ["release-active", "model-derived", "model-base"],
        "archive_preserved": "model-archive", "dataset_preserved": "fixture-dataset",
        "unrelated_control_preserved": "control-unrelated",
        "meaning": "Kubernetes API object deletion only; backing data and replicas were not measured",
    })
