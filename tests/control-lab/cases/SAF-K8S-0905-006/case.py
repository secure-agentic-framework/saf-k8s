"""Exercise built-in PVC protection and fixed synthetic model lineage in saf-test."""
import hashlib
import json
from pathlib import Path
import time


NAMESPACE = "saf-test"
HERE = Path(__file__).resolve().parent
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
ZOT_IMAGE = (
    "ghcr.io/project-zot/zot:v2.1.23@sha256:"
    "9d3de83ac2099e6f4843045b4c9b65b7e8baf40f92d28f54906dee9d4d390fd7"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)
SOURCE_REPO = "saf-test/model-retire"
ARCHIVE_REPO = "saf-test/model-archive"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
LAYER_TYPE = "application/vnd.saf.fixture.model-bytes.v1"
CONFIG_TYPE = "application/vnd.oci.empty.v1+json"

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
    "control ConfigMap unmarked. An additive reference starts one case-owned internal Zot registry, "
    "archives the same inert bytes in a second repository, deletes the source repository manifest, "
    "and restores from archive readback by exact digest. Both repositories use the same ephemeral "
    "registry backend. This does not prove production archive independence, model registry policy, "
    "a production release controller, CycloneDX schema validation, ML-BOM ingestion, a general propagation service, "
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


def _expected_registry_manifest_digest():
    config = b"{}"
    layer_digest = "sha256:" + hashlib.sha256(ARCHIVE_BYTES).hexdigest()
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "artifactType": "application/vnd.saf.fixture.model.v1",
        "annotations": {
            "org.opencontainers.image.title": "saf-inert-lineage-fixture",
            "org.opencontainers.image.version": "1.0.0",
            "saf-k8s.example/lineage-version": LINEAGE_VERSION,
            "saf-k8s.example/lineage-source": LINEAGE["dataset"],
            "saf-k8s.example/lineage-node": "model-archive",
        },
        "config": {"mediaType": CONFIG_TYPE,
                   "digest": "sha256:" + hashlib.sha256(config).hexdigest(),
                   "size": len(config)},
        "layers": [{"mediaType": LAYER_TYPE, "digest": layer_digest,
                    "size": len(ARCHIVE_BYTES)}],
    }
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _oci_archive_restore(lab):
    registry_config = {
        "distSpecVersion": "1.1.0",
        "storage": {"rootDirectory": "/var/lib/registry", "gc": False},
        "http": {"address": "0.0.0.0", "port": "5000",
                 "accessControl": {"repositories": {
                     SOURCE_REPO: {"anonymousPolicy": ["read", "create", "delete"]},
                     ARCHIVE_REPO: {"anonymousPolicy": ["read", "create", "delete"]},
                 }}},
    }
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "model-archive-zot-config"}, "immutable": True,
                "data": {"config.json": json.dumps(registry_config, sort_keys=True)}})
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": "model-archive-zot"},
                "spec": {"replicas": 1,
                         "selector": {"matchLabels": {"app": "model-archive-zot"}},
                         "template": {"metadata": {"labels": {"app": "model-archive-zot"}},
                                      "spec": {"automountServiceAccountToken": False,
                                               "containers": [{"name": "zot", "image": ZOT_IMAGE,
                                                               "imagePullPolicy": "IfNotPresent",
                                                               "args": ["serve", "/etc/zot/config.json"],
                                                               "ports": [{"name": "registry", "containerPort": 5000}],
                                                               "readinessProbe": {"tcpSocket": {"port": 5000},
                                                                                  "periodSeconds": 1},
                                                               "resources": {"requests": {"cpu": "20m", "memory": "32Mi"},
                                                                             "limits": {"cpu": "200m", "memory": "192Mi"}},
                                                               "volumeMounts": [{"name": "config", "mountPath": "/etc/zot",
                                                                                 "readOnly": True},
                                                                                {"name": "data", "mountPath": "/var/lib/registry"}]}],
                                               "volumes": [{"name": "config", "configMap": {
                                                   "name": "model-archive-zot-config"}},
                                                   {"name": "data", "emptyDir": {"sizeLimit": "32Mi"}}]}}}})
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": "model-archive"},
                "spec": {"type": "ClusterIP", "selector": {"app": "model-archive-zot"},
                         "ports": [{"name": "registry", "port": 5000, "targetPort": 5000}]}})
    lab.kubectl("wait", "--for=condition=Available", "deployment/model-archive-zot",
                "--timeout=75s", timeout=85)

    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "model-archive-zot-probe"}, "immutable": True,
                "data": {"registry_probe.py": (HERE / "registry_probe.py").read_text()}})
    job_name = "model-archive-zot-probe"
    lab.create({"apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": job_name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 75,
                         "template": {"metadata": {"labels": {"app": job_name}},
                                      "spec": {"restartPolicy": "Never",
                                               "automountServiceAccountToken": False,
                                               "securityContext": {"runAsNonRoot": True,
                                                                   "runAsUser": 1000,
                                                                   "runAsGroup": 1000,
                                                                   "fsGroup": 1000,
                                                                   "seccompProfile": {"type": "RuntimeDefault"}},
                                               "containers": [{"name": "probe", "image": PYTHON_IMAGE,
                                                               "imagePullPolicy": "IfNotPresent",
                                                               "command": ["python", "-B", "/probe/registry_probe.py"],
                                                               "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                                             "limits": {"cpu": "100m", "memory": "64Mi"}},
                                                               "securityContext": {"allowPrivilegeEscalation": False,
                                                                                   "readOnlyRootFilesystem": True,
                                                                                   "capabilities": {"drop": ["ALL"]}},
                                                               "volumeMounts": [{"name": "probe", "mountPath": "/probe",
                                                                                 "readOnly": True}]}],
                                               "volumes": [{"name": "probe", "configMap": {
                                                   "name": "model-archive-zot-probe", "defaultMode": 292}}]}}}})
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        job = _get_json(lab, f"job/{job_name}")
        states = {condition["type"] for condition in job.get("status", {}).get("conditions", [])
                  if condition.get("status") == "True"}
        if "Failed" in states:
            lab.kubectl("logs", "job/" + job_name, allow_failure=True)
            lab.block("Case-owned OCI archive/restore probe failed")
        if "Complete" in states:
            try:
                observation = json.loads(lab.kubectl("logs", "job/" + job_name).stdout)
            except json.JSONDecodeError:
                lab.block("Case-owned OCI archive/restore probe did not emit stable JSON")
            break
        time.sleep(0.5)
    else:
        lab.block("Case-owned OCI archive/restore probe timed out")

    expected_manifest = _expected_registry_manifest_digest()
    expected_layer = hashlib.sha256(ARCHIVE_BYTES).hexdigest()
    verified = (
        observation.get("source_publish_status") == 201
        and observation.get("source_pull_digest_matches") is True
        and observation.get("archive_publish_status") == 201
        and observation.get("archive_manifest_digest") == expected_manifest
        and observation.get("source_delete_status") == 202
        and observation.get("source_manifest_absent_after_retirement") is True
        and observation.get("source_digest_absent_after_retirement") is True
        and observation.get("source_tag_absent_after_retirement") is True
        and observation.get("archive_readback_matches") is True
        and observation.get("archive_manifest_digest_after_retirement") == expected_manifest
        and observation.get("layer_sha256") == expected_layer
        and observation.get("layer_bytes_match") is True
        and observation.get("lineage_version") == LINEAGE_VERSION
        and observation.get("lineage_source") == LINEAGE["dataset"]
        and observation.get("lineage_node") == "model-archive"
        and observation.get("restore_publish_status") == 201
        and observation.get("restored_manifest_digest") == expected_manifest
        and observation.get("restored_layer_sha256") == expected_layer
        and observation.get("restore_matches") is True
        and observation.get("only_case_service_endpoint") is True
        and observation.get("raw_bytes_emitted") is False
        and observation.get("scope") == "one Zot instance; source and archive are separate repositories on the same ephemeral backend"
    )
    _save(lab, "oci-archive-restore-runtime-evidence.json", observation)
    lab.check("positive", "A fixed lineage-bound OCI artifact remains retrievable by digest after source retirement and restores from the archive repository",
              verified,
              {"matched": verified, "manifest_sha256": expected_manifest,
               "layer_sha256": expected_layer, "source_retired": observation.get("source_manifest_absent_after_retirement") is True,
               "archive_readback": observation.get("archive_readback_matches") is True,
               "restored": observation.get("restore_matches") is True,
               "backend_scope": observation.get("scope")})


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
    _oci_archive_restore(lab)
