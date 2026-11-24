"""Exercise synthetic Kubernetes AI asset inventory and live watch scope."""
import json
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import select
import subprocess
import time
from urllib.parse import urlencode

from fixtures import BUSYBOX_IMAGE


HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-1007-013-owned"
NEIGHBOR_NAMESPACE = "saf-1007-013-neighbor"
SERVICE_ACCOUNT = "asset-inventory-reader"
IDENTITY = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
PUBLISHER_ACCOUNT = "asset-inventory-publisher"
PUBLISHER_IDENTITY = f"system:serviceaccount:{NAMESPACE}:{PUBLISHER_ACCOUNT}"
PUBLISHER_ROLE = "asset-inventory-publisher"
PUBLICATION_RECORD = "typed-asset-inventory"
SNAPSHOT_READ_RULE = {"apiGroups": [""], "resources": ["configmaps"],
                      "resourceNames": [PUBLICATION_RECORD], "verbs": ["get"]}
REGISTRY_NAME = "distribution-registry"
REGISTRY_IMAGE = (
    "docker.io/library/registry:3.0.0@"
    "sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
REGISTRY_CLIENT = "registry-fixture-client"
REGISTRY_URL = f"http://{REGISTRY_NAME}.{NAMESPACE}.svc.cluster.local:5000"
REGISTRY_REPOSITORY = "saf-fixtures/synthetic-model"
REGISTRY_TAG = "fixture"
DRA_CLASS = "saf-synthetic-device-class"
DRA_DRIVER = "synthetic-dra.saf-k8s.example"
DRA_SLICE = "saf-synthetic-device-pool"
DRA_CLAIM = "owned-synthetic-dra-claim"
DRA_POD = "owned-synthetic-dra-consumer"
SELECTOR = "saf-k8s.example/control-1007-013=synthetic-owned"
REFERENCE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE_MAX_AGE_SECONDS = 60
SCOPE = (
    "Disposable Kind v1.36.1 cluster. Creates a case-owned namespace, a read-only service account "
    "Role/RoleBinding for ConfigMap list/watch in that namespace, synthetic ConfigMap records for "
    "model, dataset, pipeline, inference endpoint and GPU allocation metadata. Uses the service-account "
    "identity for an actual Kubernetes LIST and persistent WATCH, "
    "observes create/update/delete events, filters records by a synthetic ownership label, and confirms "
    "the identity is denied access to a separate namespace. The same reader lists actual typed "
    "Service, Job, PVC and ResourceClaim API objects; a deterministic fixture clock drives unknown, stale, "
    "last-good retention, recovery and relist reconciliation through a narrowly scoped Kubernetes "
    "publisher identity. A local Distribution registry supplies one deterministic synthetic OCI model "
    "source plus an inert versioned dataset manifest; synthetic DRA allocation is scheduler metadata "
    "with no physical device, and production source coverage remains adopter evidence."
)


def read_fixture():
    return json.loads((HERE / "fixtures" / "assets.json").read_text())


def resource(kind, name, namespace=None, **body):
    metadata = {"name": name, "labels": {"saf-k8s.example/control-1007-013": "fixture"}}
    if namespace:
        metadata["namespace"] = namespace
    return {"apiVersion": "v1", "kind": kind, "metadata": metadata, **body}


def asset_record(asset, namespace, revision="SYNTH-REVISION-001"):
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": asset["name"], "namespace": namespace,
            "labels": {
                "saf-k8s.example/control-1007-013": "synthetic-owned",
                "saf-k8s.example/asset-kind": asset["kind"],
            },
            "annotations": {"saf-k8s.example/asset-digest": asset["digest"]},
        },
        "data": {"display_name": asset["display_name"], "revision": revision,
                 "fixture_notice": "synthetic metadata only"},
    }


def save_raw(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def list_assets(lab):
    query = urlencode({"labelSelector": SELECTOR})
    endpoint = f"/api/v1/namespaces/{NAMESPACE}/configmaps?{query}"
    return json.loads(lab.kubectl("--as", IDENTITY, "get", "--raw", endpoint).stdout)


def start_watch(lab, resource_version):
    query = urlencode({"watch": "true", "labelSelector": SELECTOR,
                       "resourceVersion": resource_version})
    endpoint = f"/api/v1/namespaces/{NAMESPACE}/configmaps?{query}"
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", NAMESPACE, "--request-timeout=50s", "--as", IDENTITY,
        "get", "--raw", endpoint,
    ]
    with (lab.evidence / "commands.log").open("a") as log:
        log.write(f"$ kubectl get --raw {endpoint} with inventory reader impersonation\n")
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=lab.env, bufsize=0)


def next_watch_event(process, state, timeout=20):
    """Decode one JSON watch event from kubectl's streaming JSON output."""
    decoder = json.JSONDecoder()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        buffered = state["buffer"].lstrip()
        if buffered:
            try:
                event, end = decoder.raw_decode(buffered)
            except json.JSONDecodeError:
                event = None
            if event is not None:
                state["buffer"] = buffered[end:]
                return event
        if process.poll() is not None:
            error = process.stderr.read().decode("utf-8", "replace")
            raise RuntimeError(f"watch exited before expected event: {error.strip()}")
        ready, _, _ = select.select([process.stdout], [], [], min(0.5, deadline - time.monotonic()))
        if ready:
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("watch stream closed before expected event")
            state["buffer"] += chunk.decode("utf-8")
    raise TimeoutError("timed out waiting for Kubernetes watch event")


def wait_for_event(process, state, expected_type, expected_name):
    observed = []
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        event = next_watch_event(process, state, timeout=max(1, deadline - time.monotonic()))
        observed.append(event)
        obj = event.get("object", {})
        if (event.get("type") == expected_type
                and obj.get("metadata", {}).get("name") == expected_name):
            return event, observed
    raise TimeoutError(f"missing {expected_type} watch event for {expected_name}")


def _iso_time(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _typed_inventory(lab, reference_time):
    selector = urlencode({"labelSelector": SELECTOR})
    scopes = {
        "services": ("v1", "Service", f"/api/v1/namespaces/{NAMESPACE}/services"),
        "persistentvolumeclaims": ("v1", "PersistentVolumeClaim",
                                   f"/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims"),
        "jobs": ("batch/v1", "Job", f"/apis/batch/v1/namespaces/{NAMESPACE}/jobs"),
        "resourceclaims": ("resource.k8s.io/v1", "ResourceClaim",
                           f"/apis/resource.k8s.io/v1/namespaces/{NAMESPACE}/resourceclaims"),
    }
    observations = {}
    for source, (expected_version, kind, path) in scopes.items():
        source_identity = {
            "cluster_context": f"kind-{lab.cluster}", "api_version": expected_version,
            "kind": kind, "namespace": NAMESPACE, "selector": SELECTOR,
        }
        result = lab.kubectl("--as", IDENTITY, "get", "--raw", f"{path}?{selector}",
                             allow_failure=True)
        if result.returncode:
            if "(Forbidden)" not in result.stderr and " is forbidden" not in result.stderr:
                lab.block(f"Unexpected typed list failure for {source}")
            observations[source] = {
                "expected": True, "status": "unavailable", "capture_time": None,
                "cursor": None, "source_identity": source_identity, "assets": {},
                "observation_error": "Kubernetes LIST forbidden",
            }
            continue
        document = json.loads(result.stdout)
        api_version = document["apiVersion"]
        if api_version != expected_version:
            lab.block("The typed inventory returned an unexpected list API version")
        observations[source] = {
            "expected": True, "status": "fresh", "capture_time": _iso_time(reference_time),
            "cursor": document["metadata"]["resourceVersion"], "source_identity": source_identity,
            "assets": {
                (f"{row['metadata'].get('namespace', NAMESPACE)}/{row['metadata']['name']}"
                 if kind == "ResourceClaim" else row["metadata"]["name"]): {
                    "uid": row["metadata"]["uid"], "api_version": api_version,
                    "resource_version": row["metadata"]["resourceVersion"],
                    "definition": row["spec"],
                    **({"namespace": row["metadata"].get("namespace", NAMESPACE),
                        "claim_name": row["metadata"]["name"],
                        "annotations": row["metadata"].get("annotations", {}),
                        "reserved_for": row.get("status", {}).get("reservedFor", []),
                        "assigned_devices": [
                            {"request": item["request"], "driver": item["driver"],
                             "pool": item["pool"], "device_id": item["device"]}
                            for item in (row.get("status", {}).get("allocation", {})
                                         .get("devices", {}).get("results", []))
                        ]}
                       if kind == "ResourceClaim" else {}),
                } for row in document["items"]
            },
        }
    return observations


def _reconcile(previous, observations, expected_sources, reference_time):
    """Apply typed observations while retaining last-good records for source gaps."""
    snapshot = {"reference_time": _iso_time(reference_time), "expected_sources": sorted(expected_sources),
                "sources": {}}
    for source in sorted(expected_sources):
        observed = observations.get(source)
        old = (previous or {}).get("sources", {}).get(source, {})
        if observed and observed.get("status") == "fresh":
            source_state = dict(observed)
            source_state["status"] = "fresh"
        else:
            last_capture = old.get("capture_time")
            age = None
            if last_capture:
                captured_at = datetime.fromisoformat(last_capture.replace("Z", "+00:00"))
                age = (reference_time - captured_at).total_seconds()
            status = "unknown" if age is None else (
                "stale" if age > SOURCE_MAX_AGE_SECONDS else "fresh")
            source_state = {
                "expected": True, "status": status,
                "capture_time": last_capture, "cursor": old.get("cursor"),
                "source_identity": (observed or {}).get("source_identity", old.get("source_identity")),
                "assets": old.get("assets", {}),
                "observation_error": (observed or {}).get("observation_error", "source observation missing"),
            }
        source_state["gap"] = source_state["status"] != "fresh" or bool(source_state.get("observation_error"))
        snapshot["sources"][source] = source_state
    return snapshot


def _publish_snapshot(lab, record, snapshot, create=False):
    payload = {"data": {"inventory.json": json.dumps(snapshot, sort_keys=True)}}
    if create:
        obj = resource("ConfigMap", record, NAMESPACE, **payload)
        return _create_owned(lab, obj)
    lab.kubectl("--as", PUBLISHER_IDENTITY, "-n", NAMESPACE,
                "patch", "configmap", record, "--type=merge", "-p",
                json.dumps(payload))
    return json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", record, "-o", "json").stdout)



def _set_owned_job_collection(lab, enabled):
    common = {"apiGroups": [""], "resources": ["configmaps", "services", "persistentvolumeclaims"],
              "verbs": ["list", "watch"]}
    jobs = {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["list", "watch"]}
    claims = {"apiGroups": ["resource.k8s.io"], "resources": ["resourceclaims"],
              "verbs": ["list", "watch"]}
    rules = [common, SNAPSHOT_READ_RULE, jobs, claims] if enabled else [common, SNAPSHOT_READ_RULE, claims]
    lab.kubectl("-n", NAMESPACE, "patch", "role", "asset-inventory-reader", "--type=merge",
                "-p", json.dumps({"rules": rules}))
    expected_answer = "yes" if enabled else "no"
    for _ in range(20):
        observed = lab.kubectl("--as", IDENTITY, "-n", NAMESPACE, "auth", "can-i",
                               "list", "jobs.batch", allow_failure=True)
        if observed.stdout.strip() == expected_answer:
            return
        time.sleep(1)
    lab.block("The case-owned inventory reader's Job LIST permission did not settle")


def _create_owned(lab, item):
    result = lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json", payload=json.dumps(item))
    return json.loads(result.stdout)


def verify_typed_resync(lab):
    labels = dict([SELECTOR.split("=", 1)])
    service = resource("Service", "owned-inference-address", NAMESPACE,
                       spec={"ports": [{"port": 8080, "targetPort": 8080}]})
    claim = resource("PersistentVolumeClaim", "owned-dataset-reference", NAMESPACE,
                     spec={"storageClassName": "", "accessModes": ["ReadWriteOnce"],
                           "resources": {"requests": {"storage": "1Mi"}}})
    pipeline = resource("Job", "owned-pipeline-run", NAMESPACE,
                        spec={"suspend": True, "template": {"spec": {
                            "restartPolicy": "Never", "automountServiceAccountToken": False,
                            "containers": [{"name": "fixture", "image": BUSYBOX_IMAGE, "command": ["true"]}],
                        }}})
    pipeline["apiVersion"] = "batch/v1"
    for item in (service, claim, pipeline):
        item["metadata"]["labels"] = dict(labels)
    actuals = tuple(_create_owned(lab, item) for item in (service, claim, pipeline))
    expected_sources = ("services", "persistentvolumeclaims", "jobs", "resourceclaims")
    initial_observations = _typed_inventory(lab, REFERENCE_TIME)
    old = _reconcile(None, initial_observations, expected_sources, REFERENCE_TIME)
    by_kind = tuple(old["sources"][source]["assets"] for source in expected_sources[:3])
    exact = all(
        observed.get(obj["metadata"]["name"], {}).get("uid") == obj["metadata"]["uid"]
        for obj, observed in zip(actuals, by_kind)
    )
    lab.check("positive", "Read-only discovery links the actual Service, PVC and Job identities",
              exact, {"all_three_owned_typed_resource_uids_observed": exact})

    name = "typed-asset-inventory"
    denied = lab.kubectl("--as", IDENTITY, "-n", NAMESPACE, "create", "-f", "-",
                          "--dry-run=server", payload=json.dumps(
                              resource("ConfigMap", name, NAMESPACE,
                                       data={"inventory.json": json.dumps(old, sort_keys=True)})),
                          allow_failure=True)
    read_only = denied.returncode != 0 and "cannot create resource" in denied.stderr.lower()
    lab.check("red", "The inventory reader cannot create its publication record",
              read_only, {"reader_denied_publication": read_only})
    _set_owned_job_collection(lab, enabled=False)
    first_gap_observations = _typed_inventory(lab, REFERENCE_TIME)
    first_gap = _reconcile(None, first_gap_observations, expected_sources, REFERENCE_TIME)
    record = _publish_snapshot(lab, "typed-asset-inventory", first_gap, create=True)
    unknown_job = json.loads(record["data"]["inventory.json"])["sources"]["jobs"]
    unknown_check = {
        "unobserved_expected_source_is_unknown": unknown_job["expected"]
        and unknown_job["status"] == "unknown" and unknown_job["gap"],
            "expected_coverage_and_source_identity_recorded": (
            len(expected_sources) == 4 and bool(unknown_job.get("source_identity"))
        ),
    }
    save_raw(lab, "typed-inventory-unknown.raw.json", {
        "reference_time": _iso_time(REFERENCE_TIME), "source_observations": first_gap_observations,
        "published": json.loads(record["data"]["inventory.json"]), "checks": unknown_check,
    })
    lab.check("green", "An expected source without a first observation is reported unknown",
              all(unknown_check.values()), unknown_check)

    _set_owned_job_collection(lab, enabled=True)
    initial_observations = _typed_inventory(lab, REFERENCE_TIME)
    old = _reconcile(first_gap, initial_observations, expected_sources, REFERENCE_TIME)
    record = _publish_snapshot(lab, "typed-asset-inventory", old)
    last_good = json.loads(record["data"]["inventory.json"])
    if last_good["sources"]["jobs"]["status"] != "fresh":
        lab.block("The Job source must have a last-good capture before the freshness experiment")

    failure_time = REFERENCE_TIME + timedelta(seconds=120)
    _set_owned_job_collection(lab, enabled=False)
    unavailable = _typed_inventory(lab, failure_time)
    gap_snapshot = _reconcile(last_good, unavailable, expected_sources, failure_time)
    gap_persisted = _publish_snapshot(lab, name, gap_snapshot)
    gap = json.loads(gap_persisted["data"]["inventory.json"])
    stale_job = gap["sources"]["jobs"]
    gap_check = {
        "unavailable_owned_source_is_stale": stale_job["status"] == "stale" and stale_job["gap"],
        "last_good_job_cursor_and_assets_preserved": (
            stale_job["cursor"] == last_good["sources"]["jobs"]["cursor"]
            and stale_job["assets"] == last_good["sources"]["jobs"]["assets"]
        ),
        "gap_and_error_are_published": bool(stale_job.get("observation_error"))
        and gap_persisted["metadata"]["uid"] == record["metadata"]["uid"],
        "healthy_sources_remain_fresh": all(
            gap["sources"][source]["status"] == "fresh"
            for source in ("services", "persistentvolumeclaims", "resourceclaims")
        ),
    }
    save_raw(lab, "typed-inventory-gap.raw.json", {
        "reference_time": _iso_time(failure_time), "last_good": last_good,
        "source_observations": unavailable, "published": gap, "checks": gap_check,
    })
    lab.check("green", "An unavailable owned source reports stale status and retains last-good evidence",
              all(gap_check.values()), gap_check)

    recovery_time = REFERENCE_TIME + timedelta(seconds=121)
    _set_owned_job_collection(lab, enabled=True)
    recovered_observations = _typed_inventory(lab, recovery_time)
    recovered = _reconcile(gap, recovered_observations, expected_sources, recovery_time)
    recovered_persisted = _publish_snapshot(lab, name, recovered)
    recovered_record = json.loads(recovered_persisted["data"]["inventory.json"])
    recovery_check = {
        "owned_source_reobserved_fresh": recovered_record["sources"]["jobs"]["status"] == "fresh"
        and not recovered_record["sources"]["jobs"]["gap"],
        "capture_time_and_cursor_refreshed": (
            recovered_record["sources"]["jobs"]["capture_time"] == _iso_time(recovery_time)
            and bool(recovered_record["sources"]["jobs"]["cursor"])
        ),
        "all_expected_sources_fresh": all(
            recovered_record["sources"][source]["status"] == "fresh"
            for source in recovered_record["expected_sources"]
        ),
        "same_publication_record_updated": recovered_persisted["metadata"]["uid"] == record["metadata"]["uid"],
    }
    save_raw(lab, "typed-inventory-recovery.raw.json", {
        "reference_time": _iso_time(recovery_time), "source_observations": recovered_observations,
        "published": recovered_record, "checks": recovery_check,
    })
    lab.check("positive", "A successful re-observation clears the source gap through reconciliation",
              all(recovery_check.values()), recovery_check)

    change_started = time.monotonic()
    pipeline_name = pipeline["metadata"]["name"]
    service_name = service["metadata"]["name"]
    lab.kubectl("-n", NAMESPACE, "delete", "job", pipeline_name, "--wait=true")
    pipeline["metadata"]["name"] = "owned-pipeline-replacement"
    replacement = _create_owned(lab, pipeline)
    lab.kubectl("-n", NAMESPACE, "patch", "service", service_name, "--type=json", "-p",
                '[{"op":"replace","path":"/spec/ports/0/port","value":9090}]')
    updated_observations = _typed_inventory(lab, REFERENCE_TIME + timedelta(seconds=122))
    updated = _reconcile(recovered_record, updated_observations, expected_sources,
                         REFERENCE_TIME + timedelta(seconds=122))
    persisted = _publish_snapshot(lab, name, updated)
    current = json.loads(persisted["data"]["inventory.json"])
    elapsed = time.monotonic() - change_started
    observed = {
        "published_within_fixture_freshness_budget": elapsed < 60,
        "stale_snapshot_contained_pre_change_entities": (
            service_name in last_good["sources"]["services"]["assets"]
            and pipeline_name in last_good["sources"]["jobs"]["assets"]
        ),
        "modified_service_retains_identity_with_current_port": (
            current["sources"]["services"]["assets"][service_name]["uid"] == actuals[0]["metadata"]["uid"]
            and current["sources"]["services"]["assets"][service_name]["definition"]["ports"][0]["port"] == 9090
        ),
        "missing_job_removed_and_replacement_added": pipeline_name not in current["sources"]["jobs"]["assets"]
        and current["sources"]["jobs"]["assets"]["owned-pipeline-replacement"]["uid"] == replacement["metadata"]["uid"]
        and replacement["metadata"]["uid"] != actuals[2]["metadata"]["uid"],
        "existing_pvc_retained_and_snapshot_reconciled": current == updated
        and all(
            current["sources"]["persistentvolumeclaims"]["assets"][claim["metadata"]["name"]][field]
            == last_good["sources"]["persistentvolumeclaims"]["assets"][claim["metadata"]["name"]][field]
            for field in ("uid", "definition")
        )
        and persisted["metadata"]["uid"] == record["metadata"]["uid"],
        "fresh_source_cursors_and_capture_times_recorded": all(
            current["sources"][source]["cursor"]
            and current["sources"][source]["capture_time"] == _iso_time(REFERENCE_TIME + timedelta(seconds=122))
            and current["sources"][source]["status"] == "fresh"
            and current["sources"][source]["source_identity"]
            for source in current["expected_sources"]
        ),
    }
    save_raw(lab, "typed-inventory-resync.raw.json", {
        "before": old, "reconciled": current, "observed": observed,
        "fixture_elapsed_seconds": round(elapsed, 3), "fixture_budget_seconds": 60,
    })
    lab.check("green", "Typed API observations reconcile and publish the current owned inventory",
              all(observed.values()), observed)


def verify_dra_claim_reconciliation(lab):
    """Collect scheduler allocation metadata for an owned synthetic DRA claim."""
    marker = "saf-k8s.example/control-1007-013"
    device_id = "synthetic-device-001"
    device_class = {
        "apiVersion": "resource.k8s.io/v1", "kind": "DeviceClass",
        "metadata": {"name": DRA_CLASS},
        "spec": {"selectors": [{"cel": {"expression": f"device.driver == '{DRA_DRIVER}'"}}]},
    }
    resource_slice = {
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceSlice",
        "metadata": {"name": DRA_SLICE},
        "spec": {
            "driver": DRA_DRIVER,
            "pool": {"name": "saf-synthetic-pool", "generation": 1,
                     "resourceSliceCount": 1},
            "allNodes": True,
            "devices": [{"name": device_id, "attributes": {
                "saf-k8s.example/fixture": {"string": "synthetic-no-physical-device"}
            }}],
        },
    }
    claim = {
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceClaim",
        "metadata": {"name": DRA_CLAIM, "namespace": NAMESPACE,
                     "labels": {marker: "synthetic-owned"},
                     "annotations": {"saf-k8s.example/evidence-kind": "scheduler-metadata-only"}},
         "spec": {"devices": {"requests": [{"name": "synthetic-device", "exactly": {
                    "deviceClassName": DRA_CLASS, "allocationMode": "ExactCount", "count": 1}}]}},
    }
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": DRA_POD, "namespace": NAMESPACE,
                     "labels": {marker: "synthetic-owned"}},
        "spec": {"automountServiceAccountToken": False,
                 "restartPolicy": "Never",
                 "resourceClaims": [{"name": "synthetic-device", "resourceClaimName": DRA_CLAIM}],
                 "containers": [{"name": "fixture", "image": BUSYBOX_IMAGE,
                                 "command": ["true"],
                                 "resources": {"claims": [{"name": "synthetic-device"}]}}]},
    }
    lab.kubectl("apply", "-f", "-", payload=json.dumps(device_class))
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource_slice))
    _create_owned(lab, claim)
    allocated_pod = _create_owned(lab, pod)

    capture_time = REFERENCE_TIME + timedelta(seconds=123)
    observations = _typed_inventory(lab, capture_time)
    allocation = []
    for _ in range(30):
        claim_source = observations["resourceclaims"]
        entry = claim_source["assets"].get(f"{NAMESPACE}/{DRA_CLAIM}")
        allocation = (entry or {}).get("assigned_devices", [])
        if allocation and any(consumer.get("uid") == allocated_pod["metadata"]["uid"]
                              for consumer in (entry or {}).get("reserved_for", [])):
            break
        time.sleep(1)
        observations = _typed_inventory(lab, capture_time)
    if not allocation:
        lab.block("The scheduler did not publish a DRA allocation for the owned synthetic claim")

    record = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", PUBLICATION_RECORD,
                                    "-o", "json").stdout)
    previous = json.loads(record["data"]["inventory.json"])
    sources = set(previous["expected_sources"]) | {"resourceclaims"}
    allocated_snapshot = _reconcile(previous, observations, sources, capture_time)
    allocated_record = _publish_snapshot(lab, PUBLICATION_RECORD, allocated_snapshot)
    allocated_inventory = json.loads(allocated_record["data"]["inventory.json"])
    allocated_claim = allocated_inventory["sources"]["resourceclaims"]["assets"].get(
        f"{NAMESPACE}/{DRA_CLAIM}", {})
    exact_assignment = (allocated_claim.get("namespace") == NAMESPACE
                        and allocated_claim.get("claim_name") == DRA_CLAIM
                        and any(consumer.get("uid") == allocated_pod["metadata"]["uid"]
                                for consumer in allocated_claim.get("reserved_for", []))
                        and len(allocated_claim.get("assigned_devices", [])) == 1
                        and allocated_claim["assigned_devices"][0] == {
                            "request": "synthetic-device", "driver": DRA_DRIVER,
                            "pool": "saf-synthetic-pool", "device_id": device_id,
                        })
    lab.check("positive", "Owned ResourceClaim maps to its scheduler-assigned synthetic device",
              exact_assignment, {"namespace_claim_to_device_mapping": exact_assignment,
                                 "source": "native ResourceClaim allocation status",
                                 "classification": "synthetic scheduler metadata; no physical device"})

    update_time = capture_time + timedelta(seconds=1)
    update_marker = "SYNTH-DRA-REVISION-002"
    lab.kubectl("-n", NAMESPACE, "patch", "resourceclaim", DRA_CLAIM, "--type=merge", "-p",
                json.dumps({"metadata": {"annotations": {
                    "saf-k8s.example/revision": update_marker}}}))
    updated_observations = _typed_inventory(lab, update_time)
    updated_snapshot = _reconcile(allocated_inventory, updated_observations, sources, update_time)
    updated_record = _publish_snapshot(lab, PUBLICATION_RECORD, updated_snapshot)
    updated_inventory = json.loads(updated_record["data"]["inventory.json"])
    updated_claim = updated_inventory["sources"]["resourceclaims"]["assets"].get(
        f"{NAMESPACE}/{DRA_CLAIM}", {})
    update_check = (updated_claim.get("annotations", {}).get("saf-k8s.example/revision") == update_marker
                    and updated_claim.get("resource_version") != allocated_claim.get("resource_version")
                    and updated_claim.get("assigned_devices") == allocated_claim.get("assigned_devices")
                    and updated_record["metadata"]["uid"] == allocated_record["metadata"]["uid"])
    lab.check("positive", "ResourceClaim source updates reconcile through the scoped publisher",
              update_check, {"metadata_update_and_allocation_retained": update_check})

    remove_time = update_time + timedelta(seconds=1)
    lab.kubectl("-n", NAMESPACE, "delete", "pod", DRA_POD, "--wait=true", "--timeout=40s", timeout=50)
    lab.kubectl("-n", NAMESPACE, "delete", "resourceclaim", DRA_CLAIM, "--wait=true", "--timeout=50s", timeout=60)
    removed_observations = _typed_inventory(lab, remove_time)
    removed_snapshot = _reconcile(updated_inventory, removed_observations, sources, remove_time)
    removed_record = _publish_snapshot(lab, PUBLICATION_RECORD, removed_snapshot)
    removed_inventory = json.loads(removed_record["data"]["inventory.json"])
    removal_check = (f"{NAMESPACE}/{DRA_CLAIM}"
                     not in removed_inventory["sources"]["resourceclaims"]["assets"]
                     and removed_record["metadata"]["uid"] == allocated_record["metadata"]["uid"])
    save_raw(lab, "dra-resourceclaim-reconciliation.raw.json", {
        "source_identity": removed_inventory["sources"]["resourceclaims"]["source_identity"],
        "synthetic_device": {"driver": DRA_DRIVER, "pool": "saf-synthetic-pool",
                             "device_id": device_id, "physical_device": False},
        "allocated": allocated_claim, "updated": updated_claim,
        "removed_from_published_inventory": removal_check,
        "checks": {"exact_namespace_claim_device_mapping": exact_assignment,
                   "claim_update_reconciled": update_check,
                   "claim_removal_reconciled": removal_check},
    })
    lab.check("green", "ResourceClaim removal is reflected through the publication helper",
              removal_check, {"claim_absent_after_authoritative_relist": removal_check})


def _registry_client_command(lab, *arguments):
    with (lab.evidence / "commands.log").open("a") as log:
        log.write("$ kubectl -n " + NAMESPACE + " exec " + REGISTRY_CLIENT
                  + " -- python /fixture/registry_fixture.py " + REGISTRY_URL + " "
                  + REGISTRY_REPOSITORY + " " + REGISTRY_TAG + " " + " ".join(arguments) + "\n")
    return lab.kubectl("-n", NAMESPACE, "exec", REGISTRY_CLIENT, "-c", "fixture-client", "--", "python", "/fixture/registry_fixture.py",
                       REGISTRY_URL, REGISTRY_REPOSITORY, REGISTRY_TAG, *arguments)


def _registry_observation(lab, revision, reference_time):
    result = _registry_client_command(lab, "read")
    readback = json.loads(result.stdout)
    source_identity = {
        "source_type": "oci-registry-v2", "registry_service": REGISTRY_URL,
        "repository": REGISTRY_REPOSITORY, "manifest_reference": REGISTRY_TAG,
        "api": "GET /v2/<name>/manifests/<reference>",
    }
    digest = readback["manifest_digest"]
    expected_revision = f"SYNTH-REVISION-{revision:03d}"
    checks = {
        "manifest_digest_is_registry_response_digest": digest == readback["registry_digest_header"],
        "manifest_digest_matches_read_bytes": digest == readback["computed_manifest_digest"],
        "manifest_revision_read_back": readback["revision"] == expected_revision,
        "config_revision_read_back": readback["config_revision"] == expected_revision,
        "blob_digest_and_bytes_read_back": bool(readback.get("blob_digest"))
        and readback.get("blob_revision") == expected_revision
        and readback.get("config_revision") == expected_revision
        and readback.get("synthetic_marker") == "SYNTHETIC-OCI-MODEL-METADATA",
    }
    lab.check("positive", f"Local Registry API reads synthetic model revision {revision}",
              all(checks.values()), checks)
    return {
        "expected": True, "status": "fresh", "capture_time": _iso_time(reference_time),
        "cursor": digest, "source_identity": source_identity,
        "assets": {"synthetic-model": {
            "artifact_type": "application/vnd.oci.image.manifest.v1+json",
            "revision": readback["revision"], "manifest_digest": digest,
            "blob_digest": readback["blob_digest"],
        }},
    }, readback


def verify_registry_reconciliation(lab):
    first_write = json.loads(_registry_client_command(lab, "push", "1").stdout)
    first_time = REFERENCE_TIME + timedelta(seconds=126)
    first, first_readback = _registry_observation(lab, 1, first_time)
    record = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", PUBLICATION_RECORD,
                                    "-o", "json").stdout)
    previous = json.loads(record["data"]["inventory.json"])
    sources = set(previous["expected_sources"]) | {"oci_registry"}
    snapshot = _reconcile(previous, {**_typed_inventory(lab, first_time), "oci_registry": first},
                          sources, first_time)
    published = _publish_snapshot(lab, PUBLICATION_RECORD, snapshot)
    first_persisted = json.loads(published["data"]["inventory.json"])
    publisher_patch_ok = (
        published["metadata"]["uid"] == record["metadata"]["uid"]
        and first_persisted["sources"]["oci_registry"]["assets"]["synthetic-model"]["manifest_digest"]
        == first_readback["manifest_digest"]
    )
    lab.check("positive", "Publisher updates the dedicated inventory ConfigMap with registry source evidence",
              publisher_patch_ok, {"same_dedicated_record_updated": publisher_patch_ok,
                                    "publisher_identity": PUBLISHER_IDENTITY})

    read_only_patch = lab.kubectl(
        "--as", IDENTITY, "-n", NAMESPACE, "patch", "configmap", PUBLICATION_RECORD,
        "--type=merge", "-p", json.dumps({"data": {"reader_probe": "must-not-apply"}}),
        "--dry-run=server", allow_failure=True,
    )
    reader_patch_denied = (
        read_only_patch.returncode != 0
        and "(Forbidden)" in read_only_patch.stderr
        and "cannot patch" in read_only_patch.stderr
    )
    lab.check("red", "The inventory reader cannot change the dedicated snapshot",
              reader_patch_denied, {"reader_denied_snapshot_patch": reader_patch_denied})

    denied_lists = {}
    for resource_name in ("configmaps", "services", "persistentvolumeclaims", "jobs", "resourceclaims"):
        result = lab.kubectl("--as", PUBLISHER_IDENTITY, "-n", NAMESPACE, "get", resource_name,
                             "-o", "json", allow_failure=True)
        text = result.stdout + result.stderr
        denied_lists[resource_name] = result.returncode != 0 and "forbidden" in text.lower()

    other = lab.kubectl("-n", NAMESPACE, "get", "configmap", "unlabeled-neighbor",
                        "-o", "json").stdout
    other_before = json.loads(other)
    edit_other = lab.kubectl(
        "--as", PUBLISHER_IDENTITY, "-n", NAMESPACE, "patch", "configmap", "unlabeled-neighbor",
        "--type=merge", "-p", json.dumps({"data": {"publisher_probe": "must-not-apply"}}),
        allow_failure=True,
    )
    edit_text = edit_other.stdout + edit_other.stderr
    other_after = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", "unlabeled-neighbor",
                                        "-o", "json").stdout)
    denied_other_edit = (edit_other.returncode != 0 and "forbidden" in edit_text.lower()
                         and other_after.get("data") == other_before.get("data"))
    save_raw(lab, "publisher-boundary.raw.json", {
        "identity": PUBLISHER_IDENTITY, "authorized_action": "patch ConfigMap/typed-asset-inventory",
        "dedicated_record_uid": published["metadata"]["uid"],
        "list_denials": denied_lists,
        "different_configmap_patch": {"exit_code": edit_other.returncode,
                                       "response": edit_text, "object_unchanged": denied_other_edit},
        "reader_denied_snapshot_patch": reader_patch_denied,
    })
    publisher_boundary = all(denied_lists.values()) and denied_other_edit
    lab.check("red", "Publisher cannot list input resources or patch another ConfigMap",
              publisher_boundary, {"all_input_lists_denied": all(denied_lists.values()),
                                  "publisher_cannot_edit_other_object": denied_other_edit})

    second_write = json.loads(_registry_client_command(lab, "push", "2").stdout)
    second_time = first_time + timedelta(seconds=1)
    second, second_readback = _registry_observation(lab, 2, second_time)
    reconciled = _reconcile(
        first_persisted, {**_typed_inventory(lab, second_time), "oci_registry": second}, sources, second_time,
    )
    changed_publication = _publish_snapshot(lab, PUBLICATION_RECORD, reconciled)
    current = json.loads(changed_publication["data"]["inventory.json"])
    first_digest = first_persisted["sources"]["oci_registry"]["assets"]["synthetic-model"]["manifest_digest"]
    second_digest = current["sources"]["oci_registry"]["assets"]["synthetic-model"]["manifest_digest"]
    change_check = {
        "source_identity_stable": first_persisted["sources"]["oci_registry"]["source_identity"]
        == current["sources"]["oci_registry"]["source_identity"],
        "revision_changed": current["sources"]["oci_registry"]["assets"]["synthetic-model"]["revision"]
        == "SYNTH-REVISION-002",
        "authoritative_manifest_digest_changed": first_digest != second_digest
        and second_digest == second_readback["manifest_digest"],
        "same_publication_record_reconciled": changed_publication["metadata"]["uid"]
        == published["metadata"]["uid"],
        "all_sources_fresh_at_second_capture": all(
            row["status"] == "fresh" and not row["gap"] and row["capture_time"] == _iso_time(second_time)
            for row in current["sources"].values()
        ),
        "both_fixture_writes_are_deterministic": first_write["manifest_digest"] == first_digest
        and second_write["manifest_digest"] == second_digest,
    }
    save_raw(lab, "registry-source-reconciliation.raw.json", {
        "source_identity": current["sources"]["oci_registry"]["source_identity"],
        "initial_push": first_write, "initial_readback": first_readback,
        "initial_published": first_persisted["sources"]["oci_registry"],
        "changed_push": second_write, "changed_readback": second_readback,
        "reconciled_published": current["sources"]["oci_registry"],
        "checks": change_check,
    })
    lab.check("green", "Registry source revision and manifest digest reconcile through publisher path",
              all(change_check.values()), change_check)


def _dataset_manifest_observation(lab, reference_time):
    read = lab.kubectl("-n", NAMESPACE, "exec", REGISTRY_CLIENT, "-c", "fixture-client", "--",
                        "python", "/fixture/dataset_catalog.py", "read")
    received = json.loads(read.stdout)
    document = received["result"]
    selected = document["version"]
    canonical = json.dumps(selected["content"], sort_keys=True, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if digest != selected["digest"]:
        raise ValueError("dataset source content does not match its declared digest")
    identity = {**document["source_identity"], "service": "dataset-catalog"}
    return {
        "expected": True, "status": "fresh", "capture_time": _iso_time(reference_time),
        "cursor": selected["version"], "source_identity": identity,
        "assets": {document["dataset_id"]: {
            "dataset_id": document["dataset_id"], "version": selected["version"],
            "digest": digest, "change_history": selected["change_history"],
            "content_metadata": selected["content"], "response_etag": received["etag"],
            "synthetic_fixture": True,
        }},
    }


def verify_dataset_manifest_reconciliation(lab):
    """Reconcile an authoritative inert dataset manifest through the existing publisher."""
    record = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", PUBLICATION_RECORD,
                                    "-o", "json").stdout)
    previous = json.loads(record["data"]["inventory.json"])
    sources = set(previous["expected_sources"]) | {"authoritative_dataset_manifest"}
    first_time = REFERENCE_TIME + timedelta(seconds=128)
    first_source = _dataset_manifest_observation(lab, first_time)
    first_snapshot = _reconcile(previous, {
        **_typed_inventory(lab, first_time), "oci_registry": previous["sources"]["oci_registry"],
        "authoritative_dataset_manifest": first_source,
    },
                                sources, first_time)
    first_record = _publish_snapshot(lab, PUBLICATION_RECORD, first_snapshot)
    first_inventory = json.loads(first_record["data"]["inventory.json"])
    first_asset = first_inventory["sources"]["authoritative_dataset_manifest"]["assets"][
        "synthetic-dataset-001"]

    second_time = first_time + timedelta(seconds=1)
    lab.kubectl("-n", NAMESPACE, "exec", REGISTRY_CLIENT, "-c", "dataset-catalog", "--",
                "python", "/fixture/dataset_catalog.py", "advance")
    second_source = _dataset_manifest_observation(lab, second_time)
    second_snapshot = _reconcile(first_inventory,
                                 {**_typed_inventory(lab, second_time),
                                  "oci_registry": first_inventory["sources"]["oci_registry"],
                                  "authoritative_dataset_manifest": second_source},
                                 sources, second_time)
    changed_record = _publish_snapshot(lab, PUBLICATION_RECORD, second_snapshot)
    changed_inventory = json.loads(changed_record["data"]["inventory.json"])
    changed_source = changed_inventory["sources"]["authoritative_dataset_manifest"]
    changed_asset = changed_source["assets"]["synthetic-dataset-001"]
    check = {
        "authoritative_source_identity_preserved": (
            changed_source["source_identity"] == first_inventory["sources"][
                "authoritative_dataset_manifest"]["source_identity"]
        ),
        "version_and_digest_change_recorded": (
            first_asset["version"] == "SYNTH-DATASET-VERSION-001"
            and first_asset["response_etag"] != changed_asset["response_etag"]
            and first_asset["digest"] != changed_asset["digest"]
            and changed_asset["version"] == "SYNTH-DATASET-VERSION-002"
        ),
        "explicit_change_history_retained": len(changed_asset["change_history"]) == 2
        and changed_asset["change_history"][-1]["version"] == changed_asset["version"],
        "published_through_same_helper_record": (
            changed_record["metadata"]["uid"] == first_record["metadata"]["uid"]
            and changed_inventory == second_snapshot
        ),
        "all_expected_sources_present_and_fresh": (
            set(changed_inventory["sources"]) == sources
            and all(record["status"] == "fresh" and not record["gap"]
                    for record in changed_inventory["sources"].values())
        ),
        "fresh_source_cursor_and_capture_time": changed_source["status"] == "fresh"
        and changed_source["cursor"] == changed_asset["version"]
        and changed_source["capture_time"] == _iso_time(second_time),
    }
    save_raw(lab, "authoritative-dataset-manifest-reconciliation.raw.json", {
        "source_identity": changed_source["source_identity"],
        "first_published": first_asset, "changed_published": changed_asset,
        "checks": check,
    })
    lab.check("green", "Versioned authoritative dataset source changes reconcile through publisher",
              all(check.values()), check)


def _setup_registry_fixture(lab, image):
    registry_pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": REGISTRY_NAME, "namespace": NAMESPACE,
                     "labels": {"app": REGISTRY_NAME}},
        "spec": {"automountServiceAccountToken": False,
                 "containers": [{"name": "registry", "image": REGISTRY_IMAGE,
                                 "imagePullPolicy": "IfNotPresent", "ports": [{"containerPort": 5000}],
                                 "readinessProbe": {"httpGet": {"path": "/v2/", "port": 5000},
                                                    "periodSeconds": 1}}]},
    }
    service = {"apiVersion": "v1", "kind": "Service",
               "metadata": {"name": REGISTRY_NAME, "namespace": NAMESPACE},
               "spec": {"selector": {"app": REGISTRY_NAME},
                        "ports": [{"name": "registry", "port": 5000, "targetPort": 5000}]}}
    code = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "registry-fixture-code", "namespace": NAMESPACE},
            "immutable": True,
            "data": {"registry_fixture.py": (HERE / "fixtures" / "registry_fixture.py").read_text()}}
    client_pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": REGISTRY_CLIENT, "namespace": NAMESPACE},
        "spec": {"automountServiceAccountToken": False,
                 "containers": [{"name": "fixture-client", "image": image,
                                 "imagePullPolicy": "IfNotPresent", "command": ["sleep", "3600"],
                                 "volumeMounts": [{"name": "fixture-code", "mountPath": "/fixture",
                                                   "readOnly": True}]}],
                 "volumes": [{"name": "fixture-code",
                              "configMap": {"name": "registry-fixture-code"}}]},
    }
    code["data"]["dataset_catalog.py"] = (HERE / "fixtures" / "dataset_catalog.py").read_text()
    code["data"]["authoritative_dataset_manifest.json"] = (
        HERE / "fixtures" / "authoritative_dataset_manifest.json").read_text()
    client_pod["metadata"]["labels"] = {"app": REGISTRY_CLIENT}
    client_pod["spec"]["containers"].append({
        "name": "dataset-catalog", "image": image, "command": ["python", "/fixture/dataset_catalog.py", "serve"],
        "ports": [{"containerPort": 8080}],
        "readinessProbe": {"httpGet": {"path": "/dataset", "port": 8080}, "periodSeconds": 1},
        "volumeMounts": [{"name": "fixture-code", "mountPath": "/fixture", "readOnly": True},
                         {"name": "dataset-active", "mountPath": "/data"}],
    })
    client_pod["spec"]["volumes"].append({"name": "dataset-active", "emptyDir": {}})
    dataset_service = {"apiVersion": "v1", "kind": "Service",
                       "metadata": {"name": "dataset-catalog", "namespace": NAMESPACE},
                       "spec": {"selector": {"app": REGISTRY_CLIENT},
                                "ports": [{"port": 8080, "targetPort": 8080}]}}
    for obj in (registry_pod, service, code, client_pod, dataset_service):
        lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(obj))
    for name in (REGISTRY_NAME, REGISTRY_CLIENT):
        lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
                    "--timeout=90s", timeout=100)


def run(lab):
    fixture = read_fixture()
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("create", "namespace", NEIGHBOR_NAMESPACE)

    account = {"apiVersion": "v1", "kind": "ServiceAccount",
               "metadata": {"name": SERVICE_ACCOUNT, "namespace": NAMESPACE}}
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "asset-inventory-reader", "namespace": NAMESPACE},
        "rules": [
            {"apiGroups": [""], "resources": ["configmaps", "services", "persistentvolumeclaims"],
             "verbs": ["list", "watch"]},
            {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["list", "watch"]},
            {"apiGroups": ["resource.k8s.io"], "resources": ["resourceclaims"],
             "verbs": ["list", "watch"]},
            SNAPSHOT_READ_RULE,
        ],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "asset-inventory-reader", "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT, "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "asset-inventory-reader"},
    }
    publisher_account = {"apiVersion": "v1", "kind": "ServiceAccount",
                         "metadata": {"name": PUBLISHER_ACCOUNT, "namespace": NAMESPACE}}
    publisher_role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": PUBLISHER_ROLE, "namespace": NAMESPACE},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                   "resourceNames": [PUBLICATION_RECORD], "verbs": ["get", "patch"]}],
    }
    publisher_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": PUBLISHER_ROLE, "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": PUBLISHER_ACCOUNT,
                      "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": PUBLISHER_ROLE},
    }
    for obj in (account, role, binding, publisher_account, publisher_role, publisher_binding):
        lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(obj))
    _setup_registry_fixture(lab, fixture["mock_workload_image"])

    for asset in fixture["assets"]:
        lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(asset_record(asset, NAMESPACE)))
    unrelated = resource("ConfigMap", "unlabeled-neighbor", NAMESPACE,
                         data={"fixture_notice": "unrelated synthetic record"})
    lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(unrelated))
    remote_unrelated = resource("ConfigMap", fixture["unrelated_record"]["name"],
                                NEIGHBOR_NAMESPACE,
                                data={"fixture_notice": "unrelated synthetic record"})
    remote_unrelated["metadata"]["labels"] = {
        "saf-k8s.example/control-1007-013": "unrelated"}
    lab.kubectl("-n", NEIGHBOR_NAMESPACE, "apply", "-f", "-", payload=json.dumps(remote_unrelated))

    # The original discovery, watch, and source-gap checks remain unchanged.
    initial = list_assets(lab)
    observed = [{"name": item["metadata"]["name"],
                 "kind": item["metadata"].get("labels", {}).get("saf-k8s.example/asset-kind"),
                 "digest": item["metadata"].get("annotations", {}).get("saf-k8s.example/asset-digest"),
                 "resourceVersion": item["metadata"].get("resourceVersion")}
                for item in initial["items"]]
    expected_kinds = sorted(asset["kind"] for asset in fixture["assets"])
    actual_kinds = sorted(item["kind"] for item in observed)
    save_raw(lab, "inventory-list.raw.json", initial)
    initial_version = initial.get("metadata", {}).get("resourceVersion")
    unlabeled_excluded = "unlabeled-neighbor" not in [item["name"] for item in observed]
    resource_versions_present = bool(initial_version) and all(item["resourceVersion"] for item in observed)
    lab.check("green", "Authorized LIST discovers each labeled synthetic AI asset class",
              actual_kinds == expected_kinds and len(observed) == len(fixture["assets"])
              and unlabeled_excluded and resource_versions_present,
              {"expected_asset_kinds": expected_kinds, "observed_asset_kinds": actual_kinds,
               "unlabeled_record_excluded": unlabeled_excluded,
               "resource_versions_present": resource_versions_present})

    forbidden = lab.kubectl("--as", IDENTITY, "get", "configmaps", "-n", NEIGHBOR_NAMESPACE,
                            "-o", "json", allow_failure=True)
    forbidden_text = forbidden.stdout + forbidden.stderr
    denied = forbidden.returncode != 0 and "forbidden" in forbidden_text.lower()
    save_raw(lab, "denied-neighbor.raw.json", {
        "identity": IDENTITY, "namespace": NEIGHBOR_NAMESPACE,
        "exit_code": forbidden.returncode, "response": forbidden_text,
        "response_contains_secret": False,
    })
    lab.check("red", "The inventory identity is denied LIST access to an unrelated namespace",
              denied, {"request_denied": denied, "exit_code": forbidden.returncode,
                       "namespace": NEIGHBOR_NAMESPACE})

    process = start_watch(lab, initial_version)
    state = {"buffer": ""}
    event_name = "mock-model-change-event"
    try:
        event_asset = {"name": event_name, "kind": "model", "display_name": "SYNTH-MODEL-EVENT-001",
                       "digest": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
        lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(asset_record(event_asset, NAMESPACE)))
        added, raw_added = wait_for_event(process, state, "ADDED", event_name)
        changed = asset_record(event_asset, NAMESPACE, fixture["change_fixture"]["updated_revision"])
        lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(changed))
        modified, raw_modified = wait_for_event(process, state, "MODIFIED", event_name)
        lab.kubectl("-n", NAMESPACE, "delete", "configmap", event_name)
        deleted, raw_deleted = wait_for_event(process, state, "DELETED", event_name)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    final = list_assets(lab)
    final_names = [item["metadata"]["name"] for item in final["items"]]
    save_raw(lab, "inventory-watch.raw.json", {
        "identity": IDENTITY, "selector": SELECTOR,
        "initial_list_resource_version": initial_version,
        "events": [raw_added, raw_modified, raw_deleted], "final_list": final,
    })
    transitions = [added.get("type"), modified.get("type"), deleted.get("type")]
    event_revisions = [event.get("object", {}).get("data", {}).get("revision")
                       for event in (added, modified, deleted)]
    lab.check("positive", "Persistent Kubernetes WATCH observes create, update, delete and converges to current inventory",
              transitions == ["ADDED", "MODIFIED", "DELETED"]
              and event_revisions[:2] == [fixture["change_fixture"]["initial_revision"],
                                          fixture["change_fixture"]["updated_revision"]]
              and event_name not in final_names,
              {"event_types": transitions, "observed_revisions": event_revisions,
               "deleted_asset_absent_from_final_list": event_name not in final_names,
               "event_objects_are_synthetic_fixture_metadata": True})
    verify_typed_resync(lab)
    verify_dra_claim_reconciliation(lab)
    verify_registry_reconciliation(lab)
    verify_dataset_manifest_reconciliation(lab)
