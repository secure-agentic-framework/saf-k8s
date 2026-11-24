"""Exercise synthetic Kubernetes AI asset inventory and live watch scope."""
import json
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
    "Service, Job and PVC API objects; a deterministic fixture clock drives unknown, stale, "
    "last-good retention, recovery and relist reconciliation through a separate harness publisher. "
    "PVC contents, external registries and actual accelerator ownership are adopter evidence."
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
                row["metadata"]["name"]: {
                    "uid": row["metadata"]["uid"], "api_version": api_version,
                    "resource_version": row["metadata"]["resourceVersion"],
                    "definition": row["spec"],
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
    lab.kubectl("-n", NAMESPACE, "patch", "configmap", record, "--type=merge", "-p",
                json.dumps(payload))
    return json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", record, "-o", "json").stdout)



def _set_owned_job_collection(lab, enabled):
    common = {"apiGroups": [""], "resources": ["configmaps", "services", "persistentvolumeclaims"],
              "verbs": ["list", "watch"]}
    jobs = {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["list", "watch"]}
    rules = [common, jobs] if enabled else [common]
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
    expected_sources = ("services", "persistentvolumeclaims", "jobs")
    initial_observations = _typed_inventory(lab, REFERENCE_TIME)
    old = _reconcile(None, initial_observations, expected_sources, REFERENCE_TIME)
    by_kind = tuple(old["sources"][source]["assets"] for source in expected_sources)
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
            len(expected_sources) == 3 and bool(unknown_job.get("source_identity"))
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
            for source in ("services", "persistentvolumeclaims")
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
        ],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "asset-inventory-reader", "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT, "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "asset-inventory-reader"},
    }
    for obj in (account, role, binding):
        lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(obj))

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
        "exit_code": forbidden.returncode,
        "response": forbidden_text,
        "response_contains_secret": False,
    })
    lab.check("red", "The inventory identity is denied LIST access to an unrelated namespace",
              denied, {"request_denied": denied, "exit_code": forbidden.returncode,
                       "namespace": NEIGHBOR_NAMESPACE})

    # Continue from the LIST snapshot even if the API receives the first write
    # before the client's watch connection opens.
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
        "identity": IDENTITY,
        "selector": SELECTOR,
        "initial_list_resource_version": initial_version,
        "events": [raw_added, raw_modified, raw_deleted],
        "final_list": final,
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
