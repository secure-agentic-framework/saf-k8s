"""Exercise synthetic Kubernetes AI asset inventory and live watch scope."""
import json
import os
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
SCOPE = (
    "Disposable Kind v1.36.1 cluster. Creates a case-owned namespace, a read-only service account "
    "Role/RoleBinding for ConfigMap list/watch in that namespace, synthetic ConfigMap records for "
    "model, dataset, pipeline, inference endpoint and GPU allocation metadata. Uses the service-account "
    "identity for an actual Kubernetes LIST and persistent WATCH, "
    "observes create/update/delete events, filters records by a synthetic ownership label, and confirms "
    "the identity is denied access to a separate namespace. The same reader relists real "
    "Service, Job and PVC resources, repairs a stale snapshot after a disconnected change, "
    "and cannot publish inventory itself. PVC contents, external registries and actual "
    "accelerator ownership are adopter evidence."
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


def _typed_inventory(lab):
    selector = urlencode({"labelSelector": SELECTOR})
    scopes = {
        "services": f"/api/v1/namespaces/{NAMESPACE}/services",
        "persistentvolumeclaims": f"/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims",
        "jobs": f"/apis/batch/v1/namespaces/{NAMESPACE}/jobs",
    }
    views = {}
    for kind, path in scopes.items():
        document = json.loads(lab.kubectl("--as", IDENTITY, "get", "--raw", f"{path}?{selector}").stdout)
        api_version = document["apiVersion"]
        expected_version = "batch/v1" if kind == "jobs" else "v1"
        if api_version != expected_version:
            lab.block("The typed inventory returned an unexpected list API version")
        views[kind] = {
            "list_resource_version": document["metadata"]["resourceVersion"],
            "assets": {
                row["metadata"]["name"]: {
                    "uid": row["metadata"]["uid"], "api_version": api_version,
                    "resource_version": row["metadata"]["resourceVersion"],
                    "definition": row["spec"],
                } for row in document["items"]
            },
        }
    return views


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
    old = _typed_inventory(lab)
    by_kind = tuple(old[kind]["assets"] for kind in ("services", "persistentvolumeclaims", "jobs"))
    exact = all(
        observed.get(obj["metadata"]["name"], {}).get("uid") == obj["metadata"]["uid"]
        for obj, observed in zip(actuals, by_kind)
    )
    lab.check("positive", "Read-only discovery links the actual Service, PVC and Job identities",
              exact, {"all_three_owned_typed_resource_uids_observed": exact})

    name = "typed-asset-inventory"
    snapshot = resource("ConfigMap", name, NAMESPACE, data={"inventory.json": json.dumps(old, sort_keys=True)})
    denied = lab.kubectl("--as", IDENTITY, "-n", NAMESPACE, "create", "-f", "-",
                          "--dry-run=server", payload=json.dumps(snapshot), allow_failure=True)
    read_only = denied.returncode != 0 and "cannot create resource" in denied.stderr.lower()
    lab.check("red", "The inventory reader cannot create its publication record",
              read_only, {"reader_denied_publication": read_only})
    record = _create_owned(lab, snapshot)
    stale = json.loads(record["data"]["inventory.json"])

    change_started = time.monotonic()
    pipeline_name = pipeline["metadata"]["name"]
    service_name = service["metadata"]["name"]
    lab.kubectl("-n", NAMESPACE, "delete", "job", pipeline_name, "--wait=true")
    pipeline["metadata"]["name"] = "owned-pipeline-replacement"
    replacement = _create_owned(lab, pipeline)
    lab.kubectl("-n", NAMESPACE, "patch", "service", service_name, "--type=json", "-p",
                '[{"op":"replace","path":"/spec/ports/0/port","value":9090}]')
    updated = _typed_inventory(lab)
    lab.kubectl("-n", NAMESPACE, "patch", "configmap", name, "--type=merge", "-p",
                json.dumps({"data": {"inventory.json": json.dumps(updated, sort_keys=True)}}))
    persisted = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", name, "-o", "json").stdout)
    current = json.loads(persisted["data"]["inventory.json"])
    elapsed = time.monotonic() - change_started
    observed = {
        "published_within_fixture_freshness_budget": elapsed < 60,
        "stale_snapshot_contained_pre_change_entities": stale == old
        and service_name in old["services"]["assets"] and pipeline_name in old["jobs"]["assets"],
        "modified_service_retains_identity_with_current_port": (
            current["services"]["assets"][service_name]["uid"] == actuals[0]["metadata"]["uid"]
            and current["services"]["assets"][service_name]["definition"]["ports"][0]["port"] == 9090
        ),
        "missing_job_removed_and_replacement_added": pipeline_name not in current["jobs"]["assets"]
        and current["jobs"]["assets"]["owned-pipeline-replacement"]["uid"] == replacement["metadata"]["uid"]
        and replacement["metadata"]["uid"] != actuals[2]["metadata"]["uid"],
        "existing_pvc_retained_and_snapshot_reconciled": current == updated
        and all(
            current["persistentvolumeclaims"]["assets"][claim["metadata"]["name"]][field]
            == old["persistentvolumeclaims"]["assets"][claim["metadata"]["name"]][field]
            for field in ("uid", "definition")
        )
        and persisted["metadata"]["uid"] == record["metadata"]["uid"],
        "fresh_source_versions_recorded": all(item["list_resource_version"] for item in current.values()),
    }
    save_raw(lab, "typed-inventory-resync.raw.json", {
        "before": old, "reconciled": current, "observed": observed,
        "fixture_elapsed_seconds": round(elapsed, 3), "fixture_budget_seconds": 60,
    })
    lab.check("green", "A fresh API relist repairs the durable inventory after disconnected changes",
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
