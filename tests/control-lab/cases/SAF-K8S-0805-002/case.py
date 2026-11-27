"""Verify live Pod lifecycle audit evidence and explicitly modeled allocation correlation."""

from datetime import datetime, timezone
import json
import time

SCOPE = ("Live Kubernetes Pod audit, DRA allocation and reservation lifecycle, "
         "and inert comparison records without physical device delivery.")
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NS = "saf-test"
POD = "fixture-allocation"
ACCOUNT = "fixture-accelerator-workload"
RESOURCE = "fixture.example/accelerator"
CONTAINER = "unit"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
LOG = "/var/log/kubernetes/saf-allocation-audit.log"
KEYS = ("cluster", "namespace", "node", "uid", "container", "resource")
DRA_DRIVER = "mock.saf-lab.example"
DRA_CLASS = "fixture-accelerator-class"
DRA_SLICE = "fixture-accelerator-slice"
DRA_CLAIM = "fixture-accelerator-claim"
DRA_POD = "fixture-dra-workload"
DRA_PEER = "fixture-dra-shared-consumer"


def prepare_kind(_lab, temporary):
    policy = temporary / "allocation-audit.json"
    policy.write_text(json.dumps({
        "apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "RequestResponse", "verbs": ["create"], "namespaces": [NS],
                   "resources": [{"group": "", "resources": ["pods"]}]}, {"level": "None"}],
    }))
    config = temporary / "kind-allocation-audit.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-allocation-audit.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-allocation-audit.json
        - name: audit-log-path
          value: {LOG}
      extraVolumes:
        - name: saf-allocation-audit-policy
          hostPath: /etc/kubernetes/saf-allocation-audit.json
          mountPath: /etc/kubernetes/saf-allocation-audit.json
          readOnly: true
          pathType: File
        - name: saf-allocation-audit-log
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
""")
    return config


def node_resource(lab):
    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    name = node["metadata"]["name"]
    field = RESOURCE.replace("/", "~1")
    lab.kubectl("patch", "node", name, "--subresource=status", "--type=json", "-p",
                json.dumps([{"op": "add", "path": f"/status/capacity/{field}", "value": "1"}]))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", "node", name, "-o", "json").stdout)["status"]
        if status.get("allocatable", {}).get(RESOURCE) == "1":
            return name
        time.sleep(0.5)
    lab.block("The disposable node did not advertise the synthetic resource")


def scheduled(lab, node):
    created = lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD}, "spec": {
        "serviceAccountName": ACCOUNT, "automountServiceAccountToken": False, "restartPolicy": "Never",
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": CONTAINER, "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(100)"],
                        "resources": {"requests": {RESOURCE: "1", "cpu": "5m", "memory": "12Mi"},
                                      "limits": {RESOURCE: "1", "cpu": "100m", "memory": "64Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}}}],
    }})
    lab.kubectl("wait", "--for=condition=PodScheduled", f"pod/{POD}", "--timeout=55s", timeout=64)
    item = json.loads(lab.kubectl("get", "pod", POD, "-o", "json").stdout)
    spec = item["spec"]
    container, = spec["containers"]
    if (item["metadata"]["uid"] != created["metadata"]["uid"] or spec["nodeName"] != node
            or container["resources"]["requests"].get(RESOURCE) != "1"):
        lab.block("The scheduled fixture did not preserve the admitted workload and resource identity")
    return {"cluster": lab.cluster, "namespace": item["metadata"]["namespace"], "name": item["metadata"]["name"],
            "node": spec["nodeName"], "uid": item["metadata"]["uid"], "container": container["name"],
            "resource": RESOURCE, "service_account": spec["serviceAccountName"]}


def get_audit(lab, uids):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat", LOG, allow_failure=True)
        events = {}
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                event = json.loads(line)
                obj = event.get("responseObject") or {}
                meta = obj.get("metadata") or {}
                ref = event.get("objectRef") or {}
                uid = meta.get("uid")
                if (uid in uids and meta.get("name") == POD and ref.get("namespace") == NS
                        and ref.get("resource") == "pods" and event.get("stage") == "ResponseComplete"
                        and event.get("verb") == "create" and event.get("responseStatus", {}).get("code") == 201
                        and obj.get("spec", {}).get("serviceAccountName") == ACCOUNT):
                    events[uid] = {"audit_id": event["auditID"], "recorded_at": event["stageTimestamp"],
                                   "service_account": ACCOUNT}
        if events.keys() == uids:
            return events
        time.sleep(0.5)
    lab.block("Both successful scoped API audit events were not available")


def correlate(workload, snapshots):
    matching = {row["device"] for row in snapshots if all(row[key] == workload[key] for key in KEYS)}
    if len(matching) != 1:
        return {"status": "ambiguous" if matching else "missing", "exact_duration": None}
    return {"status": "synthetic-snapshot", "device": next(iter(matching)), "exact_duration": None}


def _dra_objects(node):
    labels = {"saf-k8s.example/control": "SAF-K8S-0805-002",
              "saf-k8s.example/fixture": "synthetic-dra-only"}
    device_class = {
        "apiVersion": "resource.k8s.io/v1", "kind": "DeviceClass",
        "metadata": {"name": DRA_CLASS, "labels": labels},
        "spec": {"selectors": [{"cel": {"expression": (
            f"device.driver == '{DRA_DRIVER}' && "
            f"device.attributes['{DRA_DRIVER}'].type == 'accelerator'"
        )}}]},
    }
    resource_slice = {
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceSlice",
        "metadata": {"name": DRA_SLICE, "labels": labels},
        "spec": {
            "driver": DRA_DRIVER, "nodeName": node,
            "pool": {"name": "fixture-pool", "generation": 1, "resourceSliceCount": 1},
            "devices": [{"name": "fixture-device-001", "attributes": {
                f"{DRA_DRIVER}/type": {"string": "accelerator"},
                f"{DRA_DRIVER}/evidence": {"string": "synthetic-only"},
            }}],
        },
    }
    claim = {
        "apiVersion": "resource.k8s.io/v1", "kind": "ResourceClaim",
        "metadata": {"name": DRA_CLAIM, "namespace": NS, "labels": labels,
                     "annotations": {"saf-k8s.example/evidence-class": "synthetic-scheduler-metadata"}},
        "spec": {"devices": {"requests": [{"name": "fixture-device", "exactly": {
            "deviceClassName": DRA_CLASS, "allocationMode": "ExactCount", "count": 1,
        }}]}},
    }
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": DRA_POD, "namespace": NS, "labels": labels},
        "spec": {
            "serviceAccountName": ACCOUNT, "automountServiceAccountToken": False,
            "restartPolicy": "Never", "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "resourceClaims": [{"name": "fixture-device", "resourceClaimName": DRA_CLAIM}],
            "containers": [{"name": "fixture", "image": IMAGE,
                "command": ["python", "-c", "import time; time.sleep(60)"],
                "resources": {"claims": [{"name": "fixture-device"}],
                              "requests": {"cpu": "5m", "memory": "12Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            }],
        },
    }
    return device_class, resource_slice, claim, pod


def _wait_dra_allocation(lab, pod_uid, pod_name=DRA_POD):
    deadline = time.monotonic() + 50
    last_claim = {}
    last_pod = {}
    while time.monotonic() < deadline:
        last_claim = json.loads(lab.kubectl("-n", NS, "get", "resourceclaim", DRA_CLAIM,
                                           "-o", "json").stdout)
        last_pod = json.loads(lab.kubectl("-n", NS, "get", "pod", pod_name, "-o", "json").stdout)
        results = (last_claim.get("status", {}).get("allocation", {})
                   .get("devices", {}).get("results", []))
        reserved = last_claim.get("status", {}).get("reservedFor", [])
        if (last_pod.get("metadata", {}).get("uid") == pod_uid
                and last_pod.get("spec", {}).get("nodeName")
                and len(results) == 1
                and any(item.get("uid") == pod_uid and item.get("resource") == "pods"
                        for item in reserved)):
            return last_claim, last_pod, results[0]
        time.sleep(0.5)
    lab.block("The native scheduler allocation and exact Pod reservation were not observed")


def _delete_and_wait_absent(lab, kind, name, namespace=None):
    args = ["delete", kind, name, "--wait=true", "--timeout=35s"]
    if namespace:
        args[0:0] = ["-n", namespace]
    lab.kubectl(*args, timeout=45, allow_failure=True)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        get_args = ["get", kind, name, "--ignore-not-found", "-o", "json"]
        if namespace:
            get_args[0:0] = ["-n", namespace]
        result = lab.kubectl(*get_args, allow_failure=True)
        if result.returncode == 0 and not result.stdout.strip():
            return
        time.sleep(0.5)
    lab.block(f"Owned DRA object did not disappear after deletion: {kind}/{name}")


def read_claim_reservations(lab, expected_uids=()):
    """Observe exact Pod reservations and the associated scheduler state."""
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        claim = json.loads(lab.kubectl("-n", NS, "get", "resourceclaim", DRA_CLAIM,
                                       "-o", "json", timeout=8).stdout)
        status = claim.get("status", {})
        consumers = status.get("reservedFor", [])
        if (all(item.get("resource") == "pods" for item in consumers)
                and sorted(item.get("uid", "") for item in consumers) == sorted(expected_uids)
                and bool(status.get("allocation")) == bool(expected_uids)):
            return {
                "claim_uid": claim["metadata"]["uid"],
                "resource_version": claim["metadata"]["resourceVersion"],
                "claim_live": "deletionTimestamp" not in claim["metadata"],
                "harness_observed_at": datetime.now(timezone.utc).isoformat(),
                "consumers": consumers,
                "allocation": status.get("allocation"),
            }
        time.sleep(0.5)
    lab.block("Expected exact Pod reservations and API allocation state were not observed")


def observe_dra_reservation_release(lab, prior_claim, first_pod, pod):
    """Follow a single DRA API allocation through one, two and zero consumers."""
    first_uid = first_pod["metadata"]["uid"]
    initial = read_claim_reservations(lab, [first_uid])
    peer = lab.create({**pod, "metadata": {**pod["metadata"], "name": DRA_PEER}})
    peer_uid = peer["metadata"]["uid"]
    lab.kubectl("wait", "--for=condition=PodScheduled", f"pod/{DRA_PEER}",
                "--timeout=55s", timeout=64)
    _, peer_scheduled, _ = _wait_dra_allocation(lab, peer_uid, DRA_PEER)
    shared = read_claim_reservations(lab, [first_uid, peer_uid])
    _delete_and_wait_absent(lab, "pods", DRA_POD, NS)
    one_remaining = read_claim_reservations(lab, [peer_uid])
    _delete_and_wait_absent(lab, "pods", DRA_PEER, NS)
    released = read_claim_reservations(lab)
    snapshots = (initial, shared, one_remaining, released)
    claim_uid = prior_claim["metadata"]["uid"]
    allocation = prior_claim["status"]["allocation"]
    observed = {
        "same_live_claim_in_all_observations": all(
            row["claim_uid"] == claim_uid and row["claim_live"] for row in snapshots),
        "distinct_claim_snapshots": len({row["resource_version"] for row in snapshots}) == 4,
        "peer_scheduled_to_same_node": (
            peer_scheduled["spec"]["nodeName"] == first_pod["spec"]["nodeName"]),
        "one_then_two_then_one_reservations": [
            len(row["consumers"]) for row in snapshots[:3]] == [1, 2, 1],
        "same_api_allocation_while_reserved": all(
            row["allocation"] == allocation for row in snapshots[:3]),
        "final_pod_reservation_and_api_allocation_cleared": (
            not released["consumers"] and released["allocation"] is None),
    }
    (lab.evidence / "native-dra-reservation-release.raw.json").write_text(json.dumps({
        "classification": "DRA allocation and reservation API metadata for an inert device",
        "claim_uid": claim_uid,
        "consumer_pod_uids": [first_uid, peer_uid],
        "clock": "harness UTC observations",
        "snapshots": dict(zip(("initial", "shared", "one_remaining", "released"), snapshots)),
        "physical_release_time": None,
        "assertions": observed,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Native DRA shares one API allocation, then clears it when the last Pod is removed",
              all(observed.values()), observed)


def native_dra_recreation_comparison(lab, node):
    """Observe actual scheduler-written DRA status for same-name Pod recreation."""
    device_class, resource_slice, claim, pod = _dra_objects(node)
    pair_rows = []
    try:
        created_class = lab.create(device_class)
        created_slice = lab.create(resource_slice)

        first_claim = lab.create(claim)
        first_pod = lab.create(pod)
        lab.kubectl("wait", "--for=condition=PodScheduled", f"pod/{DRA_POD}",
                    "--timeout=55s", timeout=64)
        claim_one, pod_one, allocation_one = _wait_dra_allocation(
            lab, first_pod["metadata"]["uid"])
        pair_rows.append({
            "claim": claim_one, "pod": pod_one,
            "allocation": allocation_one,
            "created_claim_uid": first_claim["metadata"]["uid"],
            "created_pod_uid": first_pod["metadata"]["uid"],
        })

        observe_dra_reservation_release(lab, claim_one, pod_one, pod)
        _delete_and_wait_absent(lab, "resourceclaims", DRA_CLAIM, NS)

        second_claim = lab.create(claim)
        second_pod = lab.create(pod)
        lab.kubectl("wait", "--for=condition=PodScheduled", f"pod/{DRA_POD}",
                    "--timeout=55s", timeout=64)
        claim_two, pod_two, allocation_two = _wait_dra_allocation(
            lab, second_pod["metadata"]["uid"])
        pair_rows.append({
            "claim": claim_two, "pod": pod_two,
            "allocation": allocation_two,
            "created_claim_uid": second_claim["metadata"]["uid"],
            "created_pod_uid": second_pod["metadata"]["uid"],
        })

        first, second = pair_rows
        observed_slice = json.loads(lab.kubectl("get", "resourceslice", DRA_SLICE,
                                                "-o", "json").stdout)
        def exact(row):
            claim_uid = row["claim"].get("metadata", {}).get("uid")
            pod_uid = row["pod"].get("metadata", {}).get("uid")
            allocation = row["allocation"]
            reserved = row["claim"].get("status", {}).get("reservedFor", [])
            claim_ref = next((entry for entry in row["pod"].get("spec", {}).get("resourceClaims", [])
                              if entry.get("name") == "fixture-device"), {})
            return (
                claim_uid == row["created_claim_uid"]
                and pod_uid == row["created_pod_uid"]
                and claim_ref.get("resourceClaimName") == DRA_CLAIM
                and allocation.get("driver") == DRA_DRIVER
                and allocation.get("pool") == "fixture-pool"
                and allocation.get("device") == "fixture-device-001"
                and any(item.get("uid") == pod_uid and item.get("resource") == "pods"
                        for item in reserved)
            )

        same_name = (first["pod"]["metadata"]["name"] == second["pod"]["metadata"]["name"]
                     and first["claim"]["metadata"]["name"] == second["claim"]["metadata"]["name"])
        distinct_pod_uids = first["pod"]["metadata"]["uid"] != second["pod"]["metadata"]["uid"]
        distinct_claim_uids = first["claim"]["metadata"]["uid"] != second["claim"]["metadata"]["uid"]
        exact_first, exact_second = exact(first), exact(second)
        slice_uid_matches = (observed_slice.get("metadata", {}).get("uid")
                             == created_slice.get("metadata", {}).get("uid"))
        slice_advertises_assigned_device = (
            observed_slice.get("spec", {}).get("driver") == DRA_DRIVER
            and observed_slice.get("spec", {}).get("pool", {}).get("name") == "fixture-pool"
            and any(device.get("name") == "fixture-device-001"
                    for device in observed_slice.get("spec", {}).get("devices", []))
        )
        allocation_source_matches_owned_slice = slice_uid_matches and slice_advertises_assigned_device
        passed = (same_name and distinct_pod_uids and distinct_claim_uids and exact_first
                  and exact_second and allocation_source_matches_owned_slice)
        observed = {
            "same_pod_and_claim_names_recreated": same_name,
            "pod_uids_distinct": distinct_pod_uids,
            "claim_uids_distinct": distinct_claim_uids,
            "first_allocation_and_reservation_match": exact_first,
            "replacement_allocation_and_reservation_match": exact_second,
            "allocation_source_matches_owned_slice": allocation_source_matches_owned_slice,
            "classification": "synthetic scheduler allocation metadata; no driver or physical device",
        }
        (lab.evidence / "native-dra-recreation.raw.json").write_text(json.dumps({
            "classification": "synthetic scheduler allocation metadata",
            "device_driver_installed": False, "physical_device_observed": False,
            "resource_class_uid": created_class.get("metadata", {}).get("uid"),
            "resource_slice_uid": created_slice.get("metadata", {}).get("uid"),
            "pairs": [{
                "pod_name": row["pod"]["metadata"].get("name"),
                "pod_uid": row["pod"]["metadata"].get("uid"),
                "claim_name": row["claim"]["metadata"].get("name"),
                "claim_uid": row["claim"]["metadata"].get("uid"),
                "resource_slice_uid": created_slice.get("metadata", {}).get("uid"),
                "allocation": row["allocation"],
                "reserved_for": row["claim"].get("status", {}).get("reservedFor", []),
            } for row in pair_rows],
            "assertions": observed,
        }, indent=2, sort_keys=True) + "\n")
        lab.check("positive", "Native DRA allocation and reservation bind each recreated Pod UID to its claim",
                  passed, observed)
    finally:
        _delete_and_wait_absent(lab, "pods", DRA_PEER, NS)
        _delete_and_wait_absent(lab, "pods", DRA_POD, NS)
        _delete_and_wait_absent(lab, "resourceclaims", DRA_CLAIM, NS)
        _delete_and_wait_absent(lab, "resourceslices", DRA_SLICE)
        _delete_and_wait_absent(lab, "deviceclasses", DRA_CLASS)


def run(lab):
    lab.kubectl("label", "namespace", NS, "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT},
                "automountServiceAccountToken": False})
    node = node_resource(lab)
    first = scheduled(lab, node)
    lab.kubectl("delete", "pod", POD, "--grace-period=0", "--force", "--wait=true")
    second = scheduled(lab, node)
    modeled = {**first, "device": "fixture-device-a"}
    name_collision = first["namespace"] == second["namespace"] and first["name"] == second["name"]
    lab.check("red", "A namespace-and-name join would confuse the old allocation with the recreated Pod",
              name_collision and first["uid"] != second["uid"], {"same_name": name_collision, "distinct_uids": first["uid"] != second["uid"]})

    audit = get_audit(lab, {first["uid"], second["uid"]})
    first_match = correlate(first, [modeled])
    second_match = correlate(second, [modeled])
    lab.check("green", "Distinct live creation audit events back the UID join and exclude the replacement Pod",
              len({row["audit_id"] for row in audit.values()}) == 2
              and first_match.get("device") == "fixture-device-a" and second_match["status"] == "missing",
              {"distinct_creation_audit_events": len(audit), "first": first_match["status"], "replacement": second_match["status"]})

    wrong_node = correlate(first, [{**modeled, "node": "fixture-other-node"}])
    conflict = correlate(first, [modeled, {**modeled, "device": "fixture-device-b"}])
    lab.check("positive", "Wrong-node and conflicting records stay unresolved and snapshots yield no exact interval",
              wrong_node["status"] == "missing" and conflict["status"] == "ambiguous" and first_match["exact_duration"] is None,
              {"wrong_node": wrong_node["status"], "conflict": conflict["status"], "exact_duration": first_match["exact_duration"]})
    native_dra_recreation_comparison(lab, node)
    (lab.evidence / "accelerator-audit-observations.json").write_text(json.dumps({
        "workloads": [first, second], "creation_audit": audit, "first_relation": first_match,
        "replacement_relation": second_match, "conflicting_relation": conflict,
        "allocation_source": "synthetic", "hardware_or_plugin_observed": False,
    }, indent=2) + "\n")
