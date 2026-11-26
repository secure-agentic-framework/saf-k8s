"""Exercise source enrollment, in-cluster forwarding, outage retry and readback."""
from collections import Counter
import json
from pathlib import Path
import time

LOG = "/var/log/kubernetes/saf-receipt-audit.log"
MARKER = "audit-receipt-marker"

PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
NAMESPACE = "saf-test"
SINK = "audit-sink"
SINK_SERVICE = "audit-sink"
SINK_PVC = "audit-sink-data"
COLLECTOR = "audit-source-collector"
READER = "audit-independent-reader"
CODE = "audit-delivery-code"
CONFIG = "audit-source-config"
PROVIDER = "audit-provider-fixture"
PROVIDER_ID = "provider-fixture:synthetic-provider-cluster"
PROVIDER_RECORD = "provider-fixture-event-0001"
PROVISIONER = "rancher.io/local-path"


def resource(api, kind, name, **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def apply(lab, obj):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(obj))


def configmap(lab, name, data):
    lab.create(resource("v1", "ConfigMap", name, data=data))


def container(name, command, mounts, *, ports=None, ready_path=None, root=False):
    security = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
        "seccompProfile": {"type": "RuntimeDefault"},
        "runAsNonRoot": not root,
        "runAsUser": 0 if root else 65534,
    }
    if root:
        security["runAsGroup"] = 0
    result = {
        "name": name, "image": PYTHON, "imagePullPolicy": "IfNotPresent",
        "command": command, "volumeMounts": mounts,
        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                      "limits": {"cpu": "100m", "memory": "96Mi"}},
        "securityContext": security,
    }
    if ports:
        result["ports"] = ports
    if ready_path:
        result["readinessProbe"] = {"httpGet": {"path": ready_path, "port": ports[0]["containerPort"]},
                                    "periodSeconds": 1, "timeoutSeconds": 2}
    return result


def deployment(name, containers, volumes, *, node_name=None):
    spec = {"automountServiceAccountToken": False, "containers": containers, "volumes": volumes,
            "terminationGracePeriodSeconds": 2}
    if node_name:
        spec["nodeName"] = node_name
    return resource("apps/v1", "Deployment", name, spec={
        "replicas": 1, "strategy": {"type": "Recreate"},
        "selector": {"matchLabels": {"app": name}},
        "template": {"metadata": {"labels": {"app": name}}, "spec": spec},
    })


def wait_rollout(lab, name):
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)


def receiver_records(lab):
    snippet = "import json,urllib.request; print(urllib.request.urlopen('http://audit-sink:8080/records',timeout=3).read().decode())"
    raw = lab.kubectl("exec", READER, "--", "python", "-c", snippet).stdout
    return json.loads(raw)


def collector_status(lab):
    snippet = "import json,urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8081/status',timeout=3).read().decode())"
    return json.loads(lab.kubectl("exec", f"deployment/{COLLECTOR}", "--", "python", "-c", snippet).stdout)


def pod_items(lab, app):
    result = lab.kubectl("get", "pods", "-l", f"app={app}", "-o", "json")
    return json.loads(result.stdout).get("items", [])


def assert_sink_storage_owned(lab):
    storage_class = json.loads(lab.kubectl("get", "storageclass", "standard", "-o", "json").stdout)
    claim = json.loads(lab.kubectl("get", "pvc", SINK_PVC, "-o", "json").stdout)
    pv_name = claim.get("spec", {}).get("volumeName")
    if not pv_name:
        lab.block("The independent receiver claim did not bind to a PV")
    pv = json.loads(lab.kubectl("get", "pv", pv_name, "-o", "json").stdout)
    pods = pod_items(lab, SINK)
    expected = f"/var/local-path-provisioner/{pv_name}_{NAMESPACE}_{SINK_PVC}"
    path = pv.get("spec", {}).get("hostPath", {}).get("path")
    if (storage_class.get("provisioner") != PROVISIONER or len(pods) != 1
            or pods[0].get("spec", {}).get("nodeName") != f"{lab.cluster}-control-plane"
            or claim.get("status", {}).get("phase") != "Bound"
            or claim.get("spec", {}).get("volumeName") != pv_name
            or pv.get("spec", {}).get("claimRef", {}).get("uid") != claim["metadata"]["uid"]
            or path != expected):
        lab.block("The receiver PVC/PV, node, or local-path backing directory was not exactly case-owned")


def wait_until(predicate, lab, message, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.5)
    lab.block(message)


def write_config(lab, cluster, enrolled):
    value = {"cluster_id": cluster, "enrolled_sources": enrolled}
    apply(lab, resource("v1", "ConfigMap", CONFIG,
                        data={"config.json": json.dumps(value, sort_keys=True)}))


def expected_api_record(event, cluster):
    return {
        "source_id": "kubernetes-apiserver:" + cluster,
        "source_type": "kubernetes-apiserver", "record_id": event["auditID"],
        "category": "apiserver-metadata", "event_time": event["stageTimestamp"],
        "subject": event.get("user", {}).get("username", "unknown"),
        "verb": "patch", "status": 200, "synthetic": False,
    }


def start_collector(lab):
    code_mount = {"name": "code", "mountPath": "/app", "readOnly": True}
    config_mount = {"name": "config", "mountPath": "/config", "readOnly": True}
    provider_mount = {"name": "provider", "mountPath": "/provider", "readOnly": True}
    audit_mount = {"name": "audit", "mountPath": "/audit.jsonl", "readOnly": True}
    obj = deployment(COLLECTOR, [container("collector", ["python", "/app/collector.py"],
                                            [code_mount, config_mount, provider_mount, audit_mount],
                                            ports=[{"name": "status", "containerPort": 8081}],
                                            ready_path="/status", root=True)], [
        {"name": "code", "configMap": {"name": CODE}},
        {"name": "config", "configMap": {"name": CONFIG}},
        {"name": "provider", "configMap": {"name": PROVIDER}},
        {"name": "audit", "hostPath": {"path": LOG, "type": "File"}},
    ], node_name=f"{lab.cluster}-control-plane")
    lab.create(obj)
    wait_rollout(lab, COLLECTOR)


def run_supplement(lab, first_event, read_audit):
    scripts = Path(__file__).resolve().parent
    codemap = {"receiver.py": (scripts / "receiver.py").read_text(),
               "collector.py": (scripts / "collector.py").read_text()}
    configmap(lab, CODE, codemap)
    lab.create(resource("v1", "PersistentVolumeClaim", SINK_PVC, spec={
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}},
    }))
    provider_record = {
        "source_id": PROVIDER_ID, "source_type": "provider-fixture", "record_id": PROVIDER_RECORD,
        "category": "synthetic-provider-audit", "event_time": first_event["stageTimestamp"],
        "subject": "synthetic-provider-actor", "verb": "synthetic-marker", "status": 200,
        "synthetic": True,
    }
    configmap(lab, PROVIDER, {"provider.jsonl": json.dumps(provider_record, sort_keys=True) + "\n"})
    write_config(lab, lab.cluster, ["provider-fixture"])

    code_volume = {"name": "code", "configMap": {"name": CODE}}
    code_mount = {"name": "code", "mountPath": "/app", "readOnly": True}
    lab.create(deployment(SINK, [container("receiver", ["python", "/app/receiver.py"], [
        code_mount, {"name": "data", "mountPath": "/data"}],
        ports=[{"name": "http", "containerPort": 8080}], ready_path="/healthz")], [
            code_volume, {"name": "data", "persistentVolumeClaim": {"claimName": SINK_PVC}},
        ]))
    lab.create(resource("v1", "Service", SINK_SERVICE, spec={
        "type": "ClusterIP", "selector": {"app": SINK},
        "ports": [{"name": "http", "port": 8080, "targetPort": 8080}],
    }))
    lab.create({
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": READER},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                 "containers": [container("readback", ["python", "-c", "import time; time.sleep(3600)"], [])]},
    })
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{READER}", "--timeout=90s", timeout=100)
    wait_rollout(lab, SINK)
    assert_sink_storage_owned(lab)
    start_collector(lab)

    provider_only = wait_until(
        lambda: records if (records := receiver_records(lab)) else None,
        lab, "The receiver did not get the enrolled synthetic provider fixture", 30)
    provider_exact = provider_only == [provider_record]
    raw_api_visible = any(event.get("auditID") == first_event["auditID"] for event in read_audit(lab))
    lab.check("green", "Only the explicitly enrolled synthetic provider source reaches the independent receiver",
              provider_exact and raw_api_visible
              and all(row["source_type"] != "kubernetes-apiserver" for row in provider_only),
              {"provider_receipt_exact": provider_exact, "actual_api_event_present_at_producer": raw_api_visible,
               "kubernetes_source_not_enrolled": True})

    write_config(lab, lab.cluster, ["provider-fixture", "kubernetes-apiserver"])
    lab.kubectl("rollout", "restart", f"deployment/{COLLECTOR}")
    wait_rollout(lab, COLLECTOR)
    expected_first = {first_event["auditID"]}
    both = wait_until(
        lambda: (rows if (rows := receiver_records(lab)) and
                 expected_first.issubset({r["record_id"] for r in rows}) else None),
        lab, "The enrolled Kubernetes audit source did not reach the receiver", 45)
    kube_first = [r for r in both if r["source_type"] == "kubernetes-apiserver"]
    provider_rows = [r for r in both if r["source_type"] == "provider-fixture"]
    expected_first_record = expected_api_record(first_event, lab.cluster)
    k8s_exact = kube_first == [expected_first_record]
    lab.check("positive", "Enrolling the Kubernetes source delivers its exact observed event beside the synthetic provider record",
              k8s_exact and provider_rows == [provider_record],
              {"kubernetes_event_delivered": k8s_exact, "distinct_provider_identity": len(provider_rows) == 1,
               "destination_records": len(both)})

    old_sink_pod = pod_items(lab, SINK)
    if len(old_sink_pod) != 1:
        lab.block("Expected exactly one owned receiver Pod before outage")
    old_sink_uid = old_sink_pod[0]["metadata"]["uid"]
    lab.kubectl("scale", f"deployment/{SINK}", "--replicas=0")
    wait_until(lambda: not pod_items(lab, SINK), lab, "The owned receiver did not become unavailable", 30)
    lab.kubectl("patch", "configmap", MARKER, "--type=merge", "-p",
                '{"data":{"marker":"public-receipt-marker-outage-retry"}}')
    observed = wait_until(lambda: (evs if len(evs := read_audit(lab)) >= 2 else None),
                          lab, "The second exact metadata-only API event was not observed", 30)
    events_by_id = {event["auditID"]: event for event in observed}
    if len(events_by_id) != 2 or first_event["auditID"] not in events_by_id:
        lab.block("Expected two unique scoped API audit records from the two fixture patches")
    retry_id = next(key for key in events_by_id if key != first_event["auditID"])
    outage_state = wait_until(
        lambda: (status if (status := collector_status(lab)).get("pending", 0) >= 1
                 and status.get("failures", 0) >= 1 else None),
        lab, "The collector did not retain a pending record and observe the receiver outage", 30)
    retry_event = events_by_id[retry_id]
    retry_source_exact = (retry_event.get("level") == "Metadata"
                          and retry_event.get("objectRef", {}).get("name") == MARKER
                          and retry_event.get("objectRef", {}).get("namespace") == NAMESPACE
                          and retry_event.get("verb") == "patch"
                          and retry_event.get("responseStatus", {}).get("code") == 200)
    lab.check("green", "A source event generated during receiver outage remains pending for retry",
              outage_state["pending"] >= 1 and outage_state["failures"] >= 1
              and not pod_items(lab, SINK) and retry_source_exact,
              {"collector_pending": outage_state["pending"], "delivery_failures_observed": True,
               "receiver_unavailable": True, "exact_metadata_source_event_observed": retry_source_exact})

    lab.kubectl("scale", f"deployment/{SINK}", "--replicas=1")
    wait_rollout(lab, SINK)
    new_sink_pod = pod_items(lab, SINK)
    if len(new_sink_pod) != 1:
        lab.block("The owned receiver did not return to one Pod")
    new_sink_uid = new_sink_pod[0]["metadata"]["uid"]
    expected_ids = {first_event["auditID"], retry_id}
    final_rows = wait_until(
        lambda: (rows if (rows := receiver_records(lab)) and expected_ids.issubset(
                 {r["record_id"] for r in rows}) else None),
        lab, "The independent receiver did not read back both API events after recovery", 45)
    recovered_state = wait_until(
        lambda: (status if (status := collector_status(lab)).get("pending") == 0
                 and status.get("delivered", 0) >= 3 else None),
        lab, "The collector did not acknowledge all three exact source records after recovery", 30)
    row_keys = Counter((row["source_id"], row["record_id"]) for row in final_rows)
    expected_retry_record = expected_api_record(retry_event, lab.cluster)
    all_exact = (len(final_rows) == 3 and row_keys[(PROVIDER_ID, PROVIDER_RECORD)] == 1
                 and row_keys[("kubernetes-apiserver:" + lab.cluster, first_event["auditID"])] == 1
                 and row_keys[("kubernetes-apiserver:" + lab.cluster, retry_id)] == 1
                 and provider_record in final_rows and expected_first_record in final_rows
                 and expected_retry_record in final_rows)
    kube_rows = [row for row in final_rows if row["source_type"] == "kubernetes-apiserver"]
    source_separation = (len(kube_rows) == 2 and all(row["synthetic"] is False for row in kube_rows)
                         and len({row["source_id"] for row in kube_rows}) == 1
                         and sum(row["source_type"] == "provider-fixture" and row["synthetic"] is True
                                 for row in final_rows) == 1)
    lab.check("positive", "The recreated independent receiver retains old records and reads the retried API event exactly once",
              all_exact and source_separation and old_sink_uid != new_sink_uid
              and recovered_state["pending"] == 0 and recovered_state["delivered"] == 3,
              {"exact_records_once": all_exact, "source_identities_separate": source_separation,
               "receiver_recreated": old_sink_uid != new_sink_uid,
               "destination_records": len(final_rows), "collector_pending_after_recovery": recovered_state["pending"],
               "collector_acknowledged_all": recovered_state["delivered"] == 3})
    (lab.evidence / "real-audit-delivery-observations.json").write_text(json.dumps({
        "scope": "synthetic provider fixture plus observed metadata-only API audit events",
        "enrolled_sources_first": ["provider-fixture"],
        "enrolled_sources_after": ["provider-fixture", "kubernetes-apiserver"],
        "source_event_ids": {"kubernetes": sorted(expected_ids), "provider": PROVIDER_RECORD},
        "initial_sink_pod_uid": old_sink_uid, "recreated_sink_pod_uid": new_sink_uid,
        "collector_outage_failures": outage_state["failures"],
        "final_source_types": sorted({row["source_type"] for row in final_rows}),
        "final_receipt_count": len(final_rows), "exact_once": all_exact,
    }, indent=2) + "\n")
