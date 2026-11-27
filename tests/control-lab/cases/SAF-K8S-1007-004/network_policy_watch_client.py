"""Read a single case-owned NetworkPolicy through a bounded Kubernetes watch."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")


def emit(phase, **fields):
    print(json.dumps({"phase": phase, **fields}, sort_keys=True), flush=True)


def watch():
    name = os.environ["WATCH_POLICY"]
    namespace = os.environ["WATCH_NAMESPACE"]
    uid = os.environ["WATCH_UID"]
    excluded = os.environ["EXCLUDED_POLICY"]
    excluded_namespace = os.environ["EXCLUDED_NAMESPACE"]
    pod_uid = os.environ["WATCH_POD_UID"]
    baseline = json.loads(os.environ["EXPECTED_SPEC"])
    identity = Path("/var/run/saf-watch")
    token = (identity / "token").read_text().strip()
    tls = ssl.create_default_context(cafile=str(identity / "ca.crt"))
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=tls))
    endpoint = ("https://kubernetes.default.svc/apis/networking.k8s.io/v1"
                f"/namespaces/{namespace}/networkpolicies")
    event_endpoint = "https://kubernetes.default.svc/apis/events.k8s.io/v1/namespaces"

    def read(query):
        return client.open(urllib.request.Request(
            endpoint + "?" + urllib.parse.urlencode(query),
            headers={"Accept": "application/json", "Authorization": "Bearer " + token}),
            timeout=45)

    def status(query):
        try:
            with read(query) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    def create_event(target_namespace, event):
        request = urllib.request.Request(
            f"{event_endpoint}/{target_namespace}/events",
            data=json.dumps(event, sort_keys=True, separators=(",", ":")).encode(),
            headers={"Accept": "application/json", "Content-Type": "application/json",
                     "Authorization": "Bearer " + token}, method="POST")
        try:
            with client.open(request, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, None

    def make_event(target_namespace, source_rv, *, source_uid=None, source_name="neighbor-policy",
                   event_name="saf-network-policy-alert-scope-probe"):
        metadata = {"name": event_name, "namespace": target_namespace,
                    "labels": {"saf-k8s.example/control-1007-004": "network-policy-alert"},
                    "annotations": {"saf-k8s.example/source-resource-version": source_rv}}
        regarding = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                     "namespace": target_namespace, "name": source_name}
        if source_uid is not None:
            regarding["uid"] = source_uid
        return {
            "apiVersion": "events.k8s.io/v1", "kind": "Event", "metadata": metadata,
            "eventTime": utc_now(), "reportingController": "saf-k8s.example/network-policy-posture-watch",
            "reportingInstance": pod_uid, "action": "DetectPostureDrift",
            "reason": "NetworkPolicyPostureDrift", "regarding": regarding,
            "note": "Fixture-owned NetworkPolicy posture differs from its declared baseline.",
            "type": "Warning",
        }

    unfiltered = status({"watch": "true", "timeoutSeconds": 2})
    outside_name = status({"watch": "true", "timeoutSeconds": 2,
                           "fieldSelector": f"metadata.name={excluded}"})
    selector = {"fieldSelector": f"metadata.name={name}"}
    with read(selector) as response:
        listing = json.load(response)
    item, = listing["items"]
    assert item["metadata"]["uid"] == uid and item["spec"] == baseline
    list_revision = listing["metadata"]["resourceVersion"]
    probe = make_event(excluded_namespace, list_revision)
    neighbor_event_status, _ = create_event(excluded_namespace, probe)
    def observe(revision, count, resumed):
        query = {**selector, "watch": "true", "resourceVersion": revision,
                 "timeoutSeconds": 50}
        prior_matches = True
        events = []
        with read(query) as response:
            if resumed:
                emit("resumed", http_status=response.status, resource_version=revision,
                     resumed_at=utc_now())
            else:
                emit("armed", http_status=response.status, unfiltered_status=unfiltered,
                     excluded_status=outside_name, list_resource_version=list_revision,
                     baseline_uid=uid, baseline_spec=item["spec"],
                     neighbor_event_create_status=neighbor_event_status,
                     neighbor_event_probe_name="saf-network-policy-alert-scope-probe",
                     armed_at=utc_now())
            for line in response:
                notification = json.loads(line)
                if notification["type"] == "BOOKMARK":
                    continue
                received_at = utc_now()
                received_monotonic = time.monotonic_ns()
                obj = notification["object"]
                assert notification["type"] == "MODIFIED" and obj["kind"] == "NetworkPolicy"
                observed = obj["metadata"]
                assert (observed["namespace"], observed["name"], observed["uid"]) == (namespace, name, uid)
                matches = obj["spec"] == baseline
                if matches == prior_matches:
                    decision = "unchanged"
                elif matches:
                    decision = "recovered"
                else:
                    decision = "drift"
                alert_sink_response = None
                if decision == "drift":
                    source_rv = observed["resourceVersion"]
                    event_name = "saf-network-policy-drift-" + hashlib.sha256(
                        source_rv.encode()).hexdigest()[:12]
                    event = make_event(namespace, source_rv, source_uid=uid,
                                       source_name=name, event_name=event_name)
                    status_code, created = create_event(namespace, event)
                    created_metadata = (created or {}).get("metadata", {})
                    alert_sink_response = {
                        "status": status_code, "event_name": created_metadata.get("name"),
                        "event_uid": created_metadata.get("uid"),
                        "event_resource_version": created_metadata.get("resourceVersion"),
                        "source_resource_version": source_rv,
                    }
                events.append({"uid": uid, "resource_version": observed["resourceVersion"],
                               "generation": observed.get("generation"), "decision": decision,
                               "spec": obj["spec"], "event_received_at_utc": received_at,
                               "event_received_monotonic_ns": received_monotonic,
                               "alert_sink_response": alert_sink_response})
                prior_matches = matches
                if len(events) == count:
                    return events
        raise RuntimeError("NetworkPolicy watch closed before the controlled event sequence completed")

    events = observe(list_revision, 3, resumed=False)
    checkpoint = events[-1]["resource_version"]
    emit("complete", events=events, complete_at=utc_now(), checkpoint=checkpoint)
    deadline = time.monotonic() + 45
    while not Path("/gate/resume").exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("The case did not release the watch resume gate")
        time.sleep(0.2)
    recovered = observe(checkpoint, 2, resumed=True)
    emit("recovery_complete", events=recovered)


if __name__ == "__main__":
    watch()
