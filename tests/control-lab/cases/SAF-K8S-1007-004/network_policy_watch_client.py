"""Read a single case-owned NetworkPolicy through a bounded Kubernetes watch."""
import datetime
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
    baseline = json.loads(os.environ["EXPECTED_SPEC"])
    identity = Path("/var/run/saf-watch")
    token = (identity / "token").read_text().strip()
    tls = ssl.create_default_context(cafile=str(identity / "ca.crt"))
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=tls))
    endpoint = ("https://kubernetes.default.svc/apis/networking.k8s.io/v1"
                f"/namespaces/{namespace}/networkpolicies")

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

    unfiltered = status({"watch": "true", "timeoutSeconds": 2})
    outside_name = status({"watch": "true", "timeoutSeconds": 2,
                           "fieldSelector": f"metadata.name={excluded}"})
    selector = {"fieldSelector": f"metadata.name={name}"}
    with read(selector) as response:
        listing = json.load(response)
    item, = listing["items"]
    assert item["metadata"]["uid"] == uid and item["spec"] == baseline
    list_revision = listing["metadata"]["resourceVersion"]
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
                     baseline_uid=uid, baseline_spec=item["spec"], armed_at=utc_now())
            for line in response:
                notification = json.loads(line)
                if notification["type"] == "BOOKMARK":
                    continue
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
                events.append({"uid": uid, "resource_version": observed["resourceVersion"],
                               "generation": observed.get("generation"), "decision": decision,
                               "spec": obj["spec"], "event_received_at_utc": utc_now(),
                               "event_received_monotonic_ns": time.monotonic_ns()})
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
