"""Read one case-owned role through a bounded Kubernetes list/watch."""
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request


def emit(phase, **fields):
    print(json.dumps({"phase": phase, **fields}, sort_keys=True), flush=True)


def watch():
    name = os.environ["WATCH_ROLE"]
    namespace = os.environ["WATCH_NAMESPACE"]
    uid = os.environ["WATCH_UID"]
    excluded = os.environ["EXCLUDED_ROLE"]
    baseline = json.loads(os.environ["EXPECTED_RULES"])
    identity = Path("/var/run/saf-watch")
    token = (identity / "token").read_text().strip()
    tls = ssl.create_default_context(cafile=str(identity / "ca.crt"))
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=tls))
    endpoint = ("https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1"
                f"/namespaces/{namespace}/roles")

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
    assert item["metadata"]["uid"] == uid and item["rules"] == baseline
    list_revision = listing["metadata"]["resourceVersion"]
    query = {**selector, "watch": "true", "resourceVersion": list_revision,
             "timeoutSeconds": 35}
    with read(query) as response:
        emit("armed", http_status=response.status, unfiltered_status=unfiltered,
             excluded_status=outside_name, list_resource_version=list_revision,
             baseline_uid=uid, baseline_rules=item["rules"])
        prior_matches = True
        events = []
        for line in response:
            notification = json.loads(line)
            obj = notification["object"]
            assert notification["type"] == "MODIFIED" and obj["kind"] == "Role"
            observed = obj["metadata"]
            assert (observed["namespace"], observed["name"], observed["uid"]) == (namespace, name, uid)
            matches = obj["rules"] == baseline
            if matches == prior_matches:
                decision = "unchanged"
            elif matches:
                decision = "recovered"
            else:
                decision = "drift"
            events.append({"uid": uid, "resource_version": observed["resourceVersion"],
                           "decision": decision, "rules": obj["rules"]})
            prior_matches = matches
            if len(events) == 3:
                emit("complete", events=events)
                return
    raise RuntimeError("Role watch closed before the controlled event sequence completed")


if __name__ == "__main__":
    watch()
