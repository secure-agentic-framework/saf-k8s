"""Apply the versioned promotion policy to one owned synthetic artifact."""
from datetime import datetime, timezone
from http.client import HTTPSConnection
import json
from pathlib import Path
import ssl
import sys


CONFIG = Path("/fixture")
CREDENTIAL = Path("/var/run/secrets/kubernetes.io/serviceaccount")
CLASSIFICATION = "saf-k8s.example/data-classification"
API_PREFIX = "/api/v1/namespaces/saf-test/configmaps/"


def api(method, name, body=None):
    context = ssl.create_default_context(cafile=str(CREDENTIAL / "ca.crt"))
    connection = HTTPSConnection("kubernetes.default.svc", timeout=8, context=context)
    try:
        headers = {"Authorization": "Bearer " + (CREDENTIAL / "token").read_text().strip()}
        if body is not None:
            headers["Content-Type"] = ("application/merge-patch+json" if method == "PATCH"
                                       else "application/json")
        connection.request(method, API_PREFIX + name, body=None if body is None else json.dumps(body),
                           headers=headers)
        response = connection.getresponse()
        raw = response.read()
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {}
        return response.status, payload
    finally:
        connection.close()


def update_target(name, source_class, required, policy):
    status, current = api("GET", "target-" + name)
    if status != 200:
        raise RuntimeError(f"fixture target read returned {status}")
    ranks = policy["classification_ranks"]
    metadata = current["metadata"]
    current_class = metadata.get("labels", {}).get(CLASSIFICATION)
    event = {
        "event": "model.promotion.classification", "artifact_id": "synthetic-model-marker-v1",
        "source": source_class, "target": policy["targets"][name]["environment"],
        "policy_version": policy["policy_version"],
    }
    if any(value not in ranks for value in (source_class, required, current_class)):
        print(json.dumps({**event, "decision": "unresolved_requirement", "applied": None}), flush=True)
        return

    chosen = max((source_class, required, current_class), key=ranks.__getitem__)
    decision = "uplifted" if ranks[chosen] > ranks[current_class] else "preserved"
    metadata.setdefault("labels", {})[CLASSIFICATION] = chosen
    annotations = metadata.setdefault("annotations", {})
    annotations.update({
        "saf-k8s.example/promotion-decision": decision,
        "saf-k8s.example/promotion-policy": policy["policy_version"],
        "saf-k8s.example/promotion-reviewed-at": datetime.now(timezone.utc).isoformat(),
    })
    # PUT carries the observed resourceVersion, so concurrent changes fail closed.
    status, updated = api("PUT", "target-" + name, current)
    if status != 200:
        raise RuntimeError(f"fixture target update returned {status}")
    applied = updated.get("metadata", {}).get("labels", {}).get(CLASSIFICATION)
    if applied != chosen:
        raise RuntimeError("fixture API did not retain the computed classification")
    print(json.dumps({**event, "decision": decision, "applied": applied}), flush=True)


def deny_probe(kind, name):
    if kind == "deny-target":
        path = "target-" + name
        body = {"metadata": {"labels": {CLASSIFICATION: "synthetic-public"}}}
    elif kind == "deny-policy":
        path = "promotion-policy"
        body = {"data": {"promotion-policy-v1.json": "unauthorized-synthetic-change"}}
    else:
        raise RuntimeError("unknown fixture probe")
    status, _ = api("PATCH", path, body)
    print(json.dumps({"probe": kind, "http_status": status, "denied": status == 403}), flush=True)
    if status != 403:
        raise RuntimeError("fixture authorization boundary did not deny the request")


def main():
    if sys.argv[1] in {"deny-target", "deny-policy"}:
        deny_probe(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
        return
    name = sys.argv[1]
    source = json.loads((CONFIG / "source-artifact.json").read_text())
    policy = json.loads((CONFIG / "promotion-policy-v1.json").read_text())
    target = policy["targets"][name]
    update_target(name, source["classification"], target["required_classification"], policy)


if __name__ == "__main__":
    main()
