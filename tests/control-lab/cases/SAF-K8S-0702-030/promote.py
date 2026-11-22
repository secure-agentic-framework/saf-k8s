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


def patch(name, data):
    endpoint = "/api/v1/namespaces/saf-test/configmaps/target-" + name
    context = ssl.create_default_context(cafile=str(CREDENTIAL / "ca.crt"))
    connection = HTTPSConnection("kubernetes.default.svc", timeout=8, context=context)
    try:
        connection.request("PATCH", endpoint, body=json.dumps(data), headers={
            "Content-Type": "application/merge-patch+json",
            "Authorization": "Bearer " + (CREDENTIAL / "token").read_text().strip(),
        })
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"fixture metadata update returned {response.status}")
        return json.load(response)["metadata"]["labels"].get(CLASSIFICATION)
    finally:
        connection.close()


def main():
    name = sys.argv[1]
    source = json.loads((CONFIG / "source-artifact.json").read_text())
    policy = json.loads((CONFIG / "promotion-policy-v1.json").read_text())
    target = policy["targets"][name]
    ranks = policy["classification_ranks"]
    original, required = source["classification"], target["required_classification"]
    event = {
        "event": "model.promotion.classification", "artifact_id": source["artifact_id"],
        "source": original, "target": target["environment"], "policy_version": policy["policy_version"],
    }
    if original not in ranks or required not in ranks:
        print(json.dumps({**event, "decision": "unresolved_requirement", "applied": None}), flush=True)
        return

    increase = ranks[required] > ranks[original]
    classification = required if increase else original
    decision = "uplifted" if increase else "preserved"
    decided = datetime.now(timezone.utc).isoformat()
    metadata = {
        "labels": {CLASSIFICATION: classification},
        "annotations": {"saf-k8s.example/promotion-decision": decision,
                        "saf-k8s.example/promotion-policy": policy["policy_version"],
                        "saf-k8s.example/promotion-reviewed-at": decided},
    }
    applied = patch(name, {"metadata": metadata})
    if applied != classification:
        raise RuntimeError("fixture API did not retain the computed classification")
    print(json.dumps({**event, "decision": decision, "applied": applied}), flush=True)


if __name__ == "__main__":
    main()
