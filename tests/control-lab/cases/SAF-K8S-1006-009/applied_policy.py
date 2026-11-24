"""Correlate fixture decisions to policy content observed in the API."""
from datetime import datetime, timezone
from hashlib import sha256
import json

RESOURCE = "namespacedvalidatingpolicy"
REVISION = "saf-lab.example/policy-revision"


def canonical(policy):
    metadata = policy["metadata"]
    values = {"api_version": policy["apiVersion"], "kind": policy["kind"],
              "namespace": metadata["namespace"], "name": metadata["name"],
              "spec": policy["spec"]}
    return sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def live(lab, namespace, name):
    return json.loads(lab.kubectl("-n", namespace, "get", RESOURCE, name, "-o", "json").stdout)


def observe(lab, namespace, name, source, commit):
    fixture = live(lab, namespace, name)
    parsed = lab.kubectl("-n", namespace, "create", "-f", "-", "--dry-run=client",
                         "-o", "json", payload=source)
    expected = json.loads(parsed.stdout)
    expected["metadata"]["resourceVersion"] = fixture["metadata"]["resourceVersion"]
    dry_run = lab.kubectl("-n", namespace, "replace", "--dry-run=server", "-f", "-",
                          "-o", "json", payload=json.dumps(expected))
    approved_digest, live_digest = canonical(json.loads(dry_run.stdout)), canonical(fixture)
    return {"source_commit": commit, "approved_digest": approved_digest, "live_digest": live_digest,
            "reported_revision": fixture["metadata"]["labels"][REVISION],
            "generation": fixture["metadata"]["generation"], "observed_at": datetime.now(timezone.utc).isoformat()}


def install_counterfactual(lab, namespace, name, source, commit):
    patch = [{"op": "replace", "path": "/spec/validations/0/message",
              "value": "SAF evidence fixture temporary comparison"}]
    lab.kubectl("-n", namespace, "patch", RESOURCE, name, "--type=json", "--patch", json.dumps(patch))
    actual = observe(lab, namespace, name, source, commit)
    lab.check("red", "An unchanged revision label cannot validate different live policy content",
              actual["reported_revision"] == "r1" and actual["approved_digest"] != actual["live_digest"],
              {"unchanged_revision_label": actual["reported_revision"] == "r1",
               "unapproved_live_content_detected": actual["approved_digest"] != actual["live_digest"]})


def correlate(lab, namespace, name, before, event_rows):
    end = live(lab, namespace, name)
    fence = datetime.now(timezone.utc)
    start = datetime.fromisoformat(before["observed_at"])
    stable = (canonical(end) == before["approved_digest"] == before["live_digest"]
              and end["metadata"]["generation"] == before["generation"])
    rows = []
    for event in event_rows:
        received = event.get("requestReceivedTimestamp", "")
        try:
            inside = start <= datetime.fromisoformat(received.replace("Z", "+00:00")) <= fence
        except ValueError:
            inside = False
        ref = event["objectRef"]
        rows.append({"audit_id": event["auditID"], "received": received, "namespace": ref["namespace"],
                     "object": ref["name"], "result": event["responseStatus"]["code"],
                     "policy_content_sha256": before["approved_digest"], "source_commit": before["source_commit"],
                     "within_observed_generation": stable and inside})
    return rows
