"""Independent fixture reviewer writes one exact decision record and Event."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import ssl
import urllib.error
import urllib.request

NAMESPACE = "saf-test"
EVALUATION = "behavioral-evaluation"
DISPOSITION = "model-disposition"
REVIEWER = "independent-model-reviewer"
API = "https://kubernetes.default.svc"
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def request(method, path, body=None):
    token = TOKEN.read_text().strip()
    data = None if body is None else json.dumps(body, sort_keys=True).encode()
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + token,
                                          "Content-Type": "application/json"})
    context = ssl.create_default_context(cafile=CA)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=context))
        with opener.open(req, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.load(error)
        except (ValueError, OSError):
            raise RuntimeError("Kubernetes API returned a non-JSON error") from None


status, config = request("GET", f"/api/v1/namespaces/{NAMESPACE}/configmaps/{EVALUATION}")
if status != 200 or config.get("immutable") is not True:
    raise SystemExit("sealed evaluation is unavailable")
evaluation = json.loads(config["data"]["evaluation.json"])
if len(evaluation.get("records", [])) != 3 or [
        item.get("candidate_id") for item in evaluation["records"]
] != ["toy-clean-v1", "toy-reject-v1", "toy-inconclusive-v1"]:
    raise SystemExit("evaluation is outside the bounded candidate set")
canonical = json.dumps({"evaluator": evaluation["evaluator"], "records": evaluation["records"],
                        "behavior_trace": evaluation["behavior_trace"]},
                       sort_keys=True, separators=(",", ":")).encode()
digest = hashlib.sha256(canonical).hexdigest()
if digest != evaluation.get("evaluation_sha256"):
    raise SystemExit("evaluation digest mismatch")

decisions = []
for result in evaluation["records"]:
    if result["outcome"] == "pass" and result["reason"] == "expected_behavior":
        disposition, reason = "approved", "behavioral_checks_passed"
    elif result["outcome"] == "fail" and result["reason"] == "behavioral_policy_violation":
        disposition, reason = "rejected", "behavioral_policy_violation"
    elif result["outcome"] == "inconclusive" and result["reason"] == "insufficient_evidence":
        disposition, reason = "escalated", "insufficient_evidence"
    else:
        raise SystemExit("unrecognized evaluator result; disposition escalated")
    decisions.append({"candidate_id": result["candidate_id"], "disposition": disposition,
                      "reason": reason, "reviewer": REVIEWER, "evaluation_sha256": digest})

record = {"evaluator": evaluation["evaluator"], "reviewer": REVIEWER,
          "evaluation_sha256": digest, "decisions": decisions}
status, output = request("GET", f"/api/v1/namespaces/{NAMESPACE}/configmaps/{DISPOSITION}")
if status != 200:
    raise SystemExit("disposition record is unavailable")
output["data"] = {"decisions.json": json.dumps(record, sort_keys=True, separators=(",", ":"))}
status, _ = request("PUT", f"/api/v1/namespaces/{NAMESPACE}/configmaps/{DISPOSITION}", output)
if status != 200:
    raise SystemExit("disposition record update failed")

rejected = [item for item in decisions if item["disposition"] == "rejected"]
if len(rejected) != 1:
    raise SystemExit("expected exactly one synthetic rejection")
event = {
    "apiVersion": "events.k8s.io/v1", "kind": "Event",
    "metadata": {"name": "synthetic-model-rejection", "namespace": NAMESPACE},
    "eventTime": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
    "type": "Warning",
    "reason": "ModelBehaviorRejected", "action": "behavioral-review",
    "note": rejected[0]["candidate_id"] + " rejected: " + rejected[0]["reason"],
    "regarding": {"apiVersion": "batch/v1", "kind": "Job",
                  "name": "toy-model-evaluation", "namespace": NAMESPACE,
                  "uid": os.environ["EVALUATION_JOB_UID"]},
    "reportingController": "saf.example/model-disposition-reviewer",
    "reportingInstance": REVIEWER,
}
status, _ = request("POST", f"/apis/events.k8s.io/v1/namespaces/{NAMESPACE}/events", event)
if status != 201:
    raise SystemExit("synthetic rejection event creation failed")
print(json.dumps(record, sort_keys=True, separators=(",", ":")))
