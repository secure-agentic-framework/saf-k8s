"""Reviewer process for a digest-bound real-model hold record."""
import hashlib
import json
from pathlib import Path
import ssl
import urllib.error
import urllib.request

NAMESPACE = "saf-test"
EVALUATION = "native-model-evaluation"
DISPOSITION = "native-model-disposition"
REVIEWER = "native-model-reviewer"
MODEL_SHA256 = "1240dfc1957df9f3550dd6c1d9e64b466fc2f452d8bc34bd4e45e1a1e2ca6055"
MODEL_BYTES = 73466432
PROMPT_SHA256 = hashlib.sha256(b"Once upon a time").hexdigest()
API = "https://kubernetes.default.svc"
SA = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def request(method, path, body=None):
    token = (SA / "token").read_text().strip()
    data = None if body is None else json.dumps(body, sort_keys=True).encode()
    req = urllib.request.Request(
        API + path, data=data, method=method,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    context = ssl.create_default_context(cafile=str(SA / "ca.crt"))
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    try:
        with client.open(req, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.load(error)
        except (ValueError, OSError):
            raise RuntimeError("API returned a non-JSON error") from None


status, config = request("GET", f"/api/v1/namespaces/{NAMESPACE}/configmaps/{EVALUATION}")
if status != 200 or config.get("immutable") is not True:
    raise SystemExit("immutable runtime evaluation is unavailable")
record = json.loads(config["data"]["evaluation.json"])
without_digest = {key: value for key, value in record.items() if key != "runtime_receipt_sha256"}
runtime_digest = hashlib.sha256(canonical(without_digest)).hexdigest()
if record.get("runtime_receipt_sha256") != runtime_digest:
    raise SystemExit("native runtime receipt digest mismatch")
if (record.get("candidate_id") != "external-stories15m-moe-fixture"
        or record.get("outcome") != "inconclusive"
        or record.get("reason") != "insufficient_evaluation_coverage"
        or record.get("model") != {"alias": "stories15m-moe", "sha256": MODEL_SHA256,
                                    "bytes": MODEL_BYTES, "llama_release": "b9519"}
        or record.get("request", {}).get("prompt_sha256") != PROMPT_SHA256
        or record.get("request", {}).get("prompt_token_count") != 4
        or record.get("request", {}).get("completion_prompt_tokens_evaluated") != 5
        or record.get("request", {}).get("completion_token_count") != 4
        or record.get("request", {}).get("completion_limit") != 4
        or record.get("request", {}).get("completion_stop_type") != "limit"
        or not record.get("request", {}).get("completion_token_ids_sha256")
        or record.get("coverage") != "A fixed smoke request does not apply an approved model-safety rubric or representative evaluation set."
        or record.get("runtime", {}).get("health_status") != 200
        or not record.get("runtime", {}).get("pod_uid")
        or not record.get("runtime", {}).get("image_id")):
    raise SystemExit("runtime record does not satisfy the bounded held candidate schema")

evaluation_digest = hashlib.sha256(canonical(record)).hexdigest()
decision = {
    "candidate_id": record["candidate_id"],
    "disposition": "escalated",
    "reason": "insufficient_evaluation_coverage",
    "reviewer": REVIEWER,
    "evaluation_sha256": evaluation_digest,
    "runtime_receipt_sha256": runtime_digest,
}
status, output = request("GET", f"/api/v1/namespaces/{NAMESPACE}/configmaps/{DISPOSITION}")
if status != 200:
    raise SystemExit("native model disposition record is unavailable")
output["data"] = {"decision.json": json.dumps(decision, sort_keys=True, separators=(",", ":"))}
status, _ = request("PUT", f"/api/v1/namespaces/{NAMESPACE}/configmaps/{DISPOSITION}", output)
if status != 200:
    raise SystemExit("native model escalation write failed")
print(json.dumps(decision, sort_keys=True, separators=(",", ":")))
