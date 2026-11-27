"""One fixed, text-free CPU model observation for SAF-K8S-0905-045."""
import hashlib
import json
import os
import urllib.request

HOST = os.environ["MODEL_SERVER_IP"]
PORT = 8080
PROMPT = "Once upon a time"
EXPECTED_IDS = [9038, 2501, 263, 931]
EXPECTED_SPECIAL_IDS = [1, 9038, 2501, 263, 931]
EXPECTED_OUTPUT_IDS = [29892, 727, 471, 263]
RUBRIC_ID = "arm64-stories15m-once-upon-a-time-seed42-four-token-regression-v1"
ALIAS = "stories15m-moe"
TOKEN_LIMIT = 4


def request(method, path, payload=None):
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        f"http://{HOST}:{PORT}{path}", data=data,
        headers={} if data is None else {"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=12) as response:
        body = response.read(65536)
        if len(body) >= 65536:
            raise RuntimeError("native model response exceeded the fixture bound")
        return response.status, json.loads(body)


status, health = request("GET", "/health")
if status != 200 or health != {"status": "ok"}:
    raise SystemExit("pinned model server was not healthy")
inventory_status, inventory = request("GET", "/v1/models")
if inventory_status != 200:
    raise SystemExit("pinned model inventory request failed")
aliases = [item.get("id") for item in inventory.get("data", [])]
if aliases != [ALIAS]:
    raise SystemExit("running model alias differs from the pinned fixture")
tokenize_status, tokenized = request("POST", "/tokenize", {
    "content": PROMPT, "add_special": False, "parse_special": True,
    "with_pieces": False,
})
prompt_ids = tokenized.get("tokens")
if tokenize_status != 200 or prompt_ids != EXPECTED_IDS:
    raise SystemExit("tokenizer output differs from the reviewed fixed vector")
special_status, special = request("POST", "/tokenize", {
    "content": PROMPT, "add_special": True, "parse_special": True,
    "with_pieces": False,
})
special_ids = special.get("tokens")
if special_status != 200 or special_ids != EXPECTED_SPECIAL_IDS:
    raise SystemExit("special-token count differs from the reviewed fixed vector")
completion_status, completion = request("POST", "/completion", {
    "prompt": PROMPT, "n_predict": TOKEN_LIMIT, "temperature": 0.0,
    "seed": 42, "ignore_eos": True, "return_tokens": True,
    "cache_prompt": False,
})
output_ids = completion.get("tokens")
if (completion_status != 200 or not isinstance(output_ids, list) or len(output_ids) != TOKEN_LIMIT
        or not all(type(token) is int for token in output_ids)
        or completion.get("tokens_evaluated") != len(special_ids)
        or completion.get("stop_type") != "limit"):
    raise SystemExit("completion did not match the fixed generation bound")

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


architecture = os.environ["MODEL_ARCH"]
baseline_applicable = architecture == "arm64"
output_matches = output_ids == EXPECTED_OUTPUT_IDS if baseline_applicable else None
behavior_outcome = (
    "pass" if output_matches is True else
    "fail" if output_matches is False else
    "inconclusive"
)

receipt = {
    "schema": "saf-lab/native-model-observation/v1",
    "candidate_id": "external-stories15m-moe-fixture",
    "outcome": "inconclusive",
    "reason": "insufficient_evaluation_coverage",
    "model": {
        "alias": ALIAS,
        "sha256": os.environ["MODEL_SHA256"],
        "bytes": int(os.environ["MODEL_BYTES"]),
        "llama_release": os.environ["LLAMA_RELEASE"],
    },
    "runtime": {
        "pod_uid": os.environ["MODEL_SERVER_UID"],
        "image_id": os.environ["MODEL_SERVER_IMAGE_ID"],
        "health_status": status,
        "architecture": architecture,
    },
    "request": {
        "prompt_sha256": hashlib.sha256(PROMPT.encode()).hexdigest(),
        "prompt_token_count": len(prompt_ids),
        "prompt_token_ids_sha256": digest(prompt_ids),
        "completion_prompt_tokens_evaluated": completion["tokens_evaluated"],
        "completion_token_count": len(output_ids),
        "completion_token_ids_sha256": digest(output_ids),
        "completion_limit": TOKEN_LIMIT,
        "completion_stop_type": completion["stop_type"],
    },
    "behavior_evaluation": {
        "rubric_id": RUBRIC_ID,
        "baseline_architecture": "arm64",
        "baseline_applicable": baseline_applicable,
        "expected_token_ids_sha256": digest(EXPECTED_OUTPUT_IDS),
        "observed_token_ids_sha256": digest(output_ids),
        "matches_baseline": output_matches,
        "outcome": behavior_outcome,
    },
    "coverage": "One exact-output regression sample is not an approved model-safety rubric or representative evaluation set.",
}
receipt["runtime_receipt_sha256"] = digest(receipt)
print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
