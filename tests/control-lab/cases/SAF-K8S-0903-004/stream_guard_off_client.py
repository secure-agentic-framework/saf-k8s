"""Compare two bounded requests against the identical service with only its input guard off."""
import argparse
import json

from encoding_fixture import load_encoding
from stream_client import Wire, ndjson_chunks

PORT = 8080
PROMPT_TEMPLATE = "Summarize this public note: {body}"
BODY = "The public release note describes routine maintenance."
OVERSIZED_BODY = " ".join([BODY] * 16)
OUTPUT_IDS = (606, 1403, 2380, 3116, 4330, 4848, 8254, 8223)


def main(host):
    encoding = load_encoding()
    prompt = PROMPT_TEMPLATE.format(body=OVERSIZED_BODY)
    input_tokens = len(encoding.encode_ordinary(prompt))
    output_ids = tuple(encoding.encode_ordinary("one two three four five six seven eight"))
    assert input_tokens == 135 and output_ids == OUTPUT_IDS

    wire = Wire(host, PORT)
    status, _, payload = wire.request("GET", "/health")
    health = json.loads(payload)
    assert status == 200 and health == {
        "service": "saf-0903-004-stream-fixture", "status": "ready",
        "tokenizer": "cl100k_base", "max_input_tokens": None,
        "input_limit_enabled": False, "max_request_output_tokens": 4,
        "max_total_generated_tokens": 6, "max_post_requests": 8,
    }, health

    for expected_id, expected_total in zip(OUTPUT_IDS[:2], (1, 2)):
        status, headers, chunks = wire.request("POST", "/generate", {
            "prompt_id": "oversized", "requested_output_tokens": 1})
        records = ndjson_chunks(chunks)
        assert status == 200 and headers.get("transfer-encoding") == "chunked"
        assert records == [
            {"event": "token", "index": 1, "token_id": expected_id,
             "generated_total": expected_total},
            {"event": "done", "accepted": True, "reason": "complete",
             "prompt_id": "oversized", "input_tokens": 135,
             "input_limit_enabled": False, "requested_output_tokens": 1,
             "output_cap": 4, "output_tokens": 1,
             "generated_total": expected_total, "backend_dispatched": True},
        ], records

    status, _, payload = wire.request("GET", "/metrics")
    metrics = json.loads(payload)
    assert status == 200 and metrics == {"received_posts": 2,
        "backend_requests": 2, "backend_prompt_tokens": 270,
        "generated_tokens": 2}, metrics
    assert wire.requests == 4
    checks = [
        {"name": "same_prompt_guard_switch_accepts", "passed": True,
         "detail": {"input_tokens_each": 135, "requests": 2,
                    "input_limit_enabled": False}},
        {"name": "guard_off_finite_output_and_counters", "passed": True,
         "detail": {"metrics": metrics, "token_ids": list(OUTPUT_IDS[:2]),
                    "http_requests": wire.requests}},
    ]
    return {"check_count": len(checks), "checks": checks,
            "http_requests": wire.requests, "metrics": metrics,
            "comparison": {"guarded_expected": {"status": 413,
                "input_tokens": 135, "backend_dispatched": False},
                "guard_off_observed": {"accepted_requests": 2,
                    "input_tokens_each": 135, "backend_prompt_tokens": 270}}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, choices=("saf-bpe-stream-input-limit-off",))
    args = parser.parse_args()
    print(json.dumps(main(args.host), sort_keys=True, separators=(",", ":")))
