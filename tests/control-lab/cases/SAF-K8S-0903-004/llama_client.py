"""Bounded direct-Pod API witness for the pinned llama.cpp CPU server."""
import ipaddress
import json
import sys
import urllib.error
import urllib.request

ADDRESS = ipaddress.ip_address(sys.argv[1])
HOST = f"[{ADDRESS}]" if ADDRESS.version == 6 else str(ADDRESS)
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
PORT = 8080
PROMPT = "Once upon a time"
EXPECTED_PROMPT_IDS = [9038, 2501, 263, 931]
TOKEN_LIMIT = 4


def request(method, path, payload=None):
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {} if data is None else {"Content-Type": "application/json"}
    req = urllib.request.Request(f"http://{HOST}:{PORT}{path}", data=data,
                                 headers=headers, method=method)
    with HTTP.open(req, timeout=12) as response:
        body = response.read(65536)
        if len(body) >= 65536:
            raise RuntimeError("response exceeds bounded fixture response size")
        return response.status, json.loads(body)


status, health = request("GET", "/health")
if status != 200 or health != {"status": "ok"}:
    raise RuntimeError("pinned server health did not report ready")
_, inventory = request("GET", "/v1/models")
aliases = [item.get("id") for item in inventory.get("data", [])]
if aliases != ["stories15m-moe"]:
    raise RuntimeError("expected exactly the reviewed tiny model alias")


_, plain = request("POST", "/tokenize", {
    "content": PROMPT, "add_special": False, "parse_special": True,
    "with_pieces": False,
})
_, special = request("POST", "/tokenize", {
    "content": PROMPT, "add_special": True, "parse_special": True,
    "with_pieces": False,
})
plain_ids = plain.get("tokens")
special_ids = special.get("tokens")
if (not isinstance(plain_ids, list) or not isinstance(special_ids, list)
        or not plain_ids or not special_ids
        or not all(type(token) is int for token in plain_ids + special_ids)):
    raise RuntimeError("/tokenize did not return bounded integer token ID arrays")
if plain_ids != EXPECTED_PROMPT_IDS:
    raise RuntimeError("pinned b9519 Stories tokenizer IDs differed from the reviewed fixed vector")

_, completion = request("POST", "/completion", {
    "prompt": PROMPT,
    "n_predict": TOKEN_LIMIT,
    "temperature": 0.0,
    "seed": 42,
    "ignore_eos": True,
    "return_tokens": True,
    "cache_prompt": False,
})
generated_ids = completion.get("tokens")
prompt_evaluated = completion.get("tokens_evaluated")
if (not isinstance(generated_ids, list) or len(generated_ids) != TOKEN_LIMIT
        or not all(type(token) is int for token in generated_ids)):
    raise RuntimeError("completion did not return exactly the requested bounded token IDs")
if type(prompt_evaluated) is not int or prompt_evaluated != len(special_ids):
    raise RuntimeError("completion prompt count does not match the model /tokenize count")
if completion.get("stop_type") != "limit":
    raise RuntimeError("completion did not stop at its configured token limit")

# Keep evidence bounded: report token IDs and counts, but omit generated text.
print(json.dumps({
    "health_status": status,
    "model_alias": aliases[0],
    "prompt_token_ids_add_special_false": plain_ids,
    "prompt_token_count_add_special_false": len(plain_ids),
    "prompt_token_ids_add_special_true": special_ids,
    "prompt_token_count_add_special_true": len(special_ids),
    "completion_prompt_tokens_evaluated": prompt_evaluated,
    "completion_token_ids": generated_ids,
    "completion_tokens": len(generated_ids),
    "completion_limit": TOKEN_LIMIT,
    "completion_stop_type": completion["stop_type"],
}, separators=(",", ":")))
