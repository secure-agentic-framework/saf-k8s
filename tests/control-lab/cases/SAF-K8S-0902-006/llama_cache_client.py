"""Fixed harmless b9519 cache observations; no text or token bodies are emitted."""
import ipaddress
import json
import sys
import urllib.request

PORT = 8080
PROMPT = "Once upon a time"
EXPECTED = [9038, 2501, 263, 931]
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(host, method, path, payload=None):
    address = ipaddress.ip_address(host)
    authority = f"[{address}]" if address.version == 6 else str(address)
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {} if body is None else {"Content-Type": "application/json"}
    request = urllib.request.Request(f"http://{authority}:{PORT}{path}", data=body,
                                     headers=headers, method=method)
    with OPENER.open(request, timeout=20) as response:
        data = response.read(32768)
        if len(data) >= 32768:
            raise RuntimeError("fixture response exceeded bound")
        return json.loads(data)


def one(host):
    health = call(host, "GET", "/health")
    models = call(host, "GET", "/v1/models")
    ids = call(host, "POST", "/tokenize", {"content": PROMPT, "add_special": False,
                                            "parse_special": True, "with_pieces": False}).get("tokens")
    if (health != {"status": "ok"}
            or [row.get("id") for row in models.get("data", [])] != ["stories15m-moe"]
            or ids != EXPECTED):
        raise RuntimeError("server readiness/model/tokenizer identity differed from pinned fixture")
    response = call(host, "POST", "/completion", {
        "prompt": PROMPT, "n_predict": 1, "temperature": 0.0, "seed": 42,
        "ignore_eos": True, "return_tokens": True, "cache_prompt": True,
    })
    timings = response.get("timings", {})
    if (response.get("stop_type") != "limit"
            or len(response.get("tokens", [])) != 1
            or type(timings.get("cache_n")) is not int
            or type(timings.get("prompt_n")) is not int):
        raise RuntimeError("bounded completion lacked the pinned server timing shape")
    return {"cache_n": timings["cache_n"], "prompt_n": timings["prompt_n"],
            "predicted_n": timings.get("predicted_n"), "stop_type": response["stop_type"]}


host_a, host_b = sys.argv[1:3]
a_first = one(host_a)
a_second = one(host_a)
b_first = one(host_b)
print(json.dumps({"a_first_cache_n": a_first["cache_n"],
                  "a_first_prompt_n": a_first["prompt_n"],
                  "a_second_cache_n": a_second["cache_n"],
                  "a_second_prompt_n": a_second["prompt_n"],
                  "b_first_cache_n": b_first["cache_n"],
                  "b_first_prompt_n": b_first["prompt_n"],
                  "fixed_prompt_token_count": len(EXPECTED),
                  "bounded_stop_types": [a_first["stop_type"], a_second["stop_type"], b_first["stop_type"]]},
                 separators=(",", ":")))
