"""Send fixed requests to the case-owned Service and verify transport receipts."""
import json
import urllib.error
import urllib.request

BASE = "http://inference-fixture:8080"
REQUESTS = {
    "exact_boundary": {"content": "x" * 64, "work_units": 2, "session": "exact",
                       "request_elapsed": 1, "session_elapsed": 1, "batch_elapsed": 1},
    "oversize": {"content": "é" * 32 + "x", "session": "oversize"},
    "request_budget": {"content": "a", "work_units": 4, "session": "req"},
    "session_first": {"content": "a", "work_units": 3, "session": "session"},
    "session_budget": {"content": "a", "work_units": 2, "session": "session"},
    "batch_budget": {"content": "a", "batch_items": 3, "session": "batch"},
    "request_timeout": {"content": "a", "request_elapsed": 3, "session": "req-time"},
    "session_timeout": {"content": "a", "session_elapsed": 5, "session": "sess-time"},
    "batch_timeout": {"content": "a", "batch_elapsed": 6, "session": "batch-time"},
    "overload": {"content": "a", "overload": True, "session": "overload"},
}

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run():
    results = {}
    for name, case in REQUESTS.items():
        req = urllib.request.Request(BASE + "/infer", data=json.dumps(case).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        try:
            response = opener.open(req, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
            if result["status"] != response.status:
                raise ValueError(f"Inconsistent HTTP receipt for {name}")
        results[name] = result
    with opener.open(BASE + "/__fixture/state", timeout=3) as response:
        state = json.load(response)
    return {**state, "results": results}


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
