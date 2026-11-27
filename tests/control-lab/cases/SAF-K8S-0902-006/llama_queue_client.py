"""Observe one bounded b9519 request deferral without retaining generated text."""
import http.client
import ipaddress
import json
import re
import sys
import threading
import time

PORT = 8080
FIRST = {"prompt": "Once upon a time", "n_predict": 192, "temperature": 0.0,
         "seed": 42, "ignore_eos": True, "cache_prompt": False}
SECOND = {"prompt": "A small bird rested beside a blue pond", "n_predict": 8,
          "temperature": 0.0, "seed": 42, "ignore_eos": True, "cache_prompt": False}
REQUEST_TIMEOUT = 45
METRIC_WAIT = 10
POLL_INTERVAL = 0.025
METRIC_PATTERNS = {
    "processing": re.compile(r"^llamacpp:requests_processing(?:\{[^}]*\})?\s+([0-9.eE+-]+)$"),
    "deferred": re.compile(r"^llamacpp:requests_deferred(?:\{[^}]*\})?\s+([0-9.eE+-]+)$"),
}


def _authority(host):
    return str(ipaddress.ip_address(host))


def _request(host, method, path, payload=None, timeout=5):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {} if body is None else {"Content-Type": "application/json"}
    connection = http.client.HTTPConnection(_authority(host), PORT, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(32768)
        if len(raw) >= 32768:
            raise RuntimeError("bounded native queue response exceeded the response limit")
        return response.status, raw.decode("utf-8", errors="strict")
    finally:
        connection.close()


def _metrics(host):
    status, raw = _request(host, "GET", "/metrics", timeout=4)
    if status != 200:
        raise RuntimeError("pinned llama.cpp metrics endpoint did not return HTTP 200")
    values = {}
    for line in raw.splitlines():
        for key, pattern in METRIC_PATTERNS.items():
            match = pattern.match(line.strip())
            if match:
                if key in values:
                    raise RuntimeError("native queue metric appeared more than once")
                values[key] = float(match.group(1))
    if set(values) != {"processing", "deferred"}:
        raise RuntimeError("native processing/deferred metrics were missing or ambiguous")
    return values


def _wait_metrics(host, predicate, seconds):
    deadline = time.monotonic() + seconds
    latest = None
    while time.monotonic() < deadline:
        latest = _metrics(host)
        if predicate(latest):
            return latest
        time.sleep(POLL_INTERVAL)
    return latest


def _completion(host, payload, submitted=None):
    connection = http.client.HTTPConnection(_authority(host), PORT, timeout=REQUEST_TIMEOUT)
    body = json.dumps(payload, separators=(",", ":")).encode()
    try:
        connection.putrequest("POST", "/completion")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        if submitted is not None:
            submitted.set()
        response = connection.getresponse()
        raw = response.read(32768)
        if len(raw) >= 32768:
            raise RuntimeError("bounded completion response exceeded the response limit")
        parsed = json.loads(raw)
        timings = parsed.get("timings", {})
        # Deliberately do not return or log completion text or token IDs.
        return {"http_status": response.status,
                "stop_type": parsed.get("stop_type"),
                "predicted_n": timings.get("predicted_n"),
                "prompt_n": timings.get("prompt_n"),
                "cache_n": timings.get("cache_n")}
    finally:
        connection.close()


host = sys.argv[1]
baseline = _metrics(host)
if baseline != {"processing": 0.0, "deferred": 0.0}:
    raise RuntimeError("pinned server was not idle before queue witness")

first_result = {}
first_error = {}
first_submitted = threading.Event()

def first_request():
    try:
        first_result["value"] = _completion(host, FIRST, submitted=first_submitted)
    except Exception as error:  # retain only a bounded type name on failure
        first_error["type"] = type(error).__name__

first_thread = threading.Thread(target=first_request, daemon=True)
first_thread.start()
processing_before_second = _wait_metrics(
    host, lambda value: value == {"processing": 1.0, "deferred": 0.0}, METRIC_WAIT)
if processing_before_second != {"processing": 1.0, "deferred": 0.0}:
    raise RuntimeError("one fixed completion did not occupy the only server slot")

second_result = {}
second_error = {}
second_submitted = threading.Event()
def second_request():
    try:
        second_result["value"] = _completion(host, SECOND, submitted=second_submitted)
    except Exception as error:
        second_error["type"] = type(error).__name__

second_thread = threading.Thread(target=second_request, daemon=True)
second_thread.start()
submitted = second_submitted.wait(timeout=5)
processing_and_deferred = (_wait_metrics(
    host, lambda value: value == {"processing": 1.0, "deferred": 1.0}, METRIC_WAIT)
    if submitted else None)
first_thread.join(timeout=REQUEST_TIMEOUT + 2)
second_thread.join(timeout=REQUEST_TIMEOUT + 2)
both_complete = (not first_thread.is_alive() and not second_thread.is_alive()
                 and first_result.get("value", {}).get("http_status") == 200
                 and second_result.get("value", {}).get("http_status") == 200
                 and first_result.get("value", {}).get("stop_type") == "limit"
                 and second_result.get("value", {}).get("stop_type") == "limit"
                 and type(first_result.get("value", {}).get("predicted_n")) is int
                 and type(second_result.get("value", {}).get("predicted_n")) is int
                 and first_result["value"]["predicted_n"] == FIRST["n_predict"]
                 and second_result["value"]["predicted_n"] == SECOND["n_predict"])
drained = (_wait_metrics(host, lambda value: value == {"processing": 0.0, "deferred": 0.0},
                         METRIC_WAIT) if both_complete else None)
print(json.dumps({
    "baseline_idle": baseline == {"processing": 0.0, "deferred": 0.0},
    "one_active_before_second_submission": processing_before_second == {"processing": 1.0, "deferred": 0.0},
    "second_request_submitted": submitted,
    "one_active_one_deferred": processing_and_deferred == {"processing": 1.0, "deferred": 1.0},
    "both_bounded_completions_succeeded": both_complete,
    "processing_after_drain": None if drained is None else drained["processing"],
    "deferred_after_drain": None if drained is None else drained["deferred"],
    "queue_returned_to_zero": drained == {"processing": 0.0, "deferred": 0.0},
    "request_counts": {"submitted": int(first_submitted.is_set()) + int(submitted),
                       "completed": int("value" in first_result) + int("value" in second_result)},
    "completion_token_counts": {
        "first_predicted_n": first_result.get("value", {}).get("predicted_n"),
        "second_predicted_n": second_result.get("value", {}).get("predicted_n"),
        "first_expected_n": FIRST["n_predict"],
        "second_expected_n": SECOND["n_predict"]},
    "client_error_types": sorted(set(first_error.values()) | set(second_error.values())),
}, separators=(",", ":")))
