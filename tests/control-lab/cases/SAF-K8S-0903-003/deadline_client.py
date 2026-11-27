"""Send only fixed, small bounded deadline requests to the owned worker Service."""
import json
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


URL = "http://deadline-worker:8080"
HTTP = build_opener(ProxyHandler({}))


def get_state():
    with HTTP.open(URL + "/__fixture/state", timeout=3) as response:
        return json.loads(response.read(4096))


def post(payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    request = Request(URL + "/work", data=body,
                      headers={"Content-Type": "application/json"})
    try:
        with HTTP.open(request, timeout=4) as response:
            return {"status": response.status,
                    "body": json.loads(response.read(4096))}
    except HTTPError as error:
        return {"status": error.code,
                "body": json.loads(error.read(4096))}


report = {}
report["request_before"] = get_state()
report["request_expired"] = post({"scope": "request", "units": 8, "deadline_ms": 45})
report["request_after_expired"] = get_state()
report["request_allowed"] = post({"scope": "request", "units": 2, "deadline_ms": 200})
report["request_after_allowed"] = get_state()

report["session_before"] = get_state()
report["session_first"] = post({"scope": "session", "session_id": "session-expiring",
                                "units": 2, "deadline_ms": 120})
report["session_after_first"] = get_state()
report["session_expired"] = post({"scope": "session", "session_id": "session-expiring",
                                  "units": 8})
report["session_after_expired"] = get_state()
report["session_rejected_after_expiry"] = post({"scope": "session",
                                                "session_id": "session-expiring",
                                                "units": 2})
report["session_after_rejected"] = get_state()
report["session_allowed"] = post({"scope": "session", "session_id": "session-allowed",
                                  "units": 2, "deadline_ms": 200})
report["session_after_allowed"] = get_state()

report["batch_before"] = get_state()
report["batch_expired"] = post({"scope": "batch", "units": 8, "deadline_ms": 45})
report["batch_after_expired"] = get_state()
report["batch_allowed"] = post({"scope": "batch", "units": 2, "deadline_ms": 200})
report["batch_after_allowed"] = get_state()

print(json.dumps(report, sort_keys=True, separators=(",", ":")))
