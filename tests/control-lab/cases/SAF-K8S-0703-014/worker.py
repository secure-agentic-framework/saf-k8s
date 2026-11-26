"""In-cluster evaluator: reads named synthetic events with its own projected token."""

import json
import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote


NAMESPACE = "saf-budget-0703-014"
ACTOR = "budget-response"
MANAGED_JOB = "owned-training"
OTHER_JOB = "unrelated-training"
EVENTS = ("red-unarmed", "warning", "stale", "wrong-target", "green-armed")
ALERT_UNITS = 80
LIMIT_UNITS = 100
ROOT = Path("/var/run/saf-api")


def request(method, path, body=None, expected_error=None):
    token = (ROOT / "token").read_text(encoding="ascii").strip()
    encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = urllib.request.Request(
        "https://kubernetes.default.svc" + path,
        data=encoded,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            **({"Content-Type": "application/merge-patch+json"} if encoded is not None else {}),
        },
    )
    context = ssl.create_default_context(cafile=str(ROOT / "ca.crt"))
    try:
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            if expected_error is not None:
                raise RuntimeError("unexpected_success")
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        if expected_error is not None and error.code == expected_error:
            return error.code, None
        raise RuntimeError("api_error") from None


def api_path(resource, name):
    return f"/api/v1/namespaces/{NAMESPACE}/{resource}/{quote(name, safe='')}"


def job_path(name):
    return f"/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{quote(name, safe='')}"


def read_event(name):
    status, obj = request("GET", api_path("configmaps", name))
    if status != 200 or obj.get("metadata", {}).get("name") != name:
        raise RuntimeError("event_readback")
    data = obj.get("data", {})
    if data.get("event_id") != name or data.get("scope") != NAMESPACE:
        raise RuntimeError("event_identity")
    try:
        spend = int(data["spend_units"])
        alert = int(data["alert_units"])
        limit = int(data["hard_limit_units"])
    except (KeyError, ValueError):
        raise RuntimeError("event_fields") from None
    if not 0 <= spend <= 1000 or not 0 < alert < limit <= 1000:
        raise RuntimeError("event_bounds")
    return data, spend, alert, limit


def evaluate(name):
    data, spend, alert, limit = read_event(name)
    target = data.get("target_job", "")
    current = data.get("freshness") == "current"
    armed = data.get("actions_armed") == "true"
    if target != MANAGED_JOB or not current or spend < alert:
        decision = "hold"
    elif spend < limit or not armed:
        decision = "alert"
    else:
        request("PATCH", job_path(MANAGED_JOB), {"spec": {"suspend": True}})
        decision = "enforced"

    other_denied = "not-tested"
    if decision == "enforced":
        status, _ = request(
            "PATCH", job_path(OTHER_JOB) + "?dryRun=All",
            {"spec": {"suspend": True}}, expected_error=403,
        )
        other_denied = "true" if status == 403 else "false"

    marker_name = "marker-" + name
    marker = {
        "data": {
            "event_id": name,
            "decision": decision,
            "actor": f"system:serviceaccount:{NAMESPACE}:{ACTOR}",
            "target_job": target,
            "other_target_denied": other_denied,
        },
    }
    request("PATCH", api_path("configmaps", marker_name), marker)


def main():
    names = tuple(os.environ.get("EVENT_NAMES", "").split(","))
    if names not in {EVENTS[:-1], EVENTS[-1:]}:
        raise RuntimeError("event_plan")
    for name in names:
        evaluate(name)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never emit request headers, tokens, or API response bodies to container logs.
        print("budget_evaluator_failed", flush=True)
        raise SystemExit(1)
    print("budget_evaluator_complete", flush=True)
