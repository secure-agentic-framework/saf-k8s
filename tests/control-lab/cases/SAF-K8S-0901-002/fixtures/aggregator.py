#!/usr/bin/env python3
"""Case-owned, in-memory mock aggregation endpoint. Synthetic data only."""
import json
import math
import os
from pathlib import Path
import ssl
from urllib.error import URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = os.environ.get("ENFORCEMENT_MODE", "enforce")
ASSIGNMENTS = {"worker-a": "round-7", "worker-b": "round-7"}
EXPECTED_KEYS = {"request_id", "worker_id", "round_id", "schema_version", "vector"}
VECTOR_SIZE = 3
VECTOR_LIMIT = 0.05
events = []
accepted = []
accepted_requests = 0
received_requests = 0
rejected = {"schema": 0, "assignment": 0}
screen_quarantined = 0
screen_alerted = 0
screen_denied = 0


def valid_schema(body):
    vector = body.get("vector")
    return (
        set(body) == EXPECTED_KEYS
        and body.get("schema_version") == "v1"
        and isinstance(body.get("request_id"), str)
        and isinstance(body.get("worker_id"), str)
        and isinstance(body.get("round_id"), str)
        and isinstance(vector, list)
        and len(vector) == VECTOR_SIZE
        and all(isinstance(x, (int, float)) and not isinstance(x, bool)
                and math.isfinite(x) and abs(x) <= VECTOR_LIMIT for x in vector)
    )


def assignment_matches(body):
    return ASSIGNMENTS.get(body.get("worker_id")) == body.get("round_id")


def mock_result():
    if not accepted:
        return {"accepted_count": 0, "mean": []}
    mean = [round(sum(row["vector"][i] for row in accepted) / len(accepted), 6)
            for i in range(VECTOR_SIZE)]
    return {"accepted_count": len(accepted), "mean": mean}


REVIEW_API = "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews"
AUDIENCE = "saf-fixture-0901-002"
ACCOUNT_PREFIX = "system:serviceaccount:saf-0901-002:"
API_ACCOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
REVIEW_CLIENT = build_opener(ProxyHandler({}), HTTPSHandler(
    context=ssl.create_default_context(cafile=str(API_ACCOUNT / "ca.crt"))
))


def review_token(token):
    fixture = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
               "spec": {"token": token, "audiences": [AUDIENCE]}}
    caller = (API_ACCOUNT / "token").read_text()
    request = Request(REVIEW_API, data=json.dumps(fixture).encode(), method="POST",
                      headers={"Authorization": "Bearer " + caller,
                               "Content-Type": "application/json"})
    with REVIEW_CLIENT.open(request, timeout=4) as response:
        status = json.loads(response.read(16384))["status"]
    actor = status.get("user", {}).get("username", "")
    if status.get("authenticated") and AUDIENCE in status.get("audiences", []) and actor.startswith(ACCOUNT_PREFIX):
        return actor[len(ACCOUNT_PREFIX):]
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        # Never emit HTTP request lines, headers, or environment details.
        return

    def reply(self, status, body):
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/healthz":
            return self.reply(200, {"ok": True, "fixture": "0901-002"})
        if self.path == "/v1/status":
            status = {"received_count": received_requests,
                      "accepted_count": accepted_requests,
                      "rejected_count": sum(rejected.values()),
                      "rejected_by_reason": rejected.copy()}
            if MODE == "screen":
                status.update(rejected_count=status["rejected_count"] + screen_denied,
                              rejected_by_reason={**rejected, "anomaly": screen_denied},
                              quarantined_count=screen_quarantined,
                              alerted_count=screen_alerted)
            return self.reply(200, status)
        if self.path == "/v1/mock-result":
            return self.reply(200, mock_result())
        return self.reply(404, {"error": "not_found"})

    def do_POST(self):
        global accepted_requests, received_requests, screen_quarantined, screen_alerted, screen_denied
        if self.path != "/v1/contribute":
            return self.reply(404, {"error": "not_found"})
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return self.reply(401, {"status": "rejected", "reason": "authentication"})
        try:
            actor = review_token(authorization[7:])
        except (URLError, OSError, ValueError, KeyError):
            return self.reply(503, {"status": "review-unavailable"})
        if actor is None:
            return self.reply(401, {"status": "rejected", "reason": "authentication"})
        if actor not in ASSIGNMENTS:
            print(json.dumps({"authenticated_identity": actor, "outcome": "not_enrolled"}), flush=True)
            return self.reply(403, {"status": "rejected", "reason": "not_enrolled"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 2048:
                raise ValueError("bounded_body_required")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("object_required")
        except (ValueError, json.JSONDecodeError):
            return self.reply(400, {"status": "rejected", "reason": "schema"})

        received_requests += 1

        reason = None
        if MODE in ("enforce", "screen", "screen-off"):
            if not valid_schema(body):
                reason = "schema"
            elif body["worker_id"] != actor or not assignment_matches(body):
                reason = "assignment"
        if reason:
            rejected[reason] += 1
            outcome = {"status": "rejected", "reason": reason}
            code = 422
        elif MODE == "screen":
            # A bounded deterministic fixture policy, separate from the normal
            # schema/assignment gate. It makes no learned-model claim.
            baseline = (0.01, -0.01, 0.0)
            score = round(max(abs(value - center)
                              for value, center in zip(body["vector"], baseline)), 8)
            if score >= 0.03:
                screen_denied += 1
                outcome = {"status": "rejected", "reason": "anomaly_threshold",
                           "score": score}
                code = 422
            elif score > 0.015:
                screen_quarantined += 1
                screen_alerted += 1
                outcome = {"status": "quarantined", "reason": "anomaly_alert",
                           "score": score}
                code = 202
            else:
                accepted_requests += 1
                accepted.append({"vector": body["vector"]})
                outcome = {"status": "accepted", "score": score}
                code = 200
        else:
            accepted_requests += 1
            outcome = {"status": "accepted"}
            code = 200
            # The permissive baseline demonstrates the effect of missing checks:
            # a safely bounded vector from the wrong assigned round enters its
            # mock result. Malformed vector shapes never enter vector arithmetic.
            vector = body.get("vector")
            safe_vector = (isinstance(vector, list) and len(vector) == VECTOR_SIZE
                           and all(isinstance(x, (int, float)) and not isinstance(x, bool)
                                   and math.isfinite(x) and abs(x) <= VECTOR_LIMIT
                                   for x in vector))
            if safe_vector and (MODE != "enforce" or assignment_matches(body)):
                accepted.append({"vector": body["vector"]})
        event = {"mode": MODE, "request": body, "outcome": outcome, "authenticated_identity": actor}
        events.append(event)
        print(json.dumps(event, sort_keys=True, separators=(",", ":")), flush=True)
        return self.reply(code, outcome)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
