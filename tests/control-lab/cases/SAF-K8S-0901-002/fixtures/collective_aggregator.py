"""Reuse the published aggregator while adding a TokenReview-gated rank grant."""
import json
from http.server import HTTPServer

import aggregator


RANK_BY_WORKER = {"worker-a": 0, "worker-b": 1}


class CollectiveHandler(aggregator.Handler):
    def do_POST(self):
        if self.path != "/v1/enroll":
            return super().do_POST()

        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return self.reply(401, {"status": "rejected", "reason": "authentication"})
        try:
            actor = aggregator.review_token(authorization[7:])
        except Exception:
            return self.reply(503, {"status": "review-unavailable"})
        if actor not in RANK_BY_WORKER or actor not in aggregator.ASSIGNMENTS:
            return self.reply(403, {"status": "rejected", "reason": "not_enrolled"})

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 256:
                raise ValueError("bounded enrollment body required")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or set(body) != {"round_id"}:
                raise ValueError("exact round field required")
        except (ValueError, json.JSONDecodeError):
            return self.reply(400, {"status": "rejected", "reason": "schema"})

        if body["round_id"] != aggregator.ASSIGNMENTS[actor]:
            return self.reply(422, {"status": "rejected", "reason": "assignment"})

        assignment = {"worker_id": actor, "round_id": body["round_id"],
                      "rank": RANK_BY_WORKER[actor]}
        print(json.dumps({"outcome": "enrolled_for_collective", **assignment},
                         sort_keys=True, separators=(",", ":")), flush=True)
        return self.reply(200, {"status": "enrolled", **assignment})


HTTPServer(("0.0.0.0", 8080), CollectiveHandler).serve_forever()
