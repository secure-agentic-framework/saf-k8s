"""An exact binary randomized-response mechanism for an owned fixture."""
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import sys

REGISTRY = {"mechanism": "fixture-binary-rr-v1", "unit": "one-owned-bit",
            "neighbor": "replace-one-bit", "epsilonRatioBound": "3", "delta": "0",
            "truthfulOutcomes": "3", "totalOutcomes": "4",
            "review": "fixture-privacy-review-001"}


def policy(root=Path("/policy")):
    actual = {name: (root/name).read_text() for name in REGISTRY}
    if actual != REGISTRY:
        raise ValueError("The deployed parameter record does not resolve to the approved mechanism")
    return actual


def apply(bit, draw, reviewed):
    truthful = int(reviewed["truthfulOutcomes"])
    return bit if draw < truthful else 1-bit


def sample(bit, reviewed):
    return apply(bit, secrets.randbelow(int(reviewed["totalOutcomes"])), reviewed)


def review(reviewed):
    count = int(reviewed["totalOutcomes"])
    rows = [Counter(apply(bit, draw, reviewed) for draw in range(count)) for bit in (0, 1)]
    return {"counts": [{str(bit): row[bit] for bit in (0, 1)} for row in rows],
            "common_support": all(set(row) == {0, 1} for row in rows),
            "approved_likelihood_bound": all(
                row[bit] <= int(reviewed["epsilonRatioBound"]) * rows[1-index][bit]
                for index, row in enumerate(rows) for bit in (0, 1)),
            "bound_is_tight_on_an_event": any(
                row[bit] == int(reviewed["epsilonRatioBound"]) * rows[1-index][bit]
                for index, row in enumerate(rows) for bit in (0, 1))}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/release":
            self.send_error(404)
            return
        body = json.dumps({"result": sample(1, self.server.reviewed)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    approved = policy()
    if sys.argv[1] == "review":
        print(json.dumps(review(approved), sort_keys=True))
    elif sys.argv[1] == "serve":
        server = HTTPServer(("127.0.0.1", 8080), Handler)
        server.reviewed = approved
        server.serve_forever()
    else:
        raise ValueError("Unknown fixture operation")


if __name__ == "__main__":
    main()
