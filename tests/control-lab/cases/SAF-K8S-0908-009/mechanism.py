"""An exact binary randomized-response mechanism for an owned fixture."""
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

REGISTRY = {"mechanism": "fixture-binary-rr-v1", "unit": "one-owned-bit",
            "neighbor": "replace-one-bit", "epsilonRatioBound": "3", "delta": "0",
            "truthfulOutcomes": "3", "totalOutcomes": "4",
            "review": "fixture-privacy-review-001"}
OUTPUT_NAME = "fixture-privacy-collected-result"
COLLECTOR_URL = "http://fixture-privacy-collector.saf-test.svc/collect"
SA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount")


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


def persist_noisy_result(result):
    token = (SA_PATH/"token").read_text().strip()
    trust = ssl.create_default_context(cafile=str(SA_PATH/"ca.crt"))
    api_host = os.environ["KUBERNETES_SERVICE_HOST"]
    api_port = os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
    target = (f"https://{api_host}:{api_port}/api/v1/namespaces/saf-test/"
              f"configmaps/{OUTPUT_NAME}")
    request = Request(target, data=json.dumps({"data": {"result": str(result)}}).encode(),
                      headers={"Authorization": "Bearer " + token,
                               "Content-Type": "application/merge-patch+json"},
                      method="PATCH")
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=trust))
    with client.open(request, timeout=8) as response:
        if response.status != 200:
            raise ValueError("The collector could not persist the owned result")


def input_read_status():
    token = (SA_PATH/"token").read_text().strip()
    trust = ssl.create_default_context(cafile=str(SA_PATH/"ca.crt"))
    api_host = os.environ["KUBERNETES_SERVICE_HOST"]
    api_port = os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
    target = (f"https://{api_host}:{api_port}/api/v1/namespaces/saf-test/"
              "configmaps/fixture-privacy-client-input")
    request = Request(target, headers={"Authorization": "Bearer " + token}, method="GET")
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=trust))
    try:
        with client.open(request, timeout=8) as response:
            return response.status
    except HTTPError as error:
        return error.code


class CollectorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.response(200 if self.path == "/health" else 404, "ready")

    def response(self, status, decision):
        body = json.dumps({"decision": decision}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/collect":
            self.response(404, "rejected")
            return
        if self.headers.get_content_type() != "application/json":
            self.response(400, "rejected")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 64:
                self.response(400, "rejected")
                return
            document = json.loads(self.rfile.read(length), object_pairs_hook=unique_object)
        except (ValueError, json.JSONDecodeError):
            self.response(400, "rejected")
            return
        if (not isinstance(document, dict) or set(document) != {"result"}
                or type(document["result"]) is not int or document["result"] not in (0, 1)):
            self.response(400, "rejected")
            return
        try:
            persist_noisy_result(document["result"])
        except Exception:
            self.response(503, "unavailable")
            return
        self.response(200, "accepted")

    def log_message(self, *_):
        pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def client_send(approved):
    text = (Path("/input/bit").read_text()).strip()
    if text not in {"0", "1"}:
        raise ValueError("The owned client input is outside the fixed one-bit fixture")
    output = sample(int(text), approved)
    body = json.dumps({"result": output}, separators=(",", ":")).encode()
    request = Request(COLLECTOR_URL, data=body,
                      headers={"Content-Type": "application/json"}, method="POST")
    client = build_opener(ProxyHandler({}))
    with client.open(request, timeout=8) as response:
        ack = json.load(response)
        print(json.dumps({"status": response.status, "decision": ack.get("decision"),
                          "sent_result": output}, sort_keys=True))


def wrong_schema_probe():
    # Fixed inert schema comparison. No sensitive or user-supplied fields are involved.
    body = json.dumps({"input": 0, "result": 1}, separators=(",", ":")).encode()
    request = Request(COLLECTOR_URL, data=body,
                      headers={"Content-Type": "application/json"}, method="POST")
    client = build_opener(ProxyHandler({}))
    try:
        with client.open(request, timeout=8) as response:
            status = response.status
            decision = json.load(response).get("decision")
    except HTTPError as error:
        status = error.code
        try:
            decision = json.load(error).get("decision")
        except (ValueError, json.JSONDecodeError):
            decision = None
    print(json.dumps({"status": status, "decision": decision}, sort_keys=True))


def collector_ready():
    client = build_opener(ProxyHandler({}))
    try:
        with client.open(COLLECTOR_URL.rsplit("/", 1)[0] + "/health", timeout=3) as response:
            return response.status == 200
    except (OSError, ValueError):
        return False


def main():
    approved = policy()
    if sys.argv[1] == "review":
        print(json.dumps(review(approved), sort_keys=True))
    elif sys.argv[1] == "serve":
        server = HTTPServer(("127.0.0.1", 8080), Handler)
        server.reviewed = approved
        server.serve_forever()
    elif sys.argv[1] == "serve-collector":
        HTTPServer(("0.0.0.0", 8080), CollectorHandler).serve_forever()
    elif sys.argv[1] == "client-send":
        client_send(approved)
    elif sys.argv[1] == "wrong-schema-probe":
        wrong_schema_probe()
    elif sys.argv[1] == "collector-input-probe":
        print(json.dumps({"status": input_read_status()}, sort_keys=True))
    else:
        raise ValueError("Unknown fixture operation")


if __name__ == "__main__":
    if sys.argv[1:] == ["collector-ready"]:
        print("ready" if collector_ready() else "pending")
    else:
        main()
