"""Compare a bounded local output policy against the exact native CPU backend."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = "saf-llama-real"
CLIENT = "saf-llama-client"

PROGRAM = r'''import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from threading import Thread
import sys

BACKEND = sys.argv[1]
PATH = "/completion"
LIMIT = 4
PROMPT = "Once upon a time"
COUNTERS = {"dispatched": 0, "rejected": 0}


def send(host, port, path, document=None):
    connection = http.client.HTTPConnection(host, port, timeout=12)
    try:
        body = None if document is None else json.dumps(document).encode("utf-8")
        headers = {} if body is None else {"Content-Type": "application/json"}
        connection.request("GET" if body is None else "POST", path, body, headers)
        response = connection.getresponse()
        data = response.read(32769)
        if len(data) > 32768:
            raise RuntimeError("owned fixture response exceeded the byte bound")
        return response.status, json.loads(data)
    finally:
        connection.close()


def completion_body(count):
    return {"prompt": PROMPT, "n_predict": count, "temperature": 0.0,
            "seed": 42, "ignore_eos": True, "return_tokens": True, "cache_prompt": False}


def project(reply):
    status, value = reply
    return {"status": status, "predicted": value.get("tokens_predicted"),
            "token_ids": len(value.get("tokens", [])), "stop": value.get("stop_type")}


class Guard(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, value):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/fixture-counts":
            self.reply(200, COUNTERS)
        else:
            self.reply(404, {"reason": "scope"})

    def do_POST(self):
        if self.path != PATH:
            self.reply(404, {"reason": "scope"})
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 1024:
            self.reply(413, {"reason": "size"})
            return
        request = json.loads(self.rfile.read(size))
        requested = request.get("n_predict")
        if type(requested) is not int or not 1 <= requested <= LIMIT:
            COUNTERS["rejected"] += 1
            self.reply(422, {"reason": "output-budget"})
            return
        if request != completion_body(requested):
            self.reply(422, {"reason": "fixture-request"})
            return
        COUNTERS["dispatched"] += 1
        try:
            observed = project(send(BACKEND, 8080, PATH, request))
        except (OSError, ValueError):
            self.reply(502, {"reason": "backend"})
            return
        self.reply(observed["status"], observed)


over = completion_body(5)
direct = project(send(BACKEND, 8080, PATH, over))
with HTTPServer(("127.0.0.1", 0), Guard) as server:
    worker = Thread(target=server.serve_forever)
    worker.start()
    try:
        port = server.server_address[1]
        denied = send("127.0.0.1", port, PATH, over)
        after_denial = send("127.0.0.1", port, "/fixture-counts")
        allowed = send("127.0.0.1", port, PATH, completion_body(LIMIT))
        final = send("127.0.0.1", port, "/fixture-counts")
    finally:
        server.shutdown()
        worker.join()
print(json.dumps({"direct": direct, "denied": denied, "after_denial": after_denial,
                  "allowed": allowed, "final": final, "budget": LIMIT,
                  "over_limit_request": 5}))
'''


def _server(lab):
    pod = json.loads(lab.kubectl("get", "pod", SERVER, "-o", "json").stdout)
    containers = pod.get("status", {}).get("containerStatuses", [])
    native = next((entry for entry in containers if entry.get("name") == "llama-server"), {})
    return {
        "uid": pod.get("metadata", {}).get("uid"),
        "ip": pod.get("status", {}).get("podIP"),
        "container": native.get("containerID"),
        "image": native.get("imageID"),
        "ready": native.get("ready") is True,
    }


def run(lab):
    before = _server(lab)
    if not before["ready"] or not all(before[k] for k in ("uid", "ip", "container", "image")):
        lab.block("The native output budget comparison needs the exact Ready server identity")
    result = lab.kubectl("exec", "pod/" + CLIENT, "-c", "client", "--",
                         "python", "-B", "-c", PROGRAM, before["ip"],
                         timeout=65, allow_failure=True)
    try:
        row = json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("The native output budget client returned no bounded JSON receipt")
    same_server = _server(lab) == before
    expected_direct = {"status": 200, "predicted": 5, "token_ids": 5, "stop": "limit"}
    expected_allowed = {"status": 200, "predicted": 4, "token_ids": 4, "stop": "limit"}
    direct_matches = row.get("direct") == expected_direct
    denial_matches = row.get("denied") == [422, {"reason": "output-budget"}]
    denial_dispatch = row.get("after_denial") == [200, {"dispatched": 0, "rejected": 1}]
    allowed_matches = row.get("allowed") == [200, expected_allowed]
    final_dispatch = row.get("final") == [200, {"dispatched": 1, "rejected": 1}]
    (lab.evidence / "native-output-budget.raw.json").write_text(
        json.dumps({"backend_identity": before, "same_backend_after": same_server,
                    "observation": row}, indent=2) + "\n")
    lab.check("green", "A four-token guard refuses the identical five-token request before dispatch and allows exact-boundary native generation",
              result.returncode == 0 and same_server and direct_matches and denial_matches
              and denial_dispatch and allowed_matches and final_dispatch,
              {"unprotected_native_generation_observed_five": direct_matches,
               "guard_refused_exact_over_budget_request": denial_matches,
               "no_guard_dispatch_before_rejection_readback": denial_dispatch,
               "guarded_native_generation_observed_four": allowed_matches,
               "one_guard_dispatch_in_final_readback": final_dispatch,
               "native_pod_container_and_image_unchanged": same_server})
