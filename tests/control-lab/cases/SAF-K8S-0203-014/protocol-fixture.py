"""Serve one public marker using two explicitly different access contracts."""

import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


class MarkerHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code, body):
        encoded = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        if self.path != "/fixture-session":
            self.reply(404, {})
            return
        self.reply(201, {"fixture_session": self.server.fixture_session})

    def do_GET(self):
        if self.path == "/intent/marker":
            if self.headers.get("X-Fixture-Intent") != "public-marker":
                self.reply(400, {})
                return
        elif self.path == "/session/marker":
            presented = self.headers.get("X-Fixture-Session", "")
            if not secrets.compare_digest(presented.encode(), self.server.fixture_session.encode()):
                self.reply(401, {})
                return
        else:
            self.reply(404, {})
            return
        self.reply(200, {"marker": "owned-public-marker"})


def main():
    with ThreadingHTTPServer(("127.0.0.1", 0), MarkerHandler) as server:
        server.fixture_session = secrets.token_hex(24)
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            prefix = f"http://127.0.0.1:{server.server_port}"
            client = build_opener(ProxyHandler({}))

            def request(path, method="GET", headers=None):
                target = Request(prefix + path, method=method, headers=headers or {})
                try:
                    response = client.open(target, timeout=4)
                except HTTPError as error:
                    response = error
                with response:
                    return response.code, json.load(response)

            intent = {"X-Fixture-Intent": "public-marker"}
            missing_intent, _ = request("/intent/marker")
            accepted_intent, intent_body = request("/intent/marker", headers=intent)
            missing_session, _ = request("/session/marker", headers=intent)
            incorrect_session, _ = request("/session/marker", headers={"X-Fixture-Session": "unknown-fixture-value"})
            issue_status, issued = request("/fixture-session", method="POST")
            with_session, session_body = request("/session/marker", headers={"X-Fixture-Session": issued["fixture_session"]})
            print(json.dumps({
                "missing_intent": missing_intent,
                "fixed_intent_accepted": accepted_intent == 200 and intent_body == {"marker": "owned-public-marker"},
                "missing_session": missing_session,
                "incorrect_session": incorrect_session,
                "issued_session_accepted": issue_status == 201 and with_session == 200 and session_body == intent_body,
            }))
        finally:
            server.shutdown()
            worker.join()


if __name__ == "__main__":
    main()
