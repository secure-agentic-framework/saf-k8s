"""Serve one public marker under a fixed intent header, a temporary session and verified mutual TLS."""

import json
import secrets
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


MARKER = "owned-public-marker"
CERT = "/fixture-pki/"
SESSION_TTL_SECONDS = 2


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
        self.server.fixture_session = secrets.token_hex(24)
        self.server.session_until = time.monotonic() + SESSION_TTL_SECONDS
        self.reply(201, {"fixture_session": self.server.fixture_session})

    def do_GET(self):
        if self.path == "/intent/marker":
            if self.headers.get("X-Fixture-Intent") != "public-marker":
                self.reply(400, {})
                return
        elif self.path == "/session/marker":
            presented = self.headers.get("X-Fixture-Session", "")
            if (time.monotonic() >= self.server.session_until
                    or not secrets.compare_digest(presented.encode(), self.server.fixture_session.encode())):
                self.reply(401, {})
                return
        else:
            self.reply(404, {})
            return
        self.reply(200, {"marker": MARKER})



class TLSMarker(MarkerHandler):
    def do_GET(self):
        if self.path != "/verified-client/marker":
            self.reply(404, {})
            return
        cert = self.connection.getpeercert()
        name = next(value for component in cert["subject"] for key, value in component if key == "commonName")
        self.reply(200, {"marker": MARKER, "verified_subject": name})


def verify_peer():
    with ThreadingHTTPServer(("127.0.0.1", 0), TLSMarker) as server:
        scope = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        scope.minimum_version = scope.maximum_version = ssl.TLSVersion.TLSv1_2
        scope.load_cert_chain(CERT + "server.crt", CERT + "server.key")
        scope.load_verify_locations(CERT + "ca.crt")
        scope.verify_mode = ssl.CERT_REQUIRED
        server.socket = scope.wrap_socket(server.socket, server_side=True)
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            url = f"https://127.0.0.1:{server.server_port}/verified-client/marker"

            def contact(credential=None):
                context = ssl.create_default_context(cafile=CERT + "ca.crt")
                if credential:
                    context.load_cert_chain(f"{CERT}{credential}.crt", f"{CERT}{credential}.key")
                client = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
                try:
                    with client.open(url, timeout=4) as response:
                        return "peer-verified", json.load(response)
                except URLError as error:
                    if isinstance(error.reason, ssl.SSLError):
                        return "tls-handshake-refused", None
                    raise
                except ssl.SSLError:
                    return "tls-handshake-refused", None

            anonymous, _ = contact()
            outsider, _ = contact("outsider")
            allowed, verified = contact("client")
            return {"anonymous_tls": anonymous, "untrusted_tls": outsider,
                    "trusted_tls": allowed, "trusted_result": verified}
        finally:
            server.shutdown()
            worker.join()


def main():
    with ThreadingHTTPServer(("127.0.0.1", 0), MarkerHandler) as server:
        server.fixture_session = ""
        server.session_until = 0
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
            time.sleep(SESSION_TTL_SECONDS + 0.2)
            expired, _ = request("/session/marker", headers={"X-Fixture-Session": issued["fixture_session"]})
            observations = {
                "missing_intent": missing_intent,
                "fixed_intent_accepted": accepted_intent == 200 and intent_body == {"marker": MARKER},
                "missing_session": missing_session,
                "incorrect_session": incorrect_session,
                "issued_session_accepted": issue_status == 201 and with_session == 200 and session_body == intent_body,
                "expired_session": expired,
            }
        finally:
            server.shutdown()
            worker.join()
    observations.update(verify_peer())
    print(json.dumps(observations))


if __name__ == "__main__":
    main()
