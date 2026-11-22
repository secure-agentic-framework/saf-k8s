"""Serve the case's two TLS endpoints and receive scoped Alertmanager payloads."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
from threading import Lock, Thread

received = []
lock = Lock()


class Handler(BaseHTTPRequestHandler):
    def send_json(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self.send_json({"ready": True})
        elif self.path == "/received" and self.server.server_port == 8080:
            with lock:
                self.send_json(list(received))
        else:
            self.send_error(404)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", 0))
        if self.path != "/notify" or self.server.server_port != 8080 or not 0 < size <= 32768:
            self.send_error(400)
            return
        try:
            payload = json.loads(self.rfile.read(size))
            if payload.get("version") != "4" or not isinstance(payload.get("alerts"), list):
                raise ValueError("invalid webhook envelope")
        except (ValueError, AttributeError):
            self.send_error(400)
            return
        with lock:
            received.append(payload)
        self.send_json({"accepted": True})

    def log_message(self, *args):
        pass


for name, port in (("near-expiry", 8443), ("healthy", 9443)):
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(f"/tls/{name}.crt", f"/tls/{name}.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    Thread(target=server.serve_forever, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
