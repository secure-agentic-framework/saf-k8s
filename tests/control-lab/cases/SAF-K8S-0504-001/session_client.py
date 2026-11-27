"""Case-owned localhost trigger around one persistent ordinary HTTP connection."""
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Lock
from urllib.parse import parse_qs, urlsplit
import json


TARGET = "saf-identity-target"
ALLOWED = {("/allow", "session-before-policy"),
           ("/allow", "session-after-policy"),
           ("/other", "session-denied-after-policy"),
           ("/allow", "session-allowed-after-denial"),
           ("/allow", "session-reconnected")}
backend = HTTPConnection(TARGET, 8080, timeout=6)
lock = Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/healthz" and not parsed.query:
            payload = b"ready\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            return
        query = parse_qs(parsed.query)
        path_values = query.get("path", [])
        marker_values = query.get("marker", [])
        if parsed.path != "/request" or len(path_values) != 1 or len(marker_values) != 1:
            self.send_error(400)
            return
        path, marker = path_values[0], marker_values[0]
        if (path, marker) not in ALLOWED:
            self.send_error(404)
            return

        with lock:
            previous_socket = backend.sock
            previous_fd = previous_socket.fileno() if previous_socket is not None else None
            previous_local = previous_socket.getsockname() if previous_socket is not None else None
            request_used_prior_socket = previous_socket is not None
            backend.request("GET", path, headers={"X-SAF-CASE": marker})
            response = backend.getresponse()
            body = response.read(1024).decode().strip()
            current_socket = backend.sock
            current_fd = current_socket.fileno() if current_socket is not None else None
            current_local = current_socket.getsockname() if current_socket is not None else None
            reused = (previous_socket is current_socket and previous_fd is not None
                      and previous_fd == current_fd
                      and previous_local == current_local)
            observed = {"status": response.status, "body": body,
                        "local_port": current_local[1] if current_local else None,
                        "same_socket_as_prior_request": reused,
                        "request_used_prior_app_socket": request_used_prior_socket,
                        "request_local_port": previous_local[1] if previous_local else None,
                        "socket_open_after_response": current_socket is not None}

        payload = json.dumps(observed, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        # Do not log query parameters; every accepted value is fixed case metadata.
        return


HTTPServer(("127.0.0.1", 19091), Handler).serve_forever()
