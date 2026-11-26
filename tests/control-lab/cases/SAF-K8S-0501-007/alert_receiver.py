from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib, json, ssl

receipts = {}
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, status, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True
    def do_POST(self):
        if self.path != "/event":
            return self._send(404, {"accepted": False})
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            event = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return self._send(400, {"accepted": False})
        fields = {"event_id", "rule_id", "source", "destination", "protocol", "verdict", "reason", "hubble_flow_uuid"}
        if set(event) != fields or event.get("rule_id") != "notebook-to-inference-policy-deny" or event.get("verdict") != "DROPPED":
            return self._send(400, {"accepted": False})
        digest = hashlib.sha256(raw).hexdigest()
        receipts[event["event_id"]] = {"sha256": digest, "count": receipts.get(event["event_id"], {}).get("count", 0) + 1}
        return self._send(202, {"accepted": True, "event_id": event["event_id"]})
    def do_GET(self):
        if self.path != "/receipt":
            return self._send(404, {"accepted": False})
        return self._send(200, {"receipts": receipts})
    def log_message(self, *_):
        pass

server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
