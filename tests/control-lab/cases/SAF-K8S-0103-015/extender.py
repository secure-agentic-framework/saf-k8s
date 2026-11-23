"""Authorize a single meaningful fixture extender route using its TLS peer."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ssl

CLIENT = "fixture-scheduler-peer"


class Extender(BaseHTTPRequestHandler):
    def do_POST(self):
        cert = self.connection.getpeercert()
        common_names = [value for item in cert["subject"] for name, value in item if name == "commonName"]
        if self.path != "/filter" or common_names != [CLIENT]:
            self.send_error(403)
            return
        size = int(self.headers["Content-Length"])
        if not 0 < size < 500_000:
            self.send_error(400)
            return
        request = json.loads(self.rfile.read(size))
        pod = request["Pod"]["metadata"]
        if pod.get("namespace") != "saf-test" or pod.get("name") != "fixture-approved-pod":
            self.send_error(403)
            return
        payload = json.dumps({"Nodes": request["Nodes"]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        print(json.dumps({"peer": CLIENT, "pod": pod["name"], "path": self.path, "allowed": True}), flush=True)

    def log_message(self, _format, *_args):
        pass


server = HTTPServer(("0.0.0.0", 9443), Extender)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tls/server.crt", "/tls/server.key")
context.load_verify_locations("/tls/ca.crt")
context.verify_mode = ssl.CERT_REQUIRED
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
