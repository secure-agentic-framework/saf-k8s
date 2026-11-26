"""Serve public fixture data with the certificate currently mounted by Kubernetes."""
from hashlib import sha256
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl
import sys
import time


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = b"owned-renewal-continuity-marker"
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


class Listener(HTTPServer):
    def get_request(self):
        raw, address = super().get_request()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain("/certificate/tls.crt", "/certificate/tls.key")
            return context.wrap_socket(raw, server_side=True), address
        except (ssl.SSLError, OSError):
            raw.close()
            raise


def serve():
    while not Path("/certificate/tls.crt").exists():
        time.sleep(.5)
    Listener(("0.0.0.0", 8443), Handler).serve_forever()


def request(host):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    client = HTTPSConnection(host, 8443, context=context, timeout=5)
    try:
        client.connect()
        leaf = sha256(client.sock.getpeercert(binary_form=True)).hexdigest()
        client.request("GET", "/fixture")
        response = client.getresponse()
        print(json.dumps({"fingerprint": leaf, "healthy": response.status == 200
                          and response.read() == b"owned-renewal-continuity-marker"}))
    except (OSError, ssl.SSLError):
        print(json.dumps({"healthy": False}))
    finally:
        client.close()


if sys.argv[1] == "server":
    serve()
else:
    request(sys.argv[2])
