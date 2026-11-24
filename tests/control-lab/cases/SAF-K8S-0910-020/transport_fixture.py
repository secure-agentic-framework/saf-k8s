"""Run ordinary test requests against the two fixture transports."""
from http.client import HTTPConnection, HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import sys
import threading

MARKER = b"approved-cross-cluster-reply"
NAME = "fixture-transport.saf.test"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(MARKER)))
        self.end_headers()
        self.wfile.write(MARKER)

    def log_message(self, *_args):
        return


def serve():
    plain = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    tls = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/pki/tls.crt", "/pki/tls.key")
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    tls.serve_forever()


def check(host, port, profile):
    if profile == "plaintext":
        connection = HTTPConnection(host, port, timeout=2)
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            return {"status": response.status, "marker": response.read() == MARKER}
        except (OSError, EOFError, ConnectionError):
            return {"status": "transport-refused"}
        finally:
            connection.close()
    bundle = "ca.crt" if profile == "trusted" else "wrong.crt"
    context = ssl.create_default_context(cafile=str(Path("/trust") / bundle))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        with socket.create_connection((host, port), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname=NAME) as secured:
                secured.sendall(b"GET / HTTP/1.1\r\nHost: fixture-transport.saf.test\r\nConnection: close\r\n\r\n")
                response = HTTPResponse(secured)
                response.begin()
                return {"status": response.status, "marker": response.read() == MARKER,
                        "protocol": secured.version(), "cipher": secured.cipher()[0]}
    except ssl.SSLCertVerificationError:
        return {"status": "certificate-refused"}
    except (OSError, EOFError, ConnectionError):
        return {"status": "transport-refused"}


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        print(json.dumps(check(sys.argv[1], int(sys.argv[2]), sys.argv[3]), sort_keys=True))
