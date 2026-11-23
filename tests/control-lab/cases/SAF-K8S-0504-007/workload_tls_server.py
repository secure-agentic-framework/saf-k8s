#!/usr/bin/env python3
"""Minimal mutual-TLS HTTP fixture for the SAF-K8S-0504-007 case."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import sys


class WorkloadHandler(BaseHTTPRequestHandler):
    expected_client_uri = ""

    def do_GET(self):
        # The TLS layer has already required and verified a client certificate.
        peer = self.connection.getpeercert()
        uris = [value for kind, value in peer.get("subjectAltName", ()) if kind == "URI"]
        status = 200 if uris == [self.expected_client_uri] else 403
        print(json.dumps({"type": "authorized_request", "peer_uri": uris, "status": status}), flush=True)
        body = b"ok\n" if status == 200 else b"forbidden\n"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Keep request logs free of identity and credential material.
        return


class VerifiedServer(ThreadingHTTPServer):
    def __init__(self, address, context):
        self.context = context
        super().__init__(address, WorkloadHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(8)
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except ssl.SSLCertVerificationError as error:
            print(json.dumps({"type": "client_certificate_rejected",
                              "verify_code": error.verify_code}), flush=True)
            connection.close()
            raise
        except OSError:
            connection.close()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True, help="workload X.509 certificate path")
    parser.add_argument("--key", required=True, help="workload private key path")
    parser.add_argument("--bundle", required=True, help="trusted client CA bundle path")
    parser.add_argument("--approved-uri", required=True, help="exact client SPIFFE URI SAN allowed HTTP 200")
    parser.add_argument("--bind", default="0.0.0.0", help="owned service bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8443, help="owned service port (default: 8443)")
    parser.add_argument("--ready-file", type=Path, required=True)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    if not Path(args.bundle).is_file():
        print(json.dumps({"type": "foreign_bundle_not_available"}), flush=True)
        return 12
    context.load_verify_locations(cafile=args.bundle)
    context.verify_mode = ssl.CERT_REQUIRED

    WorkloadHandler.expected_client_uri = args.approved_uri
    server = VerifiedServer((args.bind, args.port), context)
    args.ready_file.touch()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
