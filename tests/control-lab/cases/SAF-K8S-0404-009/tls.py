"""Serve and check only public fixture responses over actual TLS."""
from hashlib import sha256
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ssl
import sys

MARKER = b"owned-permitted-tls-response"


def load_identity(context, identity):
    location = f"/identity/{identity}"
    context.load_cert_chain(location + "/tls.crt", location + "/tls.key")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(MARKER)))
        self.end_headers()
        self.wfile.write(MARKER)

    def log_message(self, *_):
        pass


class Server(HTTPServer):
    def get_request(self):
        raw, addr = super().get_request()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        try:
            load_identity(context, self.identity)
            if self.mode == "mutual":
                context.load_verify_locations(cafile="/trust/checked.pem")
                context.verify_mode = ssl.CERT_REQUIRED
                context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
            return context.wrap_socket(raw, server_side=True), addr
        except (OSError, ssl.SSLError) as error:
            if isinstance(error, ssl.SSLCertVerificationError) and error.verify_code == 23:
                print("fixture peer certificate revoked", flush=True)
            raw.close()
            raise


def serve(identity, mode):
    server = Server(("0.0.0.0", 8443), Handler)
    server.identity, server.mode = identity, mode
    server.serve_forever()


def probe(host, identity, policy):
    strict = policy == "crl"
    context = ssl.create_default_context(cafile="/trust/checked.pem" if strict else "/trust/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if strict:
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    if identity != "none":
        load_identity(context, identity)
    client = HTTPSConnection(host, 8443, context=context, timeout=4)
    try:
        client.connect()
        secure = client.sock
        fingerprint = sha256(secure.getpeercert(binary_form=True)).hexdigest()
        protocol = secure.version()
        client.request("GET", "/fixture", headers={"Connection": "close"})
        response = client.getresponse()
        result = {"allowed": response.status == 200 and response.read() == MARKER,
                  "protocol": protocol, "leaf": fingerprint}
    except ssl.SSLCertVerificationError as error:
        result = {"allowed": False, "verify_code": error.verify_code}
    except (OSError, ssl.SSLError) as error:
        result = {"allowed": False, "alert": getattr(error, "reason", None)}
    finally:
        client.close()
    print(json.dumps(result))


if sys.argv[1] == "server":
    serve(*sys.argv[2:])
else:
    probe(*sys.argv[2:])
