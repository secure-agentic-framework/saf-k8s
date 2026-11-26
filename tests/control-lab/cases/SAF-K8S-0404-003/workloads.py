"""HTTPS fixtures exchange only public data and report transport and policy separately."""
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ssl
import sys


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        certificate = self.connection.getpeercert()
        names = [value for kind, value in (certificate or {}).get("subjectAltName", ()) if kind == "URI"]
        common_names = [value for rdn in (certificate or {}).get("subject", ())
                        for key, value in rdn if key == "commonName"]
        allowed = self.server.mode == "server-only" or names == ["spiffe://fixture.invalid/training"]
        status = 200 if allowed else 403
        payload = json.dumps({"fixture_operation": allowed, "certificate_identity": names,
                              "peer_certificate_cn": common_names[0] if len(common_names) == 1 else None}).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


class TLSListener(HTTPServer):
    def get_request(self):
        raw, address = super().get_request()
        try:
            return self.context.wrap_socket(raw, server_side=True), address
        except ssl.SSLError as error:
            if error.reason == "PEER_DID_NOT_RETURN_A_CERTIFICATE":
                print("fixture server denied missing peer certificate", flush=True)
            if isinstance(error, ssl.SSLCertVerificationError) and error.verify_code in (20, 21):
                print("fixture server denied unknown peer issuer", flush=True)
            raw.close()
            raise


def serve(mode):
    listener = TLSListener(("0.0.0.0", 8443), Handler)
    listener.mode = mode
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/identity/tls.crt", "/identity/tls.key")
    if mode == "mutual":
        context.load_verify_locations(cafile="/trust/ca.crt")
        context.verify_mode = ssl.CERT_REQUIRED
    listener.context = context
    listener.serve_forever()


def request(host, credential):
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if credential != "none":
        root = "/client/" + credential
        context.load_cert_chain(root + "/tls.crt", root + "/tls.key")
    client = HTTPSConnection(host, 8443, context=context, timeout=7)
    try:
        client.connect()
        protocol = client.sock.version()
        client.request("GET", "/model-ready", headers={"Connection": "close"})
        response = client.getresponse()
        data = json.loads(response.read())
        value = {"tls": protocol, "http": response.status,
                 "identity": data["certificate_identity"], "operation": data["fixture_operation"],
                 "peer_certificate_cn": data["peer_certificate_cn"]}
    except ssl.SSLCertVerificationError as error:
        value = {"error": "server-certificate-verification", "verify_code": error.verify_code}
    except ssl.SSLError as error:
        reason = error.reason or ""
        value = {"error": "client-certificate-rejected" if "ALERT" in reason else "tls-failed",
                 "authority": "missing-certificate" if "CERTIFICATE_REQUIRED" in reason
                 else "untrusted-certificate" if "UNKNOWN_CA" in reason else "other"}
    except (OSError, TimeoutError):
        value = {"error": "transport-unavailable"}
    finally:
        client.close()
    print(json.dumps(value))


if sys.argv[1] == "server":
    serve(sys.argv[2])
else:
    request(*sys.argv[2:])
