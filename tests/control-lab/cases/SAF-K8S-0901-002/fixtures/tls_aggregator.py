"""TLS-only wrapper around the existing bounded mock aggregation handler."""
import os
import sys
import ssl
from http.server import ThreadingHTTPServer

sys.path.insert(0, "/core")
import aggregator


class QuietTLSHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class, tls_context):
        self.tls_context = tls_context
        super().__init__(server_address, handler_class)

    def get_request(self):
        raw, address = super().get_request()
        raw.settimeout(5)
        wrapped = self.tls_context.wrap_socket(
            raw, server_side=True, do_handshake_on_connect=False)
        return wrapped, address

    def handle_error(self, _request, _client_address):
        # A rejected cleartext or bad-name handshake must not emit request data.
        return


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(os.environ["TLS_CERT_PATH"], os.environ["TLS_KEY_PATH"])
server = QuietTLSHTTPServer(("0.0.0.0", 8443), aggregator.Handler, context)
server.serve_forever()
