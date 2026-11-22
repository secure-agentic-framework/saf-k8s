"""Small local-only TLS fixture; accepts no command-supplied network destination."""

import json
import os
import socket
import socketserver
import ssl
import sys


SERVER_ID = "spiffe://saf.example.test/worker/server"
CLIENT_ID = "spiffe://saf.example.test/worker/client-a"
SERVER_DNS = "saf-peer.saf-0901-009.test"
PORTS = {"server-auth-only": 8443, "mutual-tls": 8444}


def emit(record):
    print(json.dumps(record, sort_keys=True), flush=True)


def peer_uri(connection):
    certificate = connection.getpeercert() or {}
    return next((value for kind, value in certificate.get("subjectAltName", [])
                 if kind == "URI"), None)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            request = self.rfile.readline(4096).decode("ascii", errors="strict").strip()
            headers = {}
            while True:
                line = self.rfile.readline(4096)
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("ascii", errors="strict").partition(":")
                headers[name.lower().strip()] = value.strip()
            length = min(int(headers.get("content-length", "0")), 256)
            marker = self.rfile.read(length).decode("ascii", errors="strict")
            mode = self.server.listener
            client_identity = peer_uri(self.connection)
            accepted = (
                request == "POST /exchange HTTP/1.1"
                and marker == os.environ["MARKER"]
                and (mode == "server-auth-only" or client_identity == CLIENT_ID)
            )
            record = {
                "event": "accepted" if accepted else "rejected",
                "listener": mode,
                "client_uri": client_identity,
                "server_uri": SERVER_ID,
                "marker": marker if accepted else None,
            }
            emit(record)
            status = "200 OK" if accepted else "403 Forbidden"
            response = {
                "accepted": accepted,
                "listener": mode,
                "client_identity": client_identity,
                "server_identity": SERVER_ID,
                "marker": marker if accepted else None,
            }
            body = json.dumps(response, sort_keys=True).encode("ascii")
            self.wfile.write(
                f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                + body
            )
        except (ValueError, UnicodeError, OSError):
            # Keep fixture diagnostics free of request bytes and TLS internals.
            emit({"event": "request_rejected", "listener": self.server.listener})


class ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, listener, context):
        self.listener = listener
        self.context = context
        super().__init__(address, Handler)

    def get_request(self):
        sock, address = super().get_request()
        try:
            return self.context.wrap_socket(sock, server_side=True), address
        except ssl.SSLError as error:
            if error.reason in {"PEER_DID_NOT_RETURN_A_CERTIFICATE", "CERTIFICATE_VERIFY_FAILED"}:
                emit({"event": "tls_rejected", "listener": self.listener, "reason": error.reason})
            sock.close()
            raise OSError("fixture TLS handshake rejected") from None

    def handle_error(self, request, client_address):
        # Do not serialize exception text, request bytes, or certificate material.
        return


def serve():
    base = "/certs/server"
    servers = []
    for listener, port in PORTS.items():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(f"{base}/server.crt", f"{base}/server.key")
        context.load_verify_locations(cafile=f"{base}/ca.crt")
        if listener == "mutual-tls":
            context.verify_mode = ssl.CERT_REQUIRED
        server = ThreadingServer(("0.0.0.0", port), listener, context)
        servers.append(server)
    import threading
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    emit({"event": "ready", "listeners": sorted(PORTS)})
    threading.Event().wait()


def probe(mode):
    if mode not in {"baseline", "missing", "untrusted", "unauthorized", "authorized"}:
        raise SystemExit("unknown fixed probe mode")
    peer_ip = os.environ["PEER_IP"]
    server_dns = os.environ["SERVER_DNS"]
    context = ssl.create_default_context(cafile="/certs/client/ca.crt")
    context.check_hostname = True
    port = 8443 if mode == "baseline" else 8444
    if mode in {"authorized", "unauthorized"}:
        directory = "/certs/client" if mode == "authorized" else "/certs/unauthorized"
        context.load_cert_chain(f"{directory}/client.crt", f"{directory}/client.key")
    elif mode == "untrusted":
        context.load_cert_chain("/certs/untrusted/client.crt", "/certs/untrusted/client.key")
    body = os.environ["MARKER"].encode("ascii")
    try:
        with socket.create_connection((peer_ip, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=server_dns) as connection:
                observed_server_uri = peer_uri(connection)
                request = (
                    b"POST /exchange HTTP/1.1\r\nHost: " + server_dns.encode("ascii")
                    + b"\r\nContent-Type: text/plain\r\nContent-Length: "
                    + str(len(body)).encode("ascii") + b"\r\nConnection: close\r\n\r\n" + body
                )
                connection.sendall(request)
                response = connection.makefile("rb").read()
                _, _, payload = response.partition(b"\r\n\r\n")
                result = json.loads(payload.decode("ascii"))
                result.update({
                    "tls_established": True,
                    "server_hostname_verified": True,
                    "server_certificate_uri_matches": observed_server_uri == SERVER_ID,
                })
    except ssl.SSLError as error:
        result = {"tls_established": False, "error_class": type(error).__name__}
    except (OSError, ValueError, json.JSONDecodeError):
        result = {"tls_established": False, "error_class": "ConnectionOrResponseError"}
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "serve":
        serve()
    elif len(sys.argv) == 2 and sys.argv[1] == "idle":
        import threading
        threading.Event().wait()
    elif len(sys.argv) == 3 and sys.argv[1] == "probe":
        probe(sys.argv[2])
    else:
        raise SystemExit("use serve, idle, or probe with a fixed mode")
