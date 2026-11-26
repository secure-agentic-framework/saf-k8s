"""HTTPS-only, read-only serving of the authenticated exact API snapshot."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl

ROOT = Path("/snapshot")
FILES = {
    "/.well-known/openid-configuration": ROOT / "discovery.json",
    "/openid/v1/jwks": ROOT / "jwks.json",
    "/status": ROOT / "snapshot-status.json",
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        candidate = FILES.get(path)
        if candidate is None or not candidate.is_file():
            self.send_error(404)
            return
        body = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Request paths and returned public metadata are not useful evidence.
        return


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/server.crt", "/tls/server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("case-owned-https-snapshot-ready", flush=True)
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("snapshot fixture permission denied", flush=True)
        raise SystemExit(1)
    except Exception as error:
        print("snapshot fixture failed " + type(error).__name__, flush=True)
        raise SystemExit(1)
