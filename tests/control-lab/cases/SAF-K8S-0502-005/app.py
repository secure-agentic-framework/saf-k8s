"""Tiny synthetic HTTP/TLS endpoint and strict probe client for the SAF fixture."""
import argparse
import http.server
import json
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.request


class MarkerHandler(http.server.BaseHTTPRequestHandler):
    marker = ""

    def do_GET(self):
        if self.path != "/marker":
            self.send_error(404)
            return
        body = self.marker.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=us-ascii")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Do not print requests or response data into container logs.
        return


def serve(args):
    handler = type("FixtureHandler", (MarkerHandler,), {"marker": args.marker})
    plain = http.server.ThreadingHTTPServer(("0.0.0.0", 8080), handler)
    tls = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    tls.socket = context.wrap_socket(tls.socket, server_side=True)
    threads = [threading.Thread(target=server.serve_forever, daemon=True)
               for server in (plain, tls)]
    for thread in threads:
        thread.start()
    try:
        for thread in threads:
            thread.join()
    finally:
        plain.server_close()
        tls.server_close()


def probe(args):
    try:
        if args.mode == "plain":
            request = urllib.request.Request("http://%s:8080/marker" % args.connect_host)
            with urllib.request.urlopen(request, timeout=3) as response:
                body = response.read().decode("ascii")
        else:
            context = ssl.create_default_context(cafile=args.ca_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = True
            with socket.create_connection((args.connect_host, 8443), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=args.expected_name) as secure:
                    request = ("GET /marker HTTP/1.1\r\nHost: %s\r\n"
                               "Connection: close\r\n\r\n" % args.expected_name)
                    secure.sendall(request.encode("ascii"))
                    chunks = []
                    while True:
                        chunk = secure.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
            response = b"".join(chunks)
            head, separator, payload = response.partition(b"\r\n\r\n")
            if not separator or b" 200 " not in head.split(b"\r\n", 1)[0]:
                raise RuntimeError("unexpected HTTP response")
            body = payload.decode("ascii")
        print(json.dumps({"outcome": "marker", "marker": body}, sort_keys=True))
    except ssl.SSLCertVerificationError as error:
        if error.verify_code == 62:
            observed = {"outcome": "certificate_error", "reason": "hostname"}
        elif error.verify_code in {19, 20, 21}:
            observed = {"outcome": "certificate_error", "reason": "trust"}
        else:
            observed = {"outcome": "unexpected_certificate_error", "verify_code": error.verify_code}
        print(json.dumps(observed, sort_keys=True))
    except (TimeoutError, socket.timeout, urllib.error.URLError) as error:
        reason = getattr(error, "reason", error)
        if isinstance(reason, (TimeoutError, socket.timeout)) or "timed out" in str(reason).lower():
            outcome = "timeout"
        else:
            outcome = "transport_error"
        print(json.dumps({"outcome": outcome}, sort_keys=True))
    except (OSError, ssl.SSLError, RuntimeError, UnicodeError):
        print(json.dumps({"outcome": "transport_error"}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("serve")
    server.add_argument("--marker", required=True)
    server.add_argument("--cert", required=True)
    server.add_argument("--key", required=True)
    client = commands.add_parser("probe")
    client.add_argument("--mode", choices=("plain", "tls"), required=True)
    client.add_argument("--connect-host", required=True)
    client.add_argument("--expected-name", default="")
    client.add_argument("--ca-file", default="")
    args = parser.parse_args()
    return serve(args) if args.command == "serve" else probe(args)


if __name__ == "__main__":
    main()
