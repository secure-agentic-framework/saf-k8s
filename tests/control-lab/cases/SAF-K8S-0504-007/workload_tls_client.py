#!/usr/bin/env python3
"""One-request client for the SAF-K8S-0504-007 workload TLS fixture."""

import argparse
import http.client
import json
import ssl
import sys


def emit(result_type, **fields):
    # Results contain outcome metadata only; never include input paths or credentials.
    print(json.dumps({"type": result_type, **fields}, sort_keys=True, separators=(",", ":")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="owned A service DNS name")
    parser.add_argument("--port", type=int, default=8443, help="owned A service port (default: 8443)")
    parser.add_argument("--cert", required=True, help="workload X.509 certificate path")
    parser.add_argument("--key", required=True, help="workload private key path")
    parser.add_argument("--bundle", required=True, help="local A server root bundle path")
    parser.add_argument("--approved-uri", required=True, help="exact server SPIFFE URI SAN expected")
    args = parser.parse_args()

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.bundle)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False  # SPIFFE URI identity is checked exactly below.
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)

    connection = http.client.HTTPSConnection(args.host, args.port, context=context, timeout=4)
    server_uri_verified = False
    try:
        connection.connect()
        peer = connection.sock.getpeercert()
        server_uris = [value for kind, value in peer.get("subjectAltName", ()) if kind == "URI"]
        if server_uris != [args.approved_uri]:
            emit("server_identity_rejected")
            return 2
        server_uri_verified = True
        connection.request("GET", "/")
        response = connection.getresponse()
        response.read()
        if response.status in (200, 403):
            emit("http_result", status=response.status, server_uri_verified=server_uri_verified)
            return 0
        emit("unexpected_http_status")
        return 2
    except ssl.SSLCertVerificationError:
        emit("server_certificate_rejected")
        return 2
    except ssl.SSLError as error:
        if error.reason == "TLSV1_ALERT_UNKNOWN_CA":
            emit("client_certificate_rejected")
            return 0
        emit("unexpected_tls_error")
        return 2
    except (OSError, http.client.HTTPException) as error:
        emit("connection_error", exception_type=type(error).__name__, errno=getattr(error, "errno", None))
        return 2
    finally:
        connection.close()


if __name__ == "__main__":
    sys.exit(main())
