"""Serve only the lab's two reserved DNS-over-TLS query names."""
import socket
import ssl
import struct

NAMES = {b"query.verified.saf-0503-009.test.", b"query.wrong.saf-0503-009.test."}
MARKER = socket.inet_aton("192.0.2.53")


def answer(query):
    if len(query) < 17:
        return None
    labels = []
    offset = 12
    while offset < len(query):
        length = query[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length >= len(query):
            return None
        labels.append(query[offset:offset + length].lower())
        offset += length
    question = query[12:offset + 4]
    name = b".".join(labels) + b"."
    if name not in NAMES or query[offset:offset + 4] != struct.pack("!HH", 1, 1):
        return query[:2] + struct.pack("!HHHHH", 0x8185, 1, 0, 0, 0) + question
    print("query=" + name.decode(), flush=True)
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + MARKER
    return header + question + record


def serve():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    with socket.create_server(("0.0.0.0", 8853)) as server:
        while True:
            client, _ = server.accept()
            print("tcp_accept", flush=True)
            offered_name = None

            def observe_name(_socket, name, _context):
                nonlocal offered_name
                offered_name = name

            context.set_servername_callback(observe_name)
            with client:
                client.settimeout(2)
                try:
                    with context.wrap_socket(client, server_side=True) as conn:
                        print("tls_handshake_ok", flush=True)
                        with conn.makefile("rb") as stream:
                            prefix = stream.read(2)
                            if prefix is None or len(prefix) != 2:
                                continue
                            size = struct.unpack("!H", prefix)[0]
                            if not 0 < size <= 4096:
                                continue
                            response = answer(stream.read(size) or b"")
                            if response is not None:
                                conn.sendall(struct.pack("!H", len(response)) + response)
                except ssl.SSLError as error:
                    if (offered_name == "other-fixture.saf-0503-009.test"
                            and error.reason in {"SSLV3_ALERT_BAD_CERTIFICATE", "TLSV1_ALERT_UNKNOWN_CA"}):
                        print("wrong_sni_bad_certificate", flush=True)
                    else:
                        print("tls_handshake_rejected", flush=True)
                except OSError:
                    print("transport_error", flush=True)


if __name__ == "__main__":
    serve()
