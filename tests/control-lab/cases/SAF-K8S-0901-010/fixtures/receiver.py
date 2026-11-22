import json
import socket
import ssl
import threading


MARKER = "SAF-SYNTH-GRADIENT-MARKER-0901-010"


def emit(**fields):
    print(json.dumps(fields, sort_keys=True, separators=(",", ":")), flush=True)


def read_one(conn, mode, tls_version=None, client_certificate_present=False):
    conn.settimeout(10)
    data = bytearray()
    while b"\n" not in data and len(data) <= 256:
        block = conn.recv(128)
        if not block:
            break
        data.extend(block)
    if not data:
        conn.close()
        return
    readback = bytes(data).split(b"\n", 1)[0].decode("ascii", "replace")
    valid = len(data) <= 256 and readback == MARKER
    conn.sendall((readback + "\n").encode("ascii"))
    emit(mode=mode, readback=readback if valid else "invalid-fixture-marker",
         tls_version=tls_version, client_certificate_present=client_certificate_present)
    conn.close()


def serve(port, mode, context=None):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(8)
    while True:
        raw, _ = listener.accept()
        try:
            conn = context.wrap_socket(raw, server_side=True) if context else raw
            peer = conn.getpeercert() if context else None
            read_one(conn, mode, conn.version() if context else None, bool(peer))
        except (OSError, ssl.SSLError):
            raw.close()


tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.minimum_version = ssl.TLSVersion.TLSv1_3
tls.maximum_version = ssl.TLSVersion.TLSv1_3
tls.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
tls.verify_mode = ssl.CERT_NONE
threading.Thread(target=serve, args=(9011, "plaintext"), daemon=True).start()
serve(9012, "tls", tls)
