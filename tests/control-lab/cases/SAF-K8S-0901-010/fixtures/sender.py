import json
import os
import socket
import ssl
import threading


HOST = os.environ["SERVER_HOST"]
SERVER_NAME = os.environ["SERVER_NAME"]
MARKER = os.environ["MARKER"]
MESSAGE = MARKER.encode("ascii") + b"\n"


def exchange(host, port, payload):
    with socket.create_connection((host, port), timeout=8) as conn:
        conn.settimeout(8)
        conn.sendall(payload)
        response = bytearray()
        while b"\n" not in response and len(response) <= 256:
            chunk = conn.recv(128)
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response).split(b"\n", 1)[0].decode("ascii")


def relay_worker(listener, upstream_port, captured, errors):
    try:
        local, _ = listener.accept()
        upstream = socket.create_connection((HOST, upstream_port), timeout=8)
        local.settimeout(8)
        upstream.settimeout(8)

        def forward(source, target, record=False):
            while True:
                try:
                    chunk = source.recv(4096)
                except OSError as error:
                    errors.append(type(error).__name__)
                    break
                if not chunk:
                    try:
                        target.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    break
                if record:
                    if len(captured) + len(chunk) > 16384:
                        errors.append("fixture_capture_limit")
                        break
                    captured.extend(chunk)
                try:
                    target.sendall(chunk)
                except OSError as error:
                    errors.append(type(error).__name__)
                    break

        t1 = threading.Thread(target=forward, args=(local, upstream, True))
        t2 = threading.Thread(target=forward, args=(upstream, local, False))
        t1.start(); t2.start(); t1.join(12); t2.join(12)
        if t1.is_alive() or t2.is_alive():
            errors.append("relay_thread_timeout")
        local.close()
        upstream.close()
    except Exception as error:
        errors.append(type(error).__name__)


def launch_relay(upstream_port):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    captured = bytearray()
    errors = []
    thread = threading.Thread(target=relay_worker,
                              args=(listener, upstream_port, captured, errors), daemon=True)
    thread.start()
    return listener, thread, captured, errors


plain_listener, plain_thread, observed_plain, plain_errors = launch_relay(9011)
plain_readback = exchange("127.0.0.1", plain_listener.getsockname()[1], MESSAGE)
plain_thread.join(15)
plain_listener.close()
plain = {"readback": plain_readback, "request_hex": bytes(observed_plain).hex(),
         "relay_completed": not plain_thread.is_alive(), "relay_errors": plain_errors}

relay, thread, captured, errors = launch_relay(9012)
port = relay.getsockname()[1]
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="/trust/ca.crt")
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
with socket.create_connection(("127.0.0.1", port), timeout=8) as raw:
    with context.wrap_socket(raw, server_hostname=SERVER_NAME) as secure:
        secure.sendall(MESSAGE)
        response = bytearray()
        while b"\n" not in response and len(response) <= 256:
            chunk = secure.recv(128)
            if not chunk:
                break
            response.extend(chunk)
        tls_readback = bytes(response).split(b"\n", 1)[0].decode("ascii")
        version = secure.version()
        peer_dns_names = [value for kind, value in secure.getpeercert().get("subjectAltName", ())
                          if kind == "DNS"]
thread.join(15)
relay.close()
tls = {"readback": tls_readback, "tls_version": version,
       "server_hostname_verified": True, "ca_validation": True,
       "peer_dns_names": peer_dns_names,
       "client_to_server_hex": bytes(captured).hex(),
       "owned_client_to_server_byte_count": len(captured),
       "relay_errors": errors, "relay_completed": not thread.is_alive()}
print(json.dumps({"plaintext": plain, "tls": tls}, sort_keys=True, separators=(",", ":")), flush=True)
