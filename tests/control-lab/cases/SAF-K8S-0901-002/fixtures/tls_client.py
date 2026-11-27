"""Fixed-message client for the TLS-only worker channel fixture."""
import http.client
import json
import ssl
import time
import sys
from pathlib import Path


PRIMARY_HOST = "aggregation-tls.saf-0901-002.svc.cluster.local"
ALTERNATE_HOST = "aggregation-alternate.saf-0901-002.svc.cluster.local"
PORT = 8443
BODY = {
    "request_id": "synthetic-tls-channel-01",
    "worker_id": "worker-a",
    "round_id": "round-7",
    "schema_version": "v1",
    "vector": [0.01, -0.02, 0.03],
}


def _context(check_hostname=True):
    context = ssl.create_default_context(cafile="/ca/ca.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = check_hostname
    return context


def _tls_json(host, method, path, body=None, authorization=False, check_hostname=True):
    context = _context(check_hostname)
    connection = http.client.HTTPSConnection(host, PORT, context=context, timeout=4)
    headers = {"Content-Type": "application/json"}
    payload = None
    if body is not None:
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    if authorization:
        headers["Authorization"] = "Bearer " + Path(
            "/run/fixture-identity/token").read_text(encoding="utf-8")
    connection.connect()
    tls_version = connection.sock.version()
    cipher = connection.sock.cipher()[0]
    connection.request(method, path, body=payload, headers=headers)
    response = connection.getresponse()
    status = response.status
    document = json.loads(response.read(4096))
    connection.close()
    return status, document, tls_version, cipher


def _plaintext_get():
    connection = http.client.HTTPConnection(PRIMARY_HOST, PORT, timeout=4)
    try:
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        response.read(4096)
        return {"plaintext_listener_rejected": False,
                "unexpected_plaintext_http_status": response.status}
    except (OSError, http.client.HTTPException):
        return {"plaintext_listener_rejected": True}
    finally:
        connection.close()


def _trusted_submit():
    cleartext = _plaintext_get()
    before_status, before, _, _ = _tls_json(PRIMARY_HOST, "GET", "/v1/status")
    status, result, version, cipher = _tls_json(
        PRIMARY_HOST, "POST", "/v1/contribute", BODY, authorization=True)
    _, observed_status, _, _ = _tls_json(PRIMARY_HOST, "GET", "/v1/status")
    _, aggregate, _, _ = _tls_json(PRIMARY_HOST, "GET", "/v1/mock-result")
    print(json.dumps({
        **cleartext,
        "count_before_tls_submit": before.get("received_count") if before_status == 200 else None,
        "http_status": status,
        "response": result,
        "tls_protocol": version,
        "cipher": cipher,
        "server_status": observed_status if status == 200 else None,
        "aggregate": aggregate if status == 200 else None,
    }, sort_keys=True), flush=True)


def _ready():
    deadline = time.monotonic() + 14
    while True:
        try:
            status, result, version, cipher = _tls_json(PRIMARY_HOST, "GET", "/healthz")
            break
        except (ConnectionError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
    print(json.dumps({"tls_ready": status == 200 and result == {"ok": True, "fixture": "0901-002"},
                      "tls_protocol": version, "cipher": cipher}, sort_keys=True), flush=True)


def _wrong_primary_name():
    try:
        status, _, _, _ = _tls_json(PRIMARY_HOST, "POST", "/v1/contribute", BODY, authorization=True)
        print(json.dumps({"hostname_verification_failed": False,
                          "contribution_request_sent": True,
                          "unexpected_http_status": status}, sort_keys=True), flush=True)
    except ssl.SSLCertVerificationError as error:
        failed = "hostname" in str(error).lower() or "ip address mismatch" in str(error).lower()
        print(json.dumps({"hostname_verification_failed": failed,
                          "contribution_request_sent": False}, sort_keys=True), flush=True)
    except (OSError, ssl.SSLError):
        print(json.dumps({"hostname_verification_failed": False,
                          "contribution_request_sent": False}, sort_keys=True), flush=True)


def _read_alternate_name():
    _, status, version, cipher = _tls_json(ALTERNATE_HOST, "GET", "/v1/status")
    _, aggregate, _, _ = _tls_json(ALTERNATE_HOST, "GET", "/v1/mock-result")
    print(json.dumps({"verified_alternate_name": True, "tls_protocol": version,
                      "cipher": cipher, "status": status, "aggregate": aggregate},
                     sort_keys=True), flush=True)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: tls_client.py ready|trusted-submit|wrong-primary-name|read-alternate-name")
    operation = sys.argv[1]
    if operation == "ready":
        _ready()
    elif operation == "trusted-submit":
        _trusted_submit()
    elif operation == "wrong-primary-name":
        _wrong_primary_name()
    elif operation == "read-alternate-name":
        _read_alternate_name()
    else:
        raise SystemExit("unsupported fixture operation")


if __name__ == "__main__":
    main()
