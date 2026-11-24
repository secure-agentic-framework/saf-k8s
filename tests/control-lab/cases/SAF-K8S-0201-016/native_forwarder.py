"""Forward one native marker from a PVC or inspect its central copy."""
import json
import os
from pathlib import Path
import ssl
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

INPUT = Path("/input/event.json")
PENDING = Path("/spool/pending.json")
BASE_URL = "https://native-audit-receiver.saf-test.svc:8443"


def context(authenticated=True):
    tls = ssl.create_default_context(cafile="/tls/ca.crt")
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    if authenticated:
        tls.load_cert_chain("/tls/client.crt", "/tls/client.key")
    return tls


def post(payload):
    request = Request(BASE_URL + "/events", data=payload,
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, context=context(), timeout=5) as response:
            return response.status
    except HTTPError as error:
        return error.code


def persist_first_record():
    if PENDING.exists():
        raise ValueError("new source input requires a clean fixture spool")
    temporary = PENDING.with_suffix(".tmp")
    with temporary.open("xb") as stream:
        stream.write(INPUT.read_bytes())
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(PENDING)
    directory = os.open(PENDING.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def forward(*, resume):
    if not resume:
        persist_first_record()
    # The resumed Pod has no source input mount. A lost spool fails here.
    payload = PENDING.read_bytes()
    serial = json.loads(payload)["serial"]
    while True:
        try:
            status = post(payload)
        except (TimeoutError, URLError, OSError) as error:
            print(f"delivery retryable={type(error).__name__} serial={serial}", flush=True)
        else:
            if status == 202:
                PENDING.unlink()
                print(f"delivery status=202 serial={serial}", flush=True)
                break
            print(f"delivery status={status} serial={serial}", flush=True)
        time.sleep(1)
    while True:
        time.sleep(3600)


def main():
    mode = sys.argv[1]
    if mode in {"send", "resume"}:
        forward(resume=mode == "resume")
    elif mode == "query":
        serial = sys.argv[2]
        with urlopen(BASE_URL + "/events?serial=" + serial, context=context(), timeout=5) as response:
            print(json.dumps(json.loads(response.read())), flush=True)
    elif mode == "replay":
        status = post(sys.stdin.buffer.read())
        print(f"delivery status={status}", flush=True)
        raise SystemExit(0 if status == 202 else 1)
    elif mode == "without-certificate":
        try:
            with urlopen(BASE_URL + "/events", context=context(False), timeout=5) as response:
                response.read()
        except URLError as error:
            error = error.reason
            if isinstance(error, ssl.SSLError) and error.reason in {
                "TLSV13_ALERT_CERTIFICATE_REQUIRED", "SSLV3_ALERT_HANDSHAKE_FAILURE"
            }:
                print("client-certificate-required", flush=True)
                return
            raise
        except ssl.SSLError as error:
            if error.reason == "TLSV13_ALERT_CERTIFICATE_REQUIRED":
                print("client-certificate-required", flush=True)
                return
            raise
        raise SystemExit("an uncredentialed client unexpectedly received an HTTP response")
    else:
        raise SystemExit("unknown sender operation")


if __name__ == "__main__":
    main()
