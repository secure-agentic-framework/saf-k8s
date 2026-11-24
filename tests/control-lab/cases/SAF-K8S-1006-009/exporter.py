"""Retry a staged synthetic audit envelope until the fixture receiver acknowledges it."""
from hashlib import sha256
import json
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SPOOL = Path("/spool")
PENDING = SPOOL / "pending.json"
STATUS = SPOOL / "status.json"
DESTINATION = "http://saf-1006-009-receiver:8080/ingest"


def report(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data))
    temporary.replace(path)


while True:
    if not PENDING.is_file():
        time.sleep(.3)
        continue
    body = PENDING.read_bytes()
    evidence_id = sha256(body).hexdigest()
    attempts = 0
    while PENDING.is_file():
        attempts += 1
        try:
            req = Request(DESTINATION, data=body, headers={"Content-Type": "application/json",
                                                           "Idempotency-Key": evidence_id},
                          method="POST")
            with urlopen(req, timeout=3) as response:
                acknowledged = response.status == 200 and response.read() == b"ok"
        except (HTTPError, URLError, TimeoutError) as error:
            report(STATUS, {"state": "delivery_failed", "evidence_id": evidence_id, "attempts": attempts,
                            "response_code": getattr(error, "code", None)})
        else:
            if acknowledged:
                PENDING.unlink()
                report(STATUS, {"state": "acknowledged", "evidence_id": evidence_id, "attempts": attempts,
                                "response_code": 200})
                break
            report(STATUS, {"state": "delivery_failed", "evidence_id": evidence_id,
                            "attempts": attempts, "response_code": None})
        time.sleep(.5)
