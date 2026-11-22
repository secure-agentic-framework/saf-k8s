"""Spool one synthetic event and retry private in-cluster delivery until accepted."""
import json
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SOURCE = Path("/input/event.json")
PENDING = Path("/spool/pending.json")
SINK = "http://audit-receiver.saf-test.svc:8080/events"


def main():
    if not PENDING.exists():
        PENDING.write_bytes(SOURCE.read_bytes())
    event = json.loads(PENDING.read_text(encoding="utf-8"))
    while PENDING.exists():
        request = Request(SINK, data=PENDING.read_bytes(), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=3) as response:
                status = response.status
                if 200 <= status < 300:
                    PENDING.unlink()
                    print(f"delivery accepted status={status} auditID={event['auditID']}", flush=True)
                    break
                print(f"delivery status={status} auditID={event['auditID']}", flush=True)
        except HTTPError as error:
            print(f"delivery status={error.code} auditID={event['auditID']}", flush=True)
        except (TimeoutError, URLError, OSError) as error:
            print(f"delivery retryable-error={type(error).__name__} auditID={event['auditID']}", flush=True)
        time.sleep(1)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
