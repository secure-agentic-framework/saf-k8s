"""Send the same fixed forwarded audit corpus through each monitor policy."""
import json
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def collect(base, events):
    def send(phase, batch):
        payload = json.dumps({"phase": phase, "events": batch}).encode()
        request = Request(base + "/ingest", data=payload, headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=5) as response:
                return json.load(response)
        except HTTPError as response:
            with response:
                return {"status": response.code, "body": json.load(response)}

    invalid = {**events[0], "event_id": "audit-invalid", "source": "unrecognized-source"}
    return {"baseline": send("baseline", events), "enforced": send("enforce", events),
            "replayed": send("enforce", events), "invalid_source": send("enforce", [invalid])}


if __name__ == "__main__":
    events = json.loads(Path(__file__).with_name("events.json").read_text())
    print(json.dumps(collect(sys.argv[1], events), sort_keys=True))
