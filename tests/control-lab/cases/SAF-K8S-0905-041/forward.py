"""Forward one bounded already-normalized fixture event and print filtered output."""
import json
import sys
from urllib.request import Request, urlopen

base, encoded_event = sys.argv[1:3]
event = json.loads(encoded_event)
payload = json.dumps({"phase": "enforce", "events": [event]},
                     sort_keys=True, separators=(",", ":")).encode()
request = Request(base + "/ingest", data=payload,
                  headers={"Content-Type": "application/json"})
with urlopen(request, timeout=5) as response:
    summary = json.load(response)
print(json.dumps({"status": response.status,
                  "event_count": len(summary.get("events", [])),
                  "duplicate_count": summary.get("duplicates"),
                  "alert_ids": sorted(summary.get("alerts", {}))}, sort_keys=True))
