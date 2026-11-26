"""Read the case-local receiver and emit only its bounded projection."""
import json
import sys
from urllib.request import urlopen

with urlopen(sys.argv[1] + "/alerts", timeout=5) as response:
    value = json.load(response)
alerts = value.get("alerts", [])
print(json.dumps({"status": response.status,
                  "alert_ids": sorted(item.get("alert_id", "") for item in alerts),
                  "events": sorted(item.get("event_id", "") for item in alerts),
                  "rules": sorted(item.get("rule", "") for item in alerts),
                  "records": alerts,
                  "duplicates": value.get("duplicates")}, sort_keys=True))
