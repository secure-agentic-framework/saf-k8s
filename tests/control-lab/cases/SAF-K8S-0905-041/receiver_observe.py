"""Read the authenticated case-local receiver and emit only a bounded projection."""
import base64
import json
import ssl
import sys
from pathlib import Path
from urllib.request import Request, urlopen

user = Path("/receiver-auth/username").read_text().strip()
password = Path("/receiver-auth/password").read_text().strip()
identity = base64.b64encode(f"{user}:{password}".encode()).decode()
context = ssl.create_default_context(cafile="/receiver-ca/ca.pem")
request = Request(sys.argv[1] + "/alerts", headers={"Authorization": "Basic " + identity})
with urlopen(request, context=context, timeout=5) as response:
    value = json.load(response)
alerts = value.get("alerts", [])
print(json.dumps({"status": response.status,
                  "alert_ids": sorted(item.get("alert_id", "") for item in alerts),
                  "events": sorted(item.get("event_id", "") for item in alerts),
                  "rules": sorted(item.get("rule", "") for item in alerts),
                  "records": alerts,
                  "duplicates": value.get("duplicates")}, sort_keys=True))
