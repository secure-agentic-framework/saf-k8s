"""Return only matched metadata audit identities and digests from the owned sink."""
import base64
import hashlib
import json
import ssl
import sys
from pathlib import Path
from urllib.request import Request, urlopen

expected_audit_id, expected_digest = sys.argv[1:3]
user = Path("/sink-auth/username").read_text().strip()
password = Path("/sink-auth/password").read_text().strip()
authorization = base64.b64encode(f"{user}:{password}".encode()).decode()
request = Request(
    "https://sink.saf-test.svc.cluster.local:8443/events",
    headers={"Authorization": "Basic " + authorization},
)
context = ssl.create_default_context(cafile="/sink-ca/ca.pem")
with urlopen(request, context=context, timeout=4) as response:
    records = [json.loads(line) for line in response.read().splitlines() if line.strip()]
matched = [row.get("event") for row in records
           if row.get("stream") == "k8s-audit" and isinstance(row.get("event"), dict)
           and row["event"].get("auditID") == expected_audit_id]
api_audit_records = [row for row in records if row.get("stream") == "k8s-audit"]
digests = [hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
           for event in matched]
metadata = [{key: event.get(key) for key in
             ("apiVersion", "kind", "level", "auditID", "stage", "stageTimestamp", "verb",
              "effectiveUsername", "objectRef", "responseStatus", "source")}
            for event in matched]
print(json.dumps({
    "sink_api_audit_record_count": len(api_audit_records),
    "matching_audit_ids": [event.get("auditID") for event in matched],
    "matching_event_sha256": digests,
    "matching_metadata": metadata,
    "expected_event_sha256_matches": digests == [expected_digest],
}, sort_keys=True))
