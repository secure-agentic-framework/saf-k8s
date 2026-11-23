"""Report an explicit canary from the already scoped test events."""
import json
from pathlib import Path

rows = json.loads(Path("/fixture/rows.json").read_text())
alerts = [
    {"rule": "fixture-static-canary", "severity": "test", "namespace": "saf-test",
     "qname": row["qname"], "qtype": row["qtype"]}
    for row in rows if row["qname"] == "signal.fixture.test." and row["qtype"] == "A"
]
print(json.dumps({"observed_records": len(rows), "alerts": alerts}))
