"""Small, deterministic counter oracle over captured case-local CoreDNS rows."""
import collections
import json
import math
from pathlib import Path

rows = json.loads(Path("/fixture/rows.json").read_text())
expected = json.loads(Path("/fixture/expected.json").read_text())
counts = collections.Counter((row["qname"], row["qtype"]) for row in rows)
by_name = collections.Counter(row["qname"] for row in rows)
alerts = []
for qname, count in sorted(by_name.items()):
    if qname == expected["volume_name"] and count >= 3:
        alerts.append({"rule": "fixture-query-volume", "qname": qname, "count": count})
for row in rows:
    label = row["qname"].split(".", 1)[0]
    freq = collections.Counter(label)
    entropy = -sum((n / len(label)) * math.log2(n / len(label)) for n in freq.values())
    if len(label) >= 32:
        alerts.append({"rule": "fixture-long-label", "qname": row["qname"], "label_length": len(label)})
    elif len(label) >= 16 and entropy >= 3.5:
        alerts.append({"rule": "fixture-high-entropy-label", "qname": row["qname"], "entropy_bits": round(entropy, 3)})
    if row["qtype"] == "TXT":
        alerts.append({"rule": "fixture-unusual-qtype", "qname": row["qname"], "qtype": row["qtype"]})
# Deduplicate alerts created by repeated rows while retaining the independently counted threshold.
unique = { (a["rule"], a["qname"]): a for a in alerts }
print(json.dumps({
    "observed_records": len(rows),
    "counts": {f"{name}|{qtype}": count for (name, qtype), count in sorted(counts.items())},
    "volume_control_count": by_name[expected["control_name"]],
    "volume_burst_count": by_name[expected["volume_name"]],
    "alerts": sorted(unique.values(), key=lambda a: (a["rule"], a["qname"])),
}, sort_keys=True))
