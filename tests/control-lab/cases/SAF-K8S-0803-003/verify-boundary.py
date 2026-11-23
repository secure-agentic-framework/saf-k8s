"""Classify reviewed synthetic RDMA policy evidence."""

import json
from pathlib import Path

source = Path("/fixture/policy-cases.json")
results = {}
for name, item in json.loads(source.read_text()).items():
    if not all(item.get(key) for key in ("trust", "region_scope", "queue_scope", "expires_at")):
        result = "incomplete"
    elif item["region_scope"] != item["trust"] or item["queue_scope"] != item["trust"]:
        result = "wrong-trust-boundary"
    elif not set(item["observed_operations"]).issubset(item["approved_operations"]):
        result = "unapproved-permission"
    elif item["expires_at"] <= item["observed_at"]:
        result = "stale"
    else:
        result = "consistent-fixture"
    results[name] = result
print(json.dumps(results, sort_keys=True))
