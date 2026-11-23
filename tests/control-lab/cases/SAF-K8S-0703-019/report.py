"""Create an informational report from the immutable synthetic input snapshot."""

from collections import defaultdict
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
from pathlib import Path


def build(snapshot):
    rates = {key: Decimal(value) for key, value in snapshot["fixture_rates"].items()}
    totals = defaultdict(int)
    exceptions = []
    unpriced = Decimal("0")
    omitted_by_naive_report = 0
    for item in snapshot["usage"]:
        owner = snapshot["owners"][item["namespace"]]
        quantity = Decimal(item["hours"])
        rate = rates.get(item["resource"])
        if rate is None:
            unpriced += quantity
            exceptions.append({"id": item["id"], "reason": "missing-rate"})
            continue
        cents = int((quantity * rate * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        if owner is None:
            omitted_by_naive_report += cents
            exceptions.append({"id": item["id"], "reason": "missing-owner"})
        totals[owner or "unallocated"] += cents
    return {"mode": "fixture-showback", "currency": "USD", "data_basis": "synthetic illustration",
            "period": snapshot["period"], "rate_revision": snapshot["rate_revision"],
            "priced_minor_units": sum(totals.values()) + snapshot["shared_minor_units"],
            "reported_minor_units": dict(totals), "shared_minor_units": snapshot["shared_minor_units"],
            "unpriced_hours": str(unpriced), "exceptions": exceptions,
            "naive_owner_only_minor_units": sum(totals.values()) - omitted_by_naive_report}


if __name__ == '__main__':
    raw = Path('/input/snapshot.json').read_bytes()
    output = build(json.loads(raw))
    output['input_sha256'] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(output, sort_keys=True))
