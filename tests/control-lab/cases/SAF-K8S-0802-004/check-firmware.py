"""Classify inert firmware inventory observations against reviewed change records."""

import json
from pathlib import Path

root = Path("/fixture")
rows = json.loads((root / "inventory.json").read_text())
windows = json.loads((root / "windows.json").read_text())
result = {}

for row in rows:
    authorized = any(
        record["device"] == row["device"] and record["version"] == row["observed"]
        and record["open"] <= row["observed_at"] < record["close"] and bool(record["review_id"])
        for record in windows
    )
    if row["integrity"] != "verified":
        finding = "integrity-unverified"
    elif row["observed"] == row["expected"]:
        finding = "unchanged"
    elif authorized:
        finding = "approved-change"
    else:
        finding = "version-drift-alert"
    result[row["device"]] = finding
print(json.dumps(result, sort_keys=True))
