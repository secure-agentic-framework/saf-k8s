"""Quality gate and file-backed observation using invented benign values."""
from __future__ import annotations

import json
import math
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MIN_SAMPLES = 8
MAX_SAMPLES = 64
MIN_VALUE = 0.0
MAX_VALUE = 100.0
MAX_OUTLIER_RATE = 0.25
MAX_MEAN_SHIFT = 5.0


def validate(snapshot):
    """Validate the strict fixture schema and bounded finite numeric values."""
    if not isinstance(snapshot, dict) or set(snapshot) != {"schema_version", "feature", "values"}:
        return ["schema_fields"]
    errors = []
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        errors.append("schema_version")
    if snapshot["feature"] != "sample_measurement":
        errors.append("feature")
    values = snapshot["values"]
    if not isinstance(values, list) or not MIN_SAMPLES <= len(values) <= MAX_SAMPLES:
        errors.append("sample_count")
        return errors
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            errors.append("numeric_finite_value")
            break
        if not MIN_VALUE <= value <= MAX_VALUE:
            errors.append("value_bounds")
            break
    return errors


def compare(approved, incoming):
    """Return a reproducible descriptive comparison and gate decision."""
    incoming_errors = validate(incoming)
    if incoming_errors:
        return {"decision": "hold", "cause": "input_validation", "validation_errors": incoming_errors,
                "sampling_limits": {"minimum": MIN_SAMPLES, "maximum": MAX_SAMPLES}}
    if validate(approved):
        return {"decision": "hold", "cause": "approved_snapshot_invalid",
                "validation_errors": validate(approved),
                "sampling_limits": {"minimum": MIN_SAMPLES, "maximum": MAX_SAMPLES}}
    a, b = approved["values"], incoming["values"]
    mean_a, mean_b = sum(a) / len(a), sum(b) / len(b)
    # Fixture-only outlier rule: count values farther than 3 approved standard
    # deviations from the approved mean. For zero variance, require exact agreement.
    variance = sum((x - mean_a) ** 2 for x in a) / len(a)
    sd = math.sqrt(variance)
    outliers = sum(abs(x - mean_a) > 3 * sd for x in b)
    outlier_rate = outliers / len(b)
    mean_shift = abs(mean_b - mean_a)
    if mean_shift > MAX_MEAN_SHIFT:
        cause = "distribution_mean_shift"
    elif outlier_rate > MAX_OUTLIER_RATE:
        cause = "outlier_rate"
    else:
        cause = "within_declared_limits"
    return {"decision": "hold" if cause != "within_declared_limits" else "release",
            "cause": cause,
            "comparison": {"method": "absolute_mean_difference_and_approved_3sd_outlier_rate",
                           "approved_mean": round(mean_a, 4), "incoming_mean": round(mean_b, 4),
                           "absolute_mean_shift": round(mean_shift, 4), "mean_shift_limit": MAX_MEAN_SHIFT,
                           "outlier_count": outliers, "outlier_rate": round(outlier_rate, 4),
                           "outlier_rate_limit": MAX_OUTLIER_RATE},
            "sampling_limits": {"minimum": MIN_SAMPLES, "maximum": MAX_SAMPLES,
                                "approved_count": len(a), "incoming_count": len(b)}}


NAMES = ("within-limits", "changed", "outliers", "out-of-bounds", "invalid-schema")


def canonical(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":")).encode()


def main():
    directory = Path("/volume")
    if sys.argv[1] == "read":
        observed = {}
        for mode in ("baseline", "approved"):
            observed[mode] = {f.stem: hashlib.sha256(f.read_bytes()).hexdigest()
                              for f in (directory / mode).glob("*.json")}
        print(json.dumps(observed, sort_keys=True))
        return
    fixtures = Path("/case")
    approved = json.loads((fixtures / "approved.json").read_text())
    for mode in ("baseline", "approved"):
        (directory / mode).mkdir(exist_ok=True)
    rows = {}
    for name in NAMES:
        candidate = json.loads((fixtures / (name + ".json")).read_text())
        payload = canonical(candidate)
        (directory / "baseline" / (name + ".json")).write_bytes(payload)
        decision = compare(approved, candidate)
        if decision["decision"] == "release":
            (directory / "approved" / (name + ".json")).write_bytes(payload)
        rows[name] = decision
    print(json.dumps(rows, sort_keys=True))


if __name__ == "__main__":
    main()
