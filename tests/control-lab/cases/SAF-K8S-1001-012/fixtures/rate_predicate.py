"""Fixed, synthetic request-rate decision derived from a documented baseline."""


def rate_exceeds_baseline(record, thresholds):
    rate = record.get("requests_per_minute")
    baseline = record.get("baseline_requests_per_minute")
    multiplier = thresholds.get("inference_rate_max_multiplier")
    numbers = (int, float)
    return (
        record.get("rule") == "inference_request_rate_spike"
        and isinstance(rate, numbers) and not isinstance(rate, bool)
        and isinstance(baseline, numbers) and not isinstance(baseline, bool) and baseline > 0
        and isinstance(multiplier, numbers) and not isinstance(multiplier, bool) and multiplier >= 1
        and rate > baseline * multiplier
    )
