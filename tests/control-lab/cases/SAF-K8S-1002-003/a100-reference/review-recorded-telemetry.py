"""Check the joins and stage boundaries of the retained A100 GPU observations."""

from datetime import datetime
import json
import math
from pathlib import Path
import re
import sys


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main(path):
    ready, threshold, support = [json.loads((path / name).read_text()) for name in
                                 ("readiness.json", "live-threshold-evidence.json", "support-review.json")]
    require(ready["schema"] == "saf-a100-live-readiness-v1"
            and threshold["schema"] == "saf-a100-live-threshold-evidence-v1"
            and support["schema"] == "saf-a100-metric-support-review-v1", "Unexpected reference evidence format")
    device = ready["hardware"]
    workload = ready["workload"]
    exporter = ready["exporter"]
    metric = ready["selected_metric"]
    for key in (workload["uid_sha256"], device["gpu_uuid_sha256"], exporter["pod_uid_sha256"]):
        require(re.fullmatch("[0-9a-f]{64}", key), "Invalid pseudonym in fixture identity")
    require(device["allocated_device_count"] == 1 and device["resource_name"] == "nvidia.com/gpu"
            and workload["gpu_request"] == "1" and exporter["target_health"] == "up"
            and exporter["node_match"] is True and ready["device_plugin"]["node_match"] is True
            and metric["workload_uid_label_matches"] is True and metric["device_uuid_label_matches"] is True,
            "Missing readiness identity, target, or allocation evidence")
    require(workload["uid_sha256"] == threshold["workload"]["uid_sha256"] and
            all(workload[key] == threshold["workload"][key] for key in ("namespace", "name", "container")) and
            device["gpu_uuid_sha256"] == threshold["device"]["gpu_uuid_sha256"] and
            exporter["pod_uid_sha256"] == threshold["exporter"]["pod_uid_sha256"] and
            threshold["sample_labels_match_workload_and_device"] is True, "Workload or device attribution differs")
    digest = support["exporter_image_digest"]
    require(re.fullmatch("[0-9a-f]{64}", digest) and exporter["image_id"] == threshold["exporter"]["image_id"]
            and exporter["image_id"].endswith("@sha256:" + digest) and support["status"] == "reviewed-supported"
            and support["device_model"] == device["model"] == threshold["hardware_model"]
            and support["driver"] == device["driver"] == threshold["driver"]
            and support["metric"] == threshold["metric"] == metric["name"] == "DCGM_FI_DEV_FB_USED"
            and metric["unit"] == threshold["unit"] == "MiB", "Metric and version review differs from observations")
    captured = parse_time(threshold["captured_at_utc"])
    sample = parse_time(threshold["source_sample_timestamp_utc"])
    require(parse_time(ready["captured_at_utc"]) < sample <= captured
            and (captured - sample).total_seconds() <= 15
            and threshold["historical_reference_used_as_live_input"] is False,
            "Reference threshold sample fails the bounded live observation interval")
    allocation = threshold["expected_fixture_allocation_bytes"]
    require(allocation == ready["framebuffer_helper"]["allocated_bytes"] == 128 * 1024 * 1024,
            "Recorded run differs from the 128 MiB fixture allocation")
    for stem, baseline in (("direct", metric["direct_value"]), ("prometheus", metric["prometheus_value"])):
        before = threshold[f"baseline_{stem}_mib"]
        after = threshold[f"observed_{stem}_mib"]
        require(all(math.isfinite(n) for n in (before, after, baseline)) and
                before == baseline and after > threshold["threshold_mib"] and
                after - before == threshold[f"baseline_to_live_delta_{stem}_mib"] >= allocation / (1024 * 1024),
                f"{stem} evidence does not show the recorded framebuffer increase")
    print("PASS: readiness and live threshold receipts agree on the exact A100 and workload")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parent)
