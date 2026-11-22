"""Print fixed synthetic telemetry records; never accesses devices or external targets."""
import json

fixture = {
    "fixture_id": "SYNTH-1005-027-ACCELERATOR-001",
    "evidence_class": "synthetic_fixture",
    "telemetry": [{
        "event": "synthetic_accelerator_snapshot",
        "observed_at": "2030-01-01T00:00:00Z",
        "temperature_celsius": 31,
        "memory_used_bytes": 0,
        "utilization_percent": 0,
        "source": "case-owned-fixture",
        "actual_measurement": False,
    }],
}
for record in fixture["telemetry"]:
    print(json.dumps(record, sort_keys=True))
