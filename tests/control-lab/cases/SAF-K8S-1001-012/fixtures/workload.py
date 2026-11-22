"""Emit one fixed benign marker; no network, credentials, or model code."""
import json

print(json.dumps({
    "fixture_id": "SYNTH-SAF-K8S-1001-012-WORKLOAD-001",
    "event": "mock_workload_ready",
    "network_calls": 0,
    "secret_values": 0,
}, sort_keys=True), flush=True)
