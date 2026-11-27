#!/usr/bin/env python3
"""Synthetic validator regression only; this is not hardware evidence."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("dcgm_validator", HERE / "validate_dcgm_receipt.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

START = "2026-11-27T12:00:00Z"
END = "2026-11-27T12:00:10Z"
POD_UID = "10000000-0000-4000-8000-000000000001"
GPU_UUID = "GPU-synthetic-device-01"
METRIC = "DCGM_FI_DEV_GPU_UTIL"
LABELS = {
    "__name__": METRIC, "UUID": GPU_UUID, "gpu": "0",
    "pod": "fixture-gpu-workload", "namespace": "saf-test",
    "container": "worker", "pod_uid": POD_UID,
    "job": "dcgm-exporter", "instance": "10.0.0.9:9400",
}


def receipt():
    return {
        "schema": "saf-k8s-dcgm-hardware-receipt-v1",
        "evidence_kind": "synthetic_regression",
        "non_evidence": True,
        "capture_id": "synthetic-only",
        "observation_interval": {"start_utc": START, "end_utc": END},
        "host": {"hostname": "fixture-node", "os": "linux", "architecture": "x86_64"},
        "hardware": {"gpu_uuid": GPU_UUID, "model": "NVIDIA Data Center Fixture GPU",
                      "category": "datacenter", "classification_basis": "synthetic test value"},
        "versions": {"driver": "synthetic-driver", "container_runtime": "synthetic-runtime",
                     "device_plugin": "synthetic-plugin", "kubelet": "synthetic-kubelet",
                     "kubernetes": "synthetic-kubernetes", "dcgm": "synthetic-dcgm",
                     "exporter_version": "synthetic-exporter",
                     "exporter_image_digest": "sha256:" + "a" * 64},
        "compatibility_assessment": {"status": "supported", "driver": "synthetic-driver",
            "dcgm": "synthetic-dcgm", "exporter_version": "synthetic-exporter",
            "official_sources": ["https://docs.nvidia.com/synthetic-only"],
            "reviewed_at_utc": END},
        "pod_before": {"namespace": "saf-test", "name": "fixture-gpu-workload", "uid": POD_UID,
            "container": "worker", "node": "fixture-node", "phase": "Running",
            "gpu_request": "1", "captured_at_utc": "2026-11-27T11:59:59Z"},
        "pod_after": {"namespace": "saf-test", "name": "fixture-gpu-workload", "uid": POD_UID,
            "container": "worker", "node": "fixture-node", "phase": "Succeeded",
            "gpu_request": "1", "captured_at_utc": "2026-11-27T12:00:11Z"},
        "node": {"name": "fixture-node", "uid": "10000000-0000-4000-8000-000000000002", "allocatable": {"nvidia.com/gpu": "1"},
                 "captured_at_utc": "2026-11-27T12:00:05Z"},
        "pod_resources": {"captured_at_utc": "2026-11-27T12:00:05Z", "entries": [{
            "namespace": "saf-test", "pod": "fixture-gpu-workload", "container": "worker",
            "resource_name": "nvidia.com/gpu", "device_ids": [GPU_UUID]}]},
        "exporter_pod": {"namespace": "gpu-monitoring", "name": "fixture-dcgm-exporter",
            "uid": "10000000-0000-4000-8000-000000000003", "node": "fixture-node",
            "pod_ip": "10.0.0.9", "phase": "Running", "captured_at_utc": "2026-11-27T12:00:05Z"},
        "exporter_target": {"namespace": "gpu-monitoring", "pod": "fixture-dcgm-exporter",
            "pod_uid": "10000000-0000-4000-8000-000000000003", "node": "fixture-node", "pod_ip": "10.0.0.9",
            "port": 9400, "job": "dcgm-exporter", "instance": "10.0.0.9:9400", "up": True,
            "captured_at_utc": "2026-11-27T12:00:05Z", "scrape_interval_seconds": 5},
        "prometheus_active_target": {"health": "up", "scrape_url": "http://10.0.0.9:9400/metrics",
            "captured_at_utc": "2026-11-27T12:00:05Z", "last_scrape_utc": "2026-11-27T12:00:04Z",
            "labels": {"job": "dcgm-exporter", "instance": "10.0.0.9:9400"},
            "discovered_labels": {"__meta_kubernetes_namespace": "gpu-monitoring",
                "__meta_kubernetes_pod_name": "fixture-dcgm-exporter",
                "__meta_kubernetes_pod_uid": "10000000-0000-4000-8000-000000000003",
                "__meta_kubernetes_pod_node_name": "fixture-node", "__meta_kubernetes_pod_ip": "10.0.0.9"}},
        "max_sample_skew_seconds": 5,
        "selected_fields": [{"metric": METRIC, "support": {"status": "supported",
            "device_model": "NVIDIA Data Center Fixture GPU", "dcgm": "synthetic-dcgm",
            "exporter_version": "synthetic-exporter", "official_sources": ["https://docs.nvidia.com/synthetic-only"],
            "unit": "percent"}}],
        "exporter_exposition": {"captured_at_utc": "2026-11-27T12:00:04Z",
            "source_url": "http://127.0.0.1:19400/metrics",
            "port_forward": {"mode": "kubectl-port-forward", "target_namespace": "gpu-monitoring",
                "target_pod": "fixture-dcgm-exporter", "target_pod_uid": "10000000-0000-4000-8000-000000000003",
                "remote_port": 9400, "local_port": 19400, "captured_at_utc": "2026-11-27T12:00:04Z"},
            "selected_lines": [f'{METRIC}{{UUID="{GPU_UUID}",gpu="0",pod="fixture-gpu-workload",namespace="saf-test",container="worker",pod_uid="{POD_UID}"}} 0']},
        "prometheus_query": {"range_start_utc": START, "range_end_utc": END,
            "evaluated_at_utc": "2026-11-27T12:00:05Z", "window_seconds": 10,
            "selected_results": [{"metric": METRIC,
                "range_vector_query": f'{METRIC}{{UUID="{GPU_UUID}",pod="fixture-gpu-workload",namespace="saf-test",container="worker"}}[10s]',
                "api_response": {"status": "success", "data": {"resultType": "matrix", "result": [{
                    "metric": LABELS, "values": [[1795780805.0, "0"]]}]}}}]},
    }


def main():
    good = receipt()
    validator.validate(good)
    precise = deepcopy(good)
    precise["pod_resources"]["captured_at_utc"] = "2026-11-27T12:00:03.317911311Z"
    precise["prometheus_active_target"]["last_scrape_utc"] = "2026-11-27T12:00:05.111222333Z"
    validator.validate(precise)
    bad = deepcopy(good)
    bad["pod_resources"]["entries"][0]["device_ids"] = ["GPU-other-synthetic-device"]
    try:
        validator.validate(bad)
    except validator.ReceiptError:
        rejected = True
    else:
        rejected = False
    assert rejected, "negative UUID join case was accepted"
    print('{"status":"passed","kind":"synthetic_non_evidence_only","checks":3}')


if __name__ == "__main__":
    main()
