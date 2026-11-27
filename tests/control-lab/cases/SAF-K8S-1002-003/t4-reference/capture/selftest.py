#!/usr/bin/env python3
"""In-process mocked response regression; synthetic only, no socket/device/cluster."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("dcgm_capture", HERE / "dcgm_capture.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)

METRIC = "DCGM_FI_DEV_GPU_UTIL"
UUID = "GPU-synthetic-device-01"
POD_UID = "10000000-0000-4000-8000-000000000001"
NODE_UID = "10000000-0000-4000-8000-000000000002"
EXPORTER_UID = "10000000-0000-4000-8000-000000000003"
POD, NS, CONTAINER, NODE = "fixture-workload", "saf-test", "worker", "fixture-node"
TARGET_IP, TARGET_PORT, JOB = "10.0.0.9", 9400, "dcgm-exporter"
INSTANCE, SCRAPE_URL = f"{TARGET_IP}:{TARGET_PORT}", f"http://{TARGET_IP}:{TARGET_PORT}/metrics"
EXPORTER_URL, PROM_URL, LOCAL_PORT = "http://127.0.0.1:19400", "http://127.0.0.1:19090", 19400


def stamp(value):
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def mock_http_get(url, _accept):
    if url == EXPORTER_URL + "/metrics":
        return ('UNSELECTED_FIXTURE_METRIC{synthetic_secret="omit"} 99\n' +
                f'{METRIC}{{UUID="{UUID}",gpu="0",namespace="{NS}",pod="{POD}",'
                f'container="{CONTAINER}",pod_uid="{POD_UID}",modelName="fixture-only-model"}} 0\n').encode()
    parsed = urlsplit(url)
    if parsed.path == "/api/v1/targets":
        now = datetime.now(timezone.utc)
        doc = {"status": "success", "data": {"activeTargets": [{
            "labels": {"job": JOB, "instance": INSTANCE},
            "discoveredLabels": {
                "__meta_kubernetes_namespace": "gpu-system",
                "__meta_kubernetes_pod_name": "dcgm-exporter-fixture",
                "__meta_kubernetes_pod_uid": EXPORTER_UID,
                "__meta_kubernetes_pod_node_name": NODE,
                "__meta_kubernetes_pod_ip": TARGET_IP,
            }, "health": "up", "scrapeUrl": SCRAPE_URL,
            "lastScrape": stamp(now)}]}}
        return json.dumps(doc).encode()
    if parsed.path == "/api/v1/query":
        params = parse_qs(parsed.query)
        expression = params["query"][0]
        assert expression.startswith(METRIC + "{") and expression.endswith("]")
        evaluated = float(params["time"][0])
        labels = {"__name__": METRIC, "UUID": UUID, "gpu": "0", "namespace": NS,
                  "pod": POD, "container": CONTAINER, "pod_uid": POD_UID,
                  "job": JOB, "instance": INSTANCE, "hostname": "fixture-only-hostname"}
        return json.dumps({"status": "success", "data": {"resultType": "matrix", "result": [
            {"metric": labels, "values": [[evaluated - 0.25, "0"]]}]}}).encode()
    raise AssertionError(f"unexpected mocked path {parsed.path}")


def run():
    adapter.http_get = mock_http_get
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=10)
    input_doc = {
        "schema": "saf-k8s-dcgm-capture-input-v1", "evidence_kind": "synthetic_regression",
        "non_evidence": True, "capture_id": "synthetic-only", "observation_start_utc": stamp(start),
        "max_observation_seconds": 30,
        "host": {"hostname": "fixture-host", "os": "linux", "architecture": "x86_64"},
        "hardware": {"gpu_uuid": UUID, "model": "NVIDIA Data Center Fixture GPU",
                     "category": "datacenter", "classification_basis": "synthetic"},
        "versions": {"driver": "fixture-driver", "container_runtime": "fixture-runtime",
                     "device_plugin": "fixture-plugin", "kubelet": "fixture-kubelet",
                     "kubernetes": "fixture-kubernetes", "dcgm": "fixture-dcgm",
                     "exporter_version": "fixture-exporter", "exporter_image_digest": "sha256:" + "a" * 64},
        "compatibility_assessment": {"status": "supported", "driver": "fixture-driver",
            "dcgm": "fixture-dcgm", "exporter_version": "fixture-exporter",
            "official_sources": ["https://docs.nvidia.com/synthetic-only"], "reviewed_at_utc": stamp(now)},
        "pod_before": {"namespace": NS, "name": POD, "uid": POD_UID, "container": CONTAINER,
            "node": NODE, "phase": "Running", "gpu_request": "1", "captured_at_utc": stamp(start - timedelta(seconds=1))},
        "exporter_pod": {"namespace": "gpu-system", "name": "dcgm-exporter-fixture", "uid": EXPORTER_UID,
            "node": NODE, "pod_ip": TARGET_IP, "phase": "Running", "captured_at_utc": stamp(start + timedelta(seconds=1))},
        "port_forward": {"mode": "kubectl-port-forward", "target_namespace": "gpu-system",
            "target_pod": "dcgm-exporter-fixture", "target_pod_uid": EXPORTER_UID,
            "remote_port": TARGET_PORT, "local_port": LOCAL_PORT, "captured_at_utc": stamp(start + timedelta(seconds=1))},
        "node": {"name": NODE, "uid": NODE_UID, "allocatable": {"nvidia.com/gpu": "1"},
                 "captured_at_utc": stamp(start + timedelta(seconds=2))},
        "pod_resources": {"captured_at_utc": stamp(start + timedelta(seconds=3)), "entries": [{
            "namespace": NS, "pod": POD, "container": CONTAINER,
            "resource_name": "nvidia.com/gpu", "device_ids": [UUID]}]},
        "exporter_target": {"namespace": "gpu-system", "pod": "dcgm-exporter-fixture",
            "pod_uid": EXPORTER_UID, "node": NODE, "pod_ip": TARGET_IP, "port": TARGET_PORT,
            "job": JOB, "instance": INSTANCE, "scrape_url": SCRAPE_URL, "scrape_interval_seconds": 15},
        "selected_fields": [{"metric": METRIC, "support": {"status": "supported",
            "device_model": "NVIDIA Data Center Fixture GPU", "dcgm": "fixture-dcgm",
            "exporter_version": "fixture-exporter", "official_sources": [
                "https://docs.nvidia.com/datacenter/dcgm/latest/reference/dcgm-exporter-metrics.html"],
            "unit": "percent"}}],
        "max_sample_skew_seconds": 5,
    }
    after = {"schema": "saf-k8s-dcgm-pod-after-v1", "namespace": NS, "name": POD,
        "uid": POD_UID, "container": CONTAINER, "node": NODE, "phase": "Running",
        "gpu_request": "1", "captured_at_utc": stamp(datetime.now(timezone.utc) + timedelta(seconds=1))}
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        ip, cp, ap, rp = (root / n for n in ("inputs.json", "collection.json", "after.json", "receipt.json"))
        ip.write_text(json.dumps(input_doc))
        ap.write_text(json.dumps(after))
        adapter.collect(argparse.Namespace(inputs=str(ip), exporter_url=EXPORTER_URL,
            prometheus_url=PROM_URL, output=str(cp)))
        adapter.finalize(argparse.Namespace(collection=str(cp), pod_after=str(ap), output=str(rp)))
        receipt = json.loads(rp.read_text())
        validator_path = os.environ.get("SAF_DCGM_RECEIPT_VALIDATOR")
        if validator_path:
            validator_spec = importlib.util.spec_from_file_location("dcgm_receipt_validator", validator_path)
            validator = importlib.util.module_from_spec(validator_spec)
            validator_spec.loader.exec_module(validator)
            validator.validate(receipt)
        assert receipt["evidence_kind"] == "synthetic_regression" and receipt["non_evidence"] is True
        assert receipt["prometheus_query"]["selected_results"][0]["api_response"]["data"]["resultType"] == "matrix"
        assert receipt["exporter_exposition"]["source_url"] == EXPORTER_URL + "/metrics"
        assert receipt["exporter_exposition"]["port_forward"]["target_pod_uid"] == EXPORTER_UID
        assert len(receipt["exporter_exposition"]["selected_lines"]) == 1
        serialized = rp.read_text()
        assert "UNSELECTED_FIXTURE_METRIC" not in serialized and "synthetic_secret" not in serialized
        assert "fixture-only-model" not in serialized and "fixture-only-hostname" not in serialized
        try:
            adapter.checked_url("http://127.0.0.1:9/?token=synthetic", "test URL")
        except adapter.CaptureError:
            rejected = True
        else:
            rejected = False
        assert rejected
    print('{"status":"passed","evidence_kind":"synthetic_regression","non_evidence":true,"checks":5}')


if __name__ == "__main__":
    run()
