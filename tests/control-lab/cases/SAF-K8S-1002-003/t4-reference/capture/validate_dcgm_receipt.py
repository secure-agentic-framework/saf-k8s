#!/usr/bin/env python3
"""Offline consistency checks for sanitized DCGM hardware captures.

This validates joins and sample shape. It cannot authenticate capture provenance,
certify NVIDIA compatibility, or turn synthetic data into hardware evidence.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+([^\s]+))?$")
_LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"\s*(?:,|$)')
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_K8S_UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)


class ReceiptError(ValueError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def _get(obj, key, where):
    _need(isinstance(obj, dict) and key in obj, f"missing {where}.{key}")
    return obj[key]


def _utc(value, where):
    _need(isinstance(value, str), f"{where} must be an ISO UTC timestamp")
    # Prometheus and the Go PodResources client emit RFC 3339 timestamps
    # with up to nine fractional digits. Python 3.9/3.10 parse microseconds.
    microseconds = re.sub(r"\.(\d+)(?=Z$|[+-]\d{2}:\d{2}$)",
                          lambda match: "." + match[1][:6].ljust(6, "0"), value)
    try:
        parsed = datetime.fromisoformat(microseconds.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReceiptError(f"invalid timestamp at {where}") from exc
    _need(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0,
          f"{where} must be UTC")
    return parsed.astimezone(timezone.utc).timestamp()


def _finite(value, where):
    _need(not isinstance(value, bool), f"{where} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ReceiptError(f"{where} must be numeric") from exc
    _need(math.isfinite(number), f"{where} must be finite")
    return number


def _labels(raw, where):
    labels = {}
    pos = 0
    while pos < len(raw):
        match = _LABEL.match(raw, pos)
        _need(match is not None, f"invalid Prometheus label syntax at {where}")
        key, encoded = match.groups()
        _need(key not in labels, f"duplicate label {key} at {where}")
        try:
            value = json.loads('"' + encoded + '"')
        except json.JSONDecodeError as exc:
            raise ReceiptError(f"invalid escaped label at {where}") from exc
        labels[key] = value
        pos = match.end()
    return labels


def _exporter_samples(capture):
    exposition = _get(capture, "exporter_exposition", "capture")
    observed = _utc(_get(exposition, "captured_at_utc", "exporter_exposition"),
                    "exporter_exposition.captured_at_utc")
    body = _get(exposition, "selected_lines", "exporter_exposition")
    _need(isinstance(body, list) and body, "exporter_exposition.selected_lines must be nonempty")
    source_url = _get(exposition, "source_url", "exporter_exposition")
    _need(isinstance(source_url, str), "exporter_exposition.source_url must identify the direct fetch")
    samples = {}
    for index, line in enumerate(body):
        _need(isinstance(line, str) and not line.startswith("#"),
              f"selected_lines[{index}] must be a Prometheus sample line")
        match = _SAMPLE.fullmatch(line.strip())
        _need(match is not None, f"invalid Prometheus sample line {index}")
        metric, label_text, value_text, timestamp_text = match.groups()
        labels = _labels(label_text or "", f"selected_lines[{index}]")
        value = _finite(value_text, f"selected_lines[{index}].value")
        sample_time = observed if timestamp_text is None else float(timestamp_text) / 1000.0
        _need(math.isfinite(sample_time), f"selected_lines[{index}] timestamp must be finite")
        samples.setdefault(metric, []).append({"labels": labels, "value": value,
                                               "timestamp": sample_time})
    return samples


def _prom_samples(capture, metric, direct_timestamp, max_skew):
    query = _get(capture, "prometheus_query", "capture")
    start = _utc(_get(query, "range_start_utc", "prometheus_query"), "prometheus_query.range_start_utc")
    end = _utc(_get(query, "range_end_utc", "prometheus_query"), "prometheus_query.range_end_utc")
    _need(start <= end, "Prometheus observation interval is reversed")
    evaluated_at = _utc(_get(query, "evaluated_at_utc", "prometheus_query"),
                        "prometheus_query.evaluated_at_utc")
    _need(start <= evaluated_at <= end,
          "Prometheus instant-query evaluation is outside the observation interval")
    window = _finite(_get(query, "window_seconds", "prometheus_query"),
                     "prometheus_query.window_seconds")
    _need(0 < window <= max_skew * 2,
          "Prometheus range-vector window must be positive and bounded")
    records = _get(query, "selected_results", "prometheus_query")
    _need(isinstance(records, list), "prometheus_query.selected_results must be a list")
    matched = [record for record in records if record.get("metric") == metric]
    _need(len(matched) == 1, f"{metric} requires exactly one Prometheus selected result record")
    record = matched[0]
    expression = _get(record, "range_vector_query", f"Prometheus result {metric}")
    _need(isinstance(expression, str) and metric in expression and "[" in expression
          and "]" in expression, f"{metric} query must be a bounded range-vector selector")
    response = _get(record, "api_response", f"Prometheus result {metric}")
    _need(response.get("status") == "success", f"{metric} Prometheus API response is not successful")
    data = _get(response, "data", f"{metric} Prometheus API response")
    _need(data.get("resultType") == "matrix",
          f"{metric} instant range-vector query must return a matrix")
    result = _get(data, "result", f"{metric} Prometheus API response.data")
    _need(isinstance(result, list) and len(result) == 1,
          f"{metric} Prometheus response must contain exactly one selected series")
    item = result[0]
    labels = _get(item, "metric", f"{metric} Prometheus result[0]")
    _need(labels.get("__name__") == metric,
          f"{metric} Prometheus series does not identify the selected metric")
    values = _get(item, "values", f"{metric} Prometheus result[0]")
    _need(isinstance(values, list) and values,
          f"{metric} range-vector result has no actual scrape samples")
    samples = []
    for index, pair in enumerate(values):
        _need(isinstance(pair, list) and len(pair) == 2,
              f"{metric} sample {index} must be [scrape_timestamp,value]")
        timestamp = _finite(pair[0], f"{metric} sample {index}.timestamp")
        value = _finite(pair[1], f"{metric} sample {index}.value")
        _need(start <= timestamp <= end,
              f"{metric} underlying scrape timestamp is outside the observation interval")
        samples.append({"labels": labels, "value": value, "timestamp": timestamp})
    near = [sample for sample in samples
            if abs(sample["timestamp"] - direct_timestamp) <= max_skew]
    _need(bool(near), f"{metric} has no actual Prometheus scrape sample near the direct exporter capture")
    near.sort(key=lambda sample: abs(sample["timestamp"] - direct_timestamp))
    if len(near) > 1:
        first_skew = abs(near[0]["timestamp"] - direct_timestamp)
        second_skew = abs(near[1]["timestamp"] - direct_timestamp)
        _need(first_skew < second_skew, f"{metric} nearest Prometheus scrape sample is ambiguous")
    return near[0]


def validate(capture):
    _need(isinstance(capture, dict), "capture root must be an object")
    _need(capture.get("schema") == "saf-k8s-dcgm-hardware-receipt-v1", "unsupported receipt schema")
    evidence_kind = _get(capture, "evidence_kind", "capture")
    _need(evidence_kind in ("sanitized_host_capture", "synthetic_regression"), "evidence_kind must be explicit")
    if evidence_kind == "synthetic_regression":
        _need(capture.get("non_evidence") is True, "synthetic regression must be marked non_evidence")
    else:
        _need(capture.get("non_evidence") is not True, "host capture cannot be marked synthetic")

    interval = _get(capture, "observation_interval", "capture")
    interval_start = _utc(_get(interval, "start_utc", "observation_interval"), "observation_interval.start_utc")
    interval_end = _utc(_get(interval, "end_utc", "observation_interval"), "observation_interval.end_utc")
    _need(interval_start <= interval_end, "observation interval is reversed")

    host = _get(capture, "host", "capture")
    for key in ("hostname", "os", "architecture"):
        _need(isinstance(_get(host, key, "host"), str) and host[key], f"host.{key} must be nonempty")
    hardware = _get(capture, "hardware", "capture")
    gpu_uuid = _get(hardware, "gpu_uuid", "hardware")
    model = _get(hardware, "model", "hardware")
    category = _get(hardware, "category", "hardware")
    _need(isinstance(gpu_uuid, str) and gpu_uuid.startswith("GPU-") and len(gpu_uuid) > 8,
          "hardware.gpu_uuid must be the observed GPU UUID")
    _need(isinstance(model, str) and model, "hardware.model must be observed and nonempty")
    _need(category in ("geforce_limited", "datacenter", "unresolved"), "hardware.category is invalid")
    _need(category != "unresolved", "unresolved device class cannot support a hardware acceptance claim")
    if re.search(r"geforce", model, re.I):
        _need(category == "geforce_limited", "GeForce model must remain classified as partial/limited")
    elif category == "datacenter":
        _need(bool(hardware.get("classification_basis")), "datacenter classification needs a recorded basis")

    versions = _get(capture, "versions", "capture")
    for key in ("driver", "container_runtime", "device_plugin", "kubelet", "kubernetes", "dcgm"):
        _need(isinstance(_get(versions, key, "versions"), str) and versions[key], f"versions.{key} must be exact observed version")
    exporter_version = _get(versions, "exporter_version", "versions")
    image_digest = _get(versions, "exporter_image_digest", "versions")
    _need(isinstance(exporter_version, str) and exporter_version, "versions.exporter_version must be exact")
    _need(isinstance(image_digest, str) and _SHA.fullmatch(image_digest), "versions.exporter_image_digest must be immutable sha256")
    compatibility = _get(capture, "compatibility_assessment", "capture")
    expected_status = "limited" if category == "geforce_limited" else "supported"
    _need(compatibility.get("status") == expected_status,
          "compatibility status must match the claimed hardware category")
    _need(compatibility.get("driver") == versions["driver"] and compatibility.get("dcgm") == versions["dcgm"]
          and compatibility.get("exporter_version") == exporter_version,
          "compatibility assessment does not bind the observed stack versions")
    sources = compatibility.get("official_sources")
    _need(isinstance(sources, list) and sources and all(
        isinstance(s, str) and s.startswith("https://docs.nvidia.com/") for s in sources),
        "compatibility_assessment needs official NVIDIA source URLs")
    _utc(_get(compatibility, "reviewed_at_utc", "compatibility_assessment"),
         "compatibility_assessment.reviewed_at_utc")

    before = _get(capture, "pod_before", "capture")
    after = _get(capture, "pod_after", "capture")
    pod_keys = ("namespace", "name", "uid", "container", "node")
    for key in pod_keys:
        _need(before.get(key) and after.get(key), f"Pod before/after require {key}")
        _need(before[key] == after[key], f"Pod {key} changed between captures")
    _need(bool(_K8S_UID.fullmatch(before["uid"])), "Pod UID must be a Kubernetes UUID")
    _need(before.get("gpu_request") == after.get("gpu_request"),
          "GPU resource request changed between Pod captures")
    before_time = _utc(_get(before, "captured_at_utc", "pod_before"), "pod_before.captured_at_utc")
    after_time = _utc(_get(after, "captured_at_utc", "pod_after"), "pod_after.captured_at_utc")
    _need(before_time <= interval_start and after_time >= interval_end,
          "Pod API captures must bracket the sample interval")
    _need(after.get("phase") in ("Running", "Succeeded"), "after Pod phase must show the assigned workload existed")
    requested = _get(after, "gpu_request", "pod_after")
    try:
        requested_count = int(requested)
    except (ValueError, TypeError) as exc:
        raise ReceiptError("pod_after.gpu_request must be an integer resource quantity") from exc
    _need(requested_count > 0, "workload must request a positive GPU quantity")

    node = _get(capture, "node", "capture")
    _need(node.get("name") == after["node"], "Node capture does not match workload node")
    _need(bool(_K8S_UID.fullmatch(node.get("uid", ""))), "Node UID must be a Kubernetes UUID")
    allocatable = _get(node, "allocatable", "node")
    try:
        allocatable_count = int(_get(allocatable, "nvidia.com/gpu", "node.allocatable"))
    except (ValueError, TypeError) as exc:
        raise ReceiptError("node.allocatable nvidia.com/gpu must be an integer") from exc
    _need(allocatable_count >= requested_count, "node GPU allocatable is below workload request")
    node_time = _utc(_get(node, "captured_at_utc", "node"), "node.captured_at_utc")
    _need(interval_start <= node_time <= interval_end, "Node allocatable observation is outside the sample interval")

    resources = _get(capture, "pod_resources", "capture")
    resource_time = _utc(_get(resources, "captured_at_utc", "pod_resources"), "pod_resources.captured_at_utc")
    _need(interval_start <= resource_time <= interval_end, "PodResources observation is outside the sample interval")
    entries = _get(resources, "entries", "pod_resources")
    matches = [e for e in entries if e.get("namespace") == after["namespace"]
               and e.get("pod") == after["name"] and e.get("container") == after["container"]]
    _need(len(matches) == 1, "PodResources must contain exactly one matching workload allocation")
    allocation = matches[0]
    _need(allocation.get("resource_name") == "nvidia.com/gpu", "PodResources allocation is not the NVIDIA GPU resource")
    device_ids = allocation.get("device_ids")
    _need(isinstance(device_ids, list) and len(device_ids) == requested_count,
          "PodResources device count does not match GPU request")
    _need(gpu_uuid in device_ids, "PodResources allocation does not map workload to captured GPU UUID")

    target = _get(capture, "exporter_target", "capture")
    for key in ("namespace", "pod", "pod_uid", "node", "pod_ip", "port", "job", "instance"):
        _need(target.get(key), f"exporter_target.{key} is required")
    _need(isinstance(target.get("port"), int) and not isinstance(target.get("port"), bool)
          and 1 <= target["port"] <= 65535, "exporter target port is invalid")
    _need(bool(_K8S_UID.fullmatch(target["pod_uid"])), "exporter target Pod UID must be a Kubernetes UUID")
    _need(target["node"] == after["node"], "exporter target is not on workload GPU node")
    _need(target.get("up") is True, "exporter target is not observed up")
    target_time = _utc(_get(target, "captured_at_utc", "exporter_target"), "exporter_target.captured_at_utc")
    _need(interval_start <= target_time <= interval_end, "exporter target observation is outside sample interval")
    scrape_interval = _finite(_get(target, "scrape_interval_seconds", "exporter_target"), "exporter_target.scrape_interval_seconds")
    max_skew = _finite(_get(capture, "max_sample_skew_seconds", "capture"), "max_sample_skew_seconds")
    _need(scrape_interval > 0 and 0 < max_skew <= scrape_interval * 2,
          "sample skew must be positive and no more than two scrape intervals")

    exporter_pod = _get(capture, "exporter_pod", "capture")
    pod_fields = {"namespace": "namespace", "pod": "name", "pod_uid": "uid",
                  "node": "node", "pod_ip": "pod_ip"}
    for target_key, pod_key in pod_fields.items():
        _need(target.get(target_key) == exporter_pod.get(pod_key),
              f"exporter target {target_key} does not match exporter Pod API capture")
    _need(exporter_pod.get("phase") == "Running", "exporter Pod API capture is not Running")
    exporter_pod_time = _utc(_get(exporter_pod, "captured_at_utc", "exporter_pod"),
                             "exporter_pod.captured_at_utc")
    _need(interval_start <= exporter_pod_time <= interval_end,
          "exporter Pod API observation is outside sample interval")
    port_forward = _get(_get(capture, "exporter_exposition", "capture"),
                        "port_forward", "exporter_exposition")
    source_url = _get(_get(capture, "exporter_exposition", "capture"),
                      "source_url", "exporter_exposition")
    _need(port_forward.get("mode") == "kubectl-port-forward",
          "direct exporter capture must identify its port-forward mechanism")
    for pf_key, pod_key in (("target_namespace", "namespace"),
                            ("target_pod", "pod"), ("target_pod_uid", "pod_uid")):
        _need(port_forward.get(pf_key) == target.get(pod_key),
              f"port-forward target {pf_key} does not bind the exporter Pod")
    _need(port_forward.get("remote_port") == target.get("port"),
          "port-forward remote port does not match the exporter target")
    local_port = port_forward.get("local_port")
    _need(isinstance(local_port, int) and not isinstance(local_port, bool)
          and 1 <= local_port <= 65535, "port-forward local_port is invalid")
    _need(source_url == f"http://127.0.0.1:{local_port}/metrics",
          "direct exporter source must be the exact IPv4 loopback port-forward URL")
    pf_time = _utc(_get(port_forward, "captured_at_utc", "exporter_exposition.port_forward"),
                   "exporter_exposition.port_forward.captured_at_utc")
    _need(interval_start <= pf_time <= interval_end,
          "port-forward identity observation is outside sample interval")
    active_target = _get(capture, "prometheus_active_target", "capture")
    _need(active_target.get("health") == "up", "Prometheus active-target observation is not up")
    active_labels = _get(active_target, "labels", "prometheus_active_target")
    discovered = _get(active_target, "discovered_labels", "prometheus_active_target")
    _need(active_labels.get("job") == target["job"]
          and active_labels.get("instance") == target["instance"],
          "Prometheus active target labels do not match the recorded target")
    discovery_bindings = {
        "__meta_kubernetes_namespace": target["namespace"],
        "__meta_kubernetes_pod_name": target["pod"],
        "__meta_kubernetes_pod_uid": target["pod_uid"],
        "__meta_kubernetes_pod_node_name": target["node"],
        "__meta_kubernetes_pod_ip": target["pod_ip"],
    }
    for key, expected in discovery_bindings.items():
        _need(discovered.get(key) == expected,
              f"Prometheus target discovery label {key} does not bind the exporter Pod")
    scrape_url = _get(active_target, "scrape_url", "prometheus_active_target")
    _need(isinstance(scrape_url, str), "prometheus active target scrape_url must be text")
    try:
        parsed_scrape_url = urlsplit(scrape_url)
        scrape_port = parsed_scrape_url.port
    except ValueError as exc:
        raise ReceiptError("prometheus active target scrape_url is malformed") from exc
    _need(parsed_scrape_url.scheme in ("http", "https")
          and parsed_scrape_url.hostname == target["pod_ip"]
          and scrape_port == target["port"],
          "Prometheus scrape URL does not match the exporter Pod IP and port")
    target_observed_at = _utc(_get(active_target, "captured_at_utc", "prometheus_active_target"),
                              "prometheus_active_target.captured_at_utc")
    last_scrape_at = _utc(_get(active_target, "last_scrape_utc", "prometheus_active_target"),
                          "prometheus_active_target.last_scrape_utc")
    _need(interval_start <= target_observed_at <= interval_end
          and interval_start <= last_scrape_at <= interval_end,
          "Prometheus target observation or last scrape is outside sample interval")

    direct = _exporter_samples(capture)
    prom_query = _get(capture, "prometheus_query", "capture")
    prom_start = _utc(_get(prom_query, "range_start_utc", "prometheus_query"), "prometheus_query.range_start_utc")
    prom_end = _utc(_get(prom_query, "range_end_utc", "prometheus_query"), "prometheus_query.range_end_utc")
    _need(prom_start == interval_start and prom_end == interval_end,
          "Prometheus query interval must equal the recorded observation interval")
    fields = _get(capture, "selected_fields", "capture")
    _need(isinstance(fields, list) and fields, "selected_fields must be a nonempty list")
    summaries = []
    seen = set()
    for spec in fields:
        metric = _get(spec, "metric", "selected_fields[]")
        _need(isinstance(metric, str) and _NAME.fullmatch(metric) and metric not in seen,
              "selected field names must be unique Prometheus metric identifiers")
        seen.add(metric)
        support = _get(spec, "support", f"selected_fields.{metric}")
        _need(support.get("status") == "supported", f"{metric} is not declared supported on this device/stack")
        _need(support.get("device_model") == model and support.get("dcgm") == versions["dcgm"]
              and support.get("exporter_version") == exporter_version,
              f"{metric} support assessment does not bind this device and stack")
        support_sources = support.get("official_sources")
        _need(isinstance(support_sources, list) and support_sources and all(
            isinstance(s, str) and s.startswith("https://docs.nvidia.com/") for s in support_sources),
            f"{metric} requires an official source basis")
        _need(isinstance(support.get("unit"), str) and support["unit"], f"{metric} requires a unit")
        direct_hits = direct.get(metric, [])
        _need(len(direct_hits) == 1, f"{metric} requires exactly one direct exporter sample")
        ds = direct_hits[0]
        ps = _prom_samples(capture, metric, ds["timestamp"], max_skew)
        dlabels, plabels = ds["labels"], ps["labels"]
        for labels, where in ((dlabels, "direct exporter"), (plabels, "Prometheus")):
            _need(labels.get("UUID") == gpu_uuid, f"{where} sample GPU UUID is not the allocated device")
            _need(labels.get("pod") == after["name"] and labels.get("namespace") == after["namespace"]
                  and labels.get("container") == after["container"],
                  f"{where} sample does not map to the exact workload Pod/container")
        _need(plabels.get("job") == target["job"] and plabels.get("instance") == target["instance"],
              "Prometheus series is not from the exact recorded exporter target")
        uid_direct_present = "pod_uid" in dlabels
        uid_prom_present = "pod_uid" in plabels
        if uid_direct_present or uid_prom_present:
            _need((not uid_direct_present or dlabels["pod_uid"] == after["uid"])
                  and (not uid_prom_present or plabels["pod_uid"] == after["uid"]),
                  "present Pod UID labels must match the exact workload UID")
        if uid_direct_present and uid_prom_present:
            binding = "direct_pod_uid_label"
        else:
            # The exact Pod API + PodResources join above supplies UID binding
            # when the selected supported exporter omits the optional UID label.
            binding = "pod_api_uid_plus_podresources_join"
        _need(interval_start <= ds["timestamp"] <= interval_end,
              f"{metric} direct sample is outside observation interval")
        skew = abs(ds["timestamp"] - ps["timestamp"])
        _need(skew <= max_skew, f"{metric} direct and Prometheus samples exceed allowed time skew")
        summaries.append({"metric": metric, "unit": support["unit"],
                          "direct_value": ds["value"], "prometheus_value": ps["value"],
                          "absolute_delta": abs(ds["value"] - ps["value"]),
                          "sample_skew_seconds": skew, "uid_binding": binding})

    # No vendor certification is inferred from a self-declared capture. This is
    # an offline consistency result; a human must review original host provenance.
    return {"status": "synthetic_non_evidence_pass" if evidence_kind == "synthetic_regression"
            else "consistent_capture_requires_provenance_review",
            "hardware_scope": "geforce_limited_partial" if category == "geforce_limited"
            else ("datacenter_claim_observed_but_not_vendor_certified" if category == "datacenter"
                  else "unresolved_device_class"),
            "workload_uid": after["uid"], "node": after["node"], "gpu_uuid": gpu_uuid,
            "exporter_target": target["instance"], "selected_sample_count": len(summaries),
            "samples": summaries,
            "limitations": ["offline consistency only; capture provenance and signatures are not authenticated",
                            "compatibility and field support declarations require human review against cited NVIDIA sources",
                            "no NVIDIA certification, fleet coverage, sustained monitoring, or production claim"]}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    args = parser.parse_args(argv)
    try:
        capture = json.loads(args.capture.read_text(encoding="utf-8"))
        result = validate(capture)
    except (OSError, json.JSONDecodeError, ReceiptError) as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
