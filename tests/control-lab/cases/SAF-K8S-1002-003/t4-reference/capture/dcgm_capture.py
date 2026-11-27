#!/usr/bin/env python3
"""Bounded loopback-only DCGM evidence adapter; no Kubernetes or cloud client."""
from __future__ import annotations

import argparse
import hashlib
import json
import ipaddress
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MAX_INPUT = 1_000_000
MAX_HTTP = 4_000_000
TIMEOUT = 8
DEFAULT_METRICS = {
    "DCGM_FI_DEV_GPU_UTIL": "percent",
    "DCGM_FI_DEV_FB_USED": "MiB",
    "DCGM_FI_DEV_FB_FREE": "MiB",
    "DCGM_FI_DEV_GPU_TEMP": "Celsius",
    "DCGM_FI_DEV_POWER_USAGE": "Watts",
}
URL = re.compile(r"^http://127\.0\.0\.1:([0-9]{1,5})/?$")
METRIC = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+([^\s]+))?$")
LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"\s*(?:,|$)')
SAMPLE_LABELS = {"UUID", "gpu", "namespace", "pod", "container", "pod_uid", "job", "instance"}


class CaptureError(ValueError):
    pass


def need(ok, msg):
    if not ok:
        raise CaptureError(msg)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def timestamp(value, field):
    need(isinstance(value, str), f"{field} must be UTC ISO text")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CaptureError(f"invalid {field}") from exc
    need(dt.tzinfo is not None and dt.utcoffset().total_seconds() == 0, f"{field} must be UTC")
    return dt.astimezone(timezone.utc).timestamp()


def read_json(path):
    raw = Path(path).read_bytes()
    need(len(raw) <= MAX_INPUT, f"input exceeds {MAX_INPUT} bytes")
    try:
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    except json.JSONDecodeError as exc:
        raise CaptureError(f"invalid JSON in {Path(path).name}") from exc


def write_json(path, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    Path(path).write_text(data, encoding="utf-8")


def checked_url(value, field):
    need(isinstance(value, str) and URL.fullmatch(value),
         f"{field} must be an explicit http://127.0.0.1:<port> URL without path, credentials, query, or fragment")
    port = int(URL.fullmatch(value).group(1))
    need(1 <= port <= 65535, f"{field} port is invalid")
    return f"http://127.0.0.1:{port}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CaptureError("HTTP redirect rejected")


def http_get(url, accept):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={"Accept": accept}, method="GET")
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            need(response.status == 200, f"HTTP status {response.status}")
            body = response.read(MAX_HTTP + 1)
    except urllib.error.HTTPError as exc:
        raise CaptureError(f"HTTP request rejected with status {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CaptureError(f"bounded loopback request failed: {type(exc).__name__}") from exc
    need(len(body) <= MAX_HTTP, "HTTP response exceeded size limit")
    return body


def parse_labels(raw):
    labels, pos = {}, 0
    while pos < len(raw):
        match = LABEL.match(raw, pos)
        need(match is not None, "invalid exposition label syntax")
        key, encoded = match.groups()
        need(key not in labels, "duplicate exposition label")
        try:
            labels[key] = json.loads('"' + encoded + '"')
        except json.JSONDecodeError as exc:
            raise CaptureError("invalid exposition label escape") from exc
        pos = match.end()
    return labels


def selected_lines(body, metrics, identity):
    try:
        lines = body.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CaptureError("exporter exposition is not UTF-8") from exc
    found = {name: [] for name in metrics}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = METRIC.fullmatch(line)
        if not match or match.group(1) not in found:
            continue
        name, label_text, value_text, sample_ms = match.groups()
        try:
            labels = parse_labels(label_text or "")
            value = float(value_text)
            need(math.isfinite(value), "non-finite metric value")
            if sample_ms is not None:
                need(math.isfinite(float(sample_ms)), "non-finite metric timestamp")
        except ValueError as exc:
            raise CaptureError("invalid selected metric sample") from exc
        if all(labels.get(k) == v for k, v in identity.items()):
            safe_labels = {k: v for k, v in labels.items() if k in SAMPLE_LABELS}
            encoded = ",".join(f'{k}="{prom_escape(str(safe_labels[k]))}"' for k in sorted(safe_labels))
            found[name].append(f"{name}{{{encoded}}} {value_text}" + (f" {sample_ms}" if sample_ms else ""))
    for name, samples in found.items():
        need(len(samples) == 1, f"expected exactly one selected exporter sample for {name}")
    return [found[name][0] for name in metrics]


def prom_target(prom_url, expected):
    url = prom_url + "/api/v1/targets?state=active"
    raw = http_get(url, "application/json")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CaptureError("invalid Prometheus target response") from exc
    need(doc.get("status") == "success" and isinstance(doc.get("data", {}).get("activeTargets"), list),
         "Prometheus target API did not return active target list")
    matches = []
    for target in doc["data"]["activeTargets"]:
        labels = target.get("labels", {})
        if labels.get("job") == expected["job"] and labels.get("instance") == expected["instance"]:
            matches.append(target)
    need(len(matches) == 1, "expected exactly one active Prometheus target for job/instance")
    target = matches[0]
    need(target.get("health") == "up", "recorded exporter target is not healthy")
    need(target.get("scrapeUrl") == expected["scrape_url"], "target scrape URL differs from explicit capture")
    expected_discovered = {
        "__meta_kubernetes_namespace": expected["namespace"],
        "__meta_kubernetes_pod_name": expected["pod"],
        "__meta_kubernetes_pod_uid": expected["pod_uid"],
        "__meta_kubernetes_pod_node_name": expected["node"],
        "__meta_kubernetes_pod_ip": expected["pod_ip"],
    }
    discovered = target.get("discoveredLabels", {})
    need(all(discovered.get(k) == v for k, v in expected_discovered.items()),
         "Prometheus discovered target identity differs from exporter Pod capture")
    labels = target.get("labels", {})
    need(labels.get("job") == expected["job"] and labels.get("instance") == expected["instance"],
         "Prometheus target final labels differ from explicit job/instance")
    return {
        "active": {"health": "up", "scrape_url": target["scrapeUrl"],
                   "captured_at_utc": utc_now(), "last_scrape_utc": target.get("lastScrape"),
                   "labels": {"job": labels["job"], "instance": labels["instance"]},
                   "discovered_labels": expected_discovered},
        "target": {"namespace": expected["namespace"], "pod": expected["pod"],
                   "pod_uid": expected["pod_uid"], "node": expected["node"],
                   "pod_ip": expected["pod_ip"], "port": expected["port"],
                   "job": expected["job"], "instance": expected["instance"], "up": True,
                   "captured_at_utc": utc_now(),
                   "scrape_interval_seconds": expected["scrape_interval_seconds"]},
    }


def prom_query(prom_url, metric, identity, start, end, window):
    matchers = ",".join(f'{key}="{prom_escape(value)}"' for key, value in identity.items())
    query = f"{metric}{{{matchers}}}[{window}s]"
    params = urllib.parse.urlencode({"query": query, "time": end})
    raw = http_get(prom_url + "/api/v1/query?" + params, "application/json")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CaptureError("invalid Prometheus query response") from exc
    need(doc.get("status") == "success" and doc.get("data", {}).get("resultType") == "matrix",
         f"Prometheus range-vector query for {metric} did not return a successful matrix")
    result = doc.get("data", {}).get("result")
    need(isinstance(result, list) and result, f"Prometheus returned no series for {metric}")
    # Retain only the exact selected series, while preserving standard API shape.
    for item in result:
        labels = item.get("metric", {})
        for key, value in identity.items():
            need(labels.get(key) == value, f"Prometheus {metric} returned a mismatched {key}")
    need(len(result) == 1, f"Prometheus query for {metric} was not uniquely scoped")
    labels = result[0].get("metric", {})
    need(labels.get("__name__") == metric, f"Prometheus response metric name mismatch for {metric}")
    need(set(result[0]) <= {"metric", "values"} and isinstance(result[0].get("values"), list),
         "Prometheus returned unapproved series fields")
    safe_result = [{"metric": {k: v for k, v in labels.items() if k in SAMPLE_LABELS | {"__name__"}},
                    "values": result[0]["values"]}]
    return query, {"status": "success", "data": {"resultType": "matrix", "result": safe_result}}


def prom_escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def validate_inputs(inputs):
    need(inputs.get("schema") == "saf-k8s-dcgm-capture-input-v1", "unsupported input schema")
    need(inputs.get("evidence_kind") in ("sanitized_host_capture", "synthetic_regression"), "evidence_kind required")
    if inputs["evidence_kind"] == "synthetic_regression":
        need(inputs.get("non_evidence") is True, "synthetic input must say non_evidence true")
    else:
        need(inputs.get("non_evidence") is not True, "host input cannot be marked non-evidence")
    metrics = inputs.get("selected_fields")
    need(isinstance(metrics, list) and 1 <= len(metrics) <= 8, "selected_fields must contain 1..8 fields")
    names = []
    for field in metrics:
        need(isinstance(field, dict) and field.get("metric") in DEFAULT_METRICS,
             "metric is outside the fixed NVIDIA shipped-default allowlist")
        names.append(field["metric"])
    need(len(set(names)) == len(names), "duplicate selected metric")
    start = timestamp(inputs.get("observation_start_utc"), "observation_start_utc")
    max_window = inputs.get("max_observation_seconds")
    need(isinstance(max_window, int) and 1 <= max_window <= 300, "max_observation_seconds must be 1..300")
    return names, start, max_window


def project(obj, keys, where, optional=()):
    need(isinstance(obj, dict), f"{where} must be an object")
    need(set(obj) <= set(keys), f"{where} contains unapproved fields")
    need(set(keys) - set(optional) <= set(obj), f"{where} is missing required fields")
    return {key: obj[key] for key in keys if key in obj}


def sanitize_inputs(inputs):
    # Explicit allowlists prevent unrelated annotations, labels, env, and
    # topology from leaking into a retained evidence receipt.
    out = {"capture_id": inputs.get("capture_id", "operator-supplied"),
           "observation_start_utc": inputs["observation_start_utc"],
           "host": project(inputs["host"], ("hostname", "os", "architecture"), "host"),
           "hardware": project(inputs["hardware"], ("gpu_uuid", "model", "category", "classification_basis"),
                               "hardware", optional=("classification_basis",)),
           "versions": project(inputs["versions"], ("driver", "container_runtime", "device_plugin", "kubelet",
                               "kubernetes", "dcgm", "exporter_version", "exporter_image_digest"), "versions"),
           "compatibility_assessment": project(inputs["compatibility_assessment"],
               ("status", "driver", "dcgm", "exporter_version", "official_sources", "reviewed_at_utc"),
               "compatibility_assessment"),
           "pod_before": project(inputs["pod_before"], ("namespace", "name", "uid", "container", "node",
               "phase", "gpu_request", "captured_at_utc"), "pod_before"),
           "exporter_pod": project(inputs["exporter_pod"], ("namespace", "name", "uid", "node", "pod_ip",
               "phase", "captured_at_utc"), "exporter_pod"),
           "port_forward": project(inputs["port_forward"], ("mode", "target_namespace", "target_pod",
               "target_pod_uid", "remote_port", "local_port", "captured_at_utc"), "port_forward"),
           "node": project(inputs["node"], ("name", "uid", "allocatable", "captured_at_utc"), "node"),
           "selected_fields": [],
           "max_sample_skew_seconds": inputs["max_sample_skew_seconds"]}
    need(set(inputs["node"]["allocatable"]) == {"nvidia.com/gpu"},
         "node allocatable capture must contain only nvidia.com/gpu")
    pod_resource = inputs["pod_resources"]
    need(set(pod_resource) == {"captured_at_utc", "entries"}, "pod_resources contains unapproved fields")
    before = out["pod_before"]
    entries = [entry for entry in pod_resource["entries"] if entry.get("namespace") == before["namespace"]
               and entry.get("pod") == before["name"] and entry.get("container") == before["container"]]
    need(len(entries) == 1, "PodResources capture must resolve exactly one case workload entry")
    entry = project(entries[0], ("namespace", "pod", "container", "resource_name", "device_ids"), "PodResources entry")
    out["pod_resources"] = {"captured_at_utc": pod_resource["captured_at_utc"], "entries": [entry]}
    for field in inputs["selected_fields"]:
        need(set(field) == {"metric", "support"}, "selected field must contain only metric and support")
        out["selected_fields"].append({"metric": field["metric"], "support": project(field["support"],
            ("status", "device_model", "dcgm", "exporter_version", "official_sources", "unit"),
            "metric support")})
    return out


def collect(args):
    inputs, input_hash = read_json(args.inputs)
    metrics, start, max_window = validate_inputs(inputs)
    clean = sanitize_inputs(inputs)
    exporter_url = checked_url(args.exporter_url, "exporter URL")
    prom_url = checked_url(args.prometheus_url, "Prometheus URL")
    before = inputs.get("pod_before", {})
    target_expected = inputs.get("exporter_target", {})
    need(set(target_expected) == {"namespace", "pod", "pod_uid", "node", "pod_ip", "port", "job", "instance",
                                   "scrape_url", "scrape_interval_seconds"},
         "exporter_target must contain only documented identity and scrape fields")
    for key in ("namespace", "name", "uid", "container", "node", "gpu_request"):
        need(before.get(key), f"pod_before.{key} is required")
    for key in ("namespace", "pod", "pod_uid", "node", "pod_ip", "port", "job", "instance", "scrape_url", "scrape_interval_seconds"):
        need(target_expected.get(key), f"exporter_target.{key} is required")
    exporter_pod = clean["exporter_pod"]
    need(target_expected["namespace"] == exporter_pod["namespace"] and target_expected["pod"] == exporter_pod["name"]
         and target_expected["pod_uid"] == exporter_pod["uid"] and target_expected["node"] == exporter_pod["node"]
         and target_expected["pod_ip"] == exporter_pod["pod_ip"],
         "exporter target identity does not match supplied exporter Pod API capture")
    pf = clean["port_forward"]
    need(pf["mode"] == "kubectl-port-forward" and pf["target_namespace"] == exporter_pod["namespace"]
         and pf["target_pod"] == exporter_pod["name"] and pf["target_pod_uid"] == exporter_pod["uid"]
         and pf["remote_port"] == target_expected["port"] and 1 <= int(pf["local_port"]) <= 65535,
         "explicit port-forward capture does not bind exact exporter Pod/port")
    target_ip = str(ipaddress.IPv4Address(target_expected["pod_ip"]))
    need(isinstance(target_expected["port"], int) and 1 <= target_expected["port"] <= 65535,
         "exporter target port must be an integer TCP port")
    need(target_expected["scrape_url"] == f"http://{target_ip}:{target_expected['port']}/metrics",
         "scrape URL must exactly bind captured exporter Pod IPv4 and port")
    target_result = prom_target(prom_url, target_expected)
    identity = {"UUID": inputs["hardware"]["gpu_uuid"], "namespace": before["namespace"],
                "pod": before["name"], "container": before["container"]}
    body = http_get(exporter_url + "/metrics", "text/plain; version=0.0.4")
    direct_at = utc_now()
    direct = {"captured_at_utc": direct_at, "source_url": exporter_url + "/metrics",
              "port_forward": clean["port_forward"],
              "selected_lines": selected_lines(body, metrics, identity)}
    need(direct["source_url"] == f"http://127.0.0.1:{pf['local_port']}/metrics",
         "direct scrape URL does not match explicit port-forward local port")
    end = timestamp(direct_at, "direct sample time")
    need(end >= start and end - start <= max_window, "capture exceeded explicit observation window")
    max_skew = float(inputs["max_sample_skew_seconds"])
    window_seconds = int(min(end - start, 2 * max_skew))
    need(window_seconds >= 1, "observation interval is too short for a bounded range selector")
    prom_queries = []
    for metric in metrics:
        query, response = prom_query(prom_url, metric, {
            "UUID": identity["UUID"], "namespace": identity["namespace"], "pod": identity["pod"],
            "container": identity["container"], "job": target_expected["job"],
            "instance": target_expected["instance"]}, start, end, window_seconds)
        prom_queries.append({"metric": metric, "range_vector_query": query, "api_response": response})
    collection = {
        "schema": "saf-k8s-dcgm-collection-v1", "evidence_kind": inputs["evidence_kind"],
        "non_evidence": inputs.get("non_evidence") is True,
        "source_hashes": {"inputs_sha256": input_hash},
        "inputs": clean,
        "observation_interval": {"start_utc": inputs["observation_start_utc"], "end_utc": direct_at},
        "exporter_pod": clean["exporter_pod"], "exporter_target": target_result["target"],
        "prometheus_active_target": target_result["active"], "exporter_exposition": direct,
        "port_forward": clean["port_forward"],
        "prometheus_query": {"range_start_utc": inputs["observation_start_utc"],
            "range_end_utc": direct_at, "evaluated_at_utc": direct_at,
            "window_seconds": window_seconds, "selected_results": prom_queries},
    }
    write_json(args.output, collection)


def finalize(args):
    collection, coll_hash = read_json(args.collection)
    raw_after, after_hash = read_json(args.pod_after)
    need(collection.get("schema") == "saf-k8s-dcgm-collection-v1", "unsupported collection schema")
    need(raw_after.get("schema") == "saf-k8s-dcgm-pod-after-v1", "unsupported after-Pod schema")
    after = project(raw_after, ("schema", "namespace", "name", "uid", "container", "node",
                       "phase", "gpu_request", "captured_at_utc"), "pod_after")
    after.pop("schema", None)
    inputs = collection["inputs"]
    before = inputs["pod_before"]
    for key in ("namespace", "name", "uid", "container", "node", "gpu_request"):
        need(after.get(key) == before.get(key), f"Pod after identity/request mismatch for {key}")
    need(timestamp(before["captured_at_utc"], "pod_before time") <= timestamp(collection["observation_interval"]["start_utc"], "window start"),
         "pod_before does not bracket observation window")
    need(timestamp(after["captured_at_utc"], "pod_after time") >= timestamp(collection["observation_interval"]["end_utc"], "window end"),
         "pod_after does not bracket collection")
    result = {
        "schema": "saf-k8s-dcgm-hardware-receipt-v1",
        "evidence_kind": collection["evidence_kind"],
        "non_evidence": collection["non_evidence"],
        "capture_id": inputs.get("capture_id", "operator-supplied"),
        "source_hashes": {**collection["source_hashes"], "collection_sha256": coll_hash,
                          "pod_after_sha256": after_hash},
        "observation_interval": collection["observation_interval"],
        "host": inputs["host"], "hardware": inputs["hardware"], "versions": inputs["versions"],
        "compatibility_assessment": inputs["compatibility_assessment"],
        "pod_before": before, "pod_after": after, "node": inputs["node"],
        "pod_resources": inputs["pod_resources"], "exporter_pod": collection["exporter_pod"],
        "exporter_target": collection["exporter_target"],
        "prometheus_active_target": collection["prometheus_active_target"],
        "max_sample_skew_seconds": inputs["max_sample_skew_seconds"],
        "selected_fields": inputs["selected_fields"],
        "exporter_exposition": collection["exporter_exposition"],
        "prometheus_query": collection["prometheus_query"],
    }
    write_json(args.output, result)


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--inputs", required=True)
    c.add_argument("--exporter-url", required=True)
    c.add_argument("--prometheus-url", required=True)
    c.add_argument("--output", required=True)
    f = sub.add_parser("finalize")
    f.add_argument("--collection", required=True)
    f.add_argument("--pod-after", required=True)
    f.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect":
            collect(args)
        else:
            finalize(args)
    except (OSError, CaptureError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"status": "captured", "output": Path(args.output).name}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
