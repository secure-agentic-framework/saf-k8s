#!/usr/bin/env python3
"""Capture one explicitly owned T4 workload and its local DCGM evidence.

This is a bounded, read-only evidence harness. It uses only an explicit kubeconfig,
fixed object names/selectors, a local PodResources List client, and two IPv4
loopback-only kubectl port-forwards to the case-owned exporter and Prometheus Pods.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

BASE = Path(__file__).resolve().parent
CAPTURE = BASE / "dcgm_capture.py"
VALIDATOR = BASE / "validate_dcgm_receipt.py"
PODRESOURCES = BASE / "podresources-list" / "podresources-list-linux-amd64"
WORKLOAD_NS = "saf-gpu-t4"
WORKLOAD_POD = "t4-vector-witness"
WORKLOAD_CONTAINER = "vector"
OBS_NS = "saf-gpu-observe"
EXPORTER_SELECTOR = (
    "app.kubernetes.io/name=dcgm-exporter,"
    "app.kubernetes.io/instance=dcgm-exporter,"
    "app.kubernetes.io/component=dcgm-exporter,"
    "saf-k8s.example/scrape=dcgm-t4"
)
PROM_SELECTOR = "app.kubernetes.io/name=saf-prometheus"
PLUGIN_NS = "kube-system"
PLUGIN_SELECTOR = "name=nvidia-device-plugin-ds"
GPU_RESOURCE = "nvidia.com/gpu"
PORTS = {"exporter_local": 19400, "exporter_remote": 9400,
         "prometheus_local": 19090, "prometheus_remote": 9090}
MAX_JSON = 2_000_000
MAX_TEXT = 128_000
UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
SHA = re.compile(r"sha256:[0-9a-f]{64}$")


class CaptureError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path):
    raw = path.read_bytes()
    if len(raw) > MAX_JSON:
        raise CaptureError(f"{path.name} exceeds the bounded JSON size")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CaptureError(f"invalid JSON in {path.name}") from exc


def adapter_failure(raw: bytes, label: str) -> str:
    """Return only the adapter's short, structured validation reason."""
    try:
        doc = json.loads(raw[:4096])
    except (json.JSONDecodeError, UnicodeDecodeError):
        return f"{label} failed with an unstructured result"
    reason = doc.get("reason") if isinstance(doc, dict) else None
    if not isinstance(reason, str) or not reason:
        return f"{label} failed with no structured reason"
    safe = "".join(ch for ch in reason if ch.isprintable())[:240]
    return f"{label} rejected the capture: {safe}"


def run_json(command: list[str], label: str, timeout: int = 12):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError(f"bounded {label} observation failed") from exc
    if result.returncode != 0:
        raise CaptureError(f"{label} observation failed (exit {result.returncode})")
    if len(result.stdout) > MAX_JSON:
        raise CaptureError(f"{label} response exceeded the size limit")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CaptureError(f"{label} returned invalid JSON") from exc


def kubectl(kubectl_bin: str, kubeconfig: Path, args: list[str], label: str):
    return run_json([kubectl_bin, "--kubeconfig", str(kubeconfig), "--request-timeout=8s", *args], label)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureError(message)


def get_container(pod: dict, container_name: str) -> tuple[dict, dict]:
    spec = [c for c in pod.get("spec", {}).get("containers", []) if c.get("name") == container_name]
    status = [c for c in pod.get("status", {}).get("containerStatuses", []) if c.get("name") == container_name]
    require(len(spec) == 1 and len(status) == 1, f"exact container {container_name} is not unique")
    return spec[0], status[0]


def pod_identity(pod: dict, namespace: str, container_name: str, expected_port: Optional[int] = None) -> dict:
    meta = pod.get("metadata", {})
    spec = pod.get("spec", {})
    status = pod.get("status", {})
    require(meta.get("namespace") == namespace and bool(meta.get("name")), "Pod namespace/name mismatch")
    require(bool(UID.fullmatch(meta.get("uid", ""))), "Pod UID is invalid")
    require(status.get("phase") == "Running", "selected Pod is not Running")
    require(bool(spec.get("nodeName")), "selected Pod has no assigned node")
    container_name = container_name
    container, container_status = get_container(pod, container_name)
    require(container_status.get("ready") is True, f"{container_name} container is not Ready")
    if expected_port is not None:
        ports = [p for p in container.get("ports", []) if p.get("containerPort") == expected_port]
        require(len(ports) == 1, f"{container_name} has no unique expected port {expected_port}")
    return {"namespace": namespace, "name": meta["name"], "uid": meta["uid"],
            "node": spec["nodeName"], "pod_ip": status.get("podIP"),
            "phase": status["phase"], "container": container_name,
            "image": container.get("image"), "image_id": container_status.get("imageID")}


def choose_one_ready(items: list[dict], namespace: str, container: str,
                     node: Optional[str] = None, port: Optional[int] = None) -> tuple[dict, dict]:
    candidates = []
    for pod in items:
        spec = pod.get("spec", {})
        if node is not None and spec.get("nodeName") != node:
            continue
        try:
            ident = pod_identity(pod, namespace, container, port)
        except CaptureError:
            continue
        candidates.append((pod, ident))
    require(len(candidates) == 1, f"expected one Ready {namespace}/{container} Pod on selected node")
    return candidates[0]


def local_nvidia_smi(expected_gpu_id: str) -> dict:
    cmd = ["nvidia-smi", "--query-gpu=uuid,name,driver_version", "--format=csv,noheader,nounits"]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError("bounded nvidia-smi identity read failed") from exc
    if result.returncode != 0 or len(result.stdout) > MAX_TEXT:
        raise CaptureError("nvidia-smi identity read failed")
    try:
        rows = list(csv.reader(result.stdout.decode("utf-8").splitlines(), skipinitialspace=True))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise CaptureError("nvidia-smi identity output is invalid") from exc
    matches = [row for row in rows if len(row) == 3 and row[0].strip() == expected_gpu_id]
    require(len(matches) == 1, "PodResources GPU UUID does not select exactly one nvidia-smi device")
    gpu, model, driver = (value.strip() for value in matches[0])
    require(model == "Tesla T4", f"selected device model is {model!r}, expected Tesla T4")
    require(driver == "580.178.04", "selected NVIDIA driver differs from reviewed R580 pin")
    return {"gpu_uuid": gpu, "model": model, "driver": driver, "raw_selected_row": matches[0]}


def start_forward(kubectl_bin: str, kubeconfig: Path, namespace: str, pod: str,
                  local_port: int, remote_port: int) -> tuple[subprocess.Popen, str]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        require(sock.connect_ex(("127.0.0.1", local_port)) != 0,
                f"required loopback port {local_port} is already occupied")
    command = [kubectl_bin, "--kubeconfig", str(kubeconfig), "-n", namespace,
               "port-forward", "--address=127.0.0.1", f"pod/{pod}",
               f"{local_port}:{remote_port}"]
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        raise CaptureError("could not start owned loopback port-forward") from exc
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise CaptureError("owned loopback port-forward exited before readiness")
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=0.25):
                return proc, utc_now()
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)
    raise CaptureError("owned loopback port-forward did not become ready in 12 seconds")


def stop_forward(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def read_review(path: Path) -> dict:
    review = read_json(path)
    require(review.get("schema") == "saf-k8s-t4-capture-review-v1", "unsupported review metadata")
    require(review.get("hardware_category") == "datacenter", "T4 capture must be explicitly classified as datacenter")
    expected = review.get("expected_stack", {})
    require(expected.get("driver") == "580.178.04" and expected.get("kubernetes") == "v1.36.6+k3s1"
            and expected.get("kubelet") == "v1.36.6+k3s1" and expected.get("dcgm") == "4.6.1"
            and expected.get("exporter_version") == "4.8.4" and expected.get("device_plugin_version") == "v0.20.2",
            "review metadata differs from the approved stack pins")
    require(expected.get("exporter_image_digest") == "sha256:804c17f67ab63e8a4dd5301546beefaa104129f833dae4a68f5ff7c4819f471b",
            "review metadata exporter digest differs from the pinned image")
    support = review.get("selected_fields", [])
    require([x.get("metric") for x in support] == ["DCGM_FI_DEV_GPU_UTIL", "DCGM_FI_DEV_FB_USED"],
            "review metadata must use exactly the two pinned selected fields")
    return review


def capture(args) -> dict:
    kubeconfig = Path(args.kubeconfig).expanduser()
    require(kubeconfig.is_absolute() and kubeconfig.is_file(), "--kubeconfig must be an existing absolute file")
    output_root = Path(args.output_root).resolve()
    require(output_root == BASE or BASE in output_root.parents,
            "output must remain under this private capture directory")
    review = read_review(Path(args.review))
    kubectl_bin = shutil.which("kubectl")
    require(kubectl_bin is not None, "kubectl is unavailable")
    require(platform.system() == "Linux" and platform.machine().lower() in ("x86_64", "amd64"),
            "capture must run on the isolated Linux x86-64 VM")
    require(PODRESOURCES.is_file(), "prebuilt Linux/amd64 PodResources client is missing")

    # Raw Kubernetes responses remain in memory; only narrow allowlisted projections are written.
    workload_obj = kubectl(kubectl_bin, kubeconfig,
        ["-n", WORKLOAD_NS, "get", "pod", WORKLOAD_POD, "-o", "json"], "workload Pod")
    pod_meta = workload_obj.get("metadata", {})
    pod_spec = workload_obj.get("spec", {})
    pod_status = workload_obj.get("status", {})
    require(pod_meta.get("namespace") == WORKLOAD_NS and pod_meta.get("name") == WORKLOAD_POD
            and bool(UID.fullmatch(pod_meta.get("uid", ""))), "workload Pod identity mismatch")
    require(pod_status.get("phase") == "Running" and bool(pod_spec.get("nodeName")),
            "workload Pod is not Running on a named node")
    workload_container, workload_container_status = get_container(workload_obj, WORKLOAD_CONTAINER)
    require(workload_container_status.get("ready") is True, "workload vector container is not Ready")
    gpu_request = workload_container.get("resources", {}).get("requests", {}).get(GPU_RESOURCE)
    require(str(gpu_request) == "1", "fixed workload must request exactly one nvidia.com/gpu")
    node_name = pod_spec["nodeName"]
    pod_before = {"namespace": WORKLOAD_NS, "name": WORKLOAD_POD, "uid": pod_meta["uid"],
                  "container": WORKLOAD_CONTAINER, "node": node_name, "phase": "Running",
                  "gpu_request": "1", "captured_at_utc": utc_now()}
    observation_start = utc_now()

    node_obj = kubectl(kubectl_bin, kubeconfig, ["get", "node", node_name, "-o", "json"], "Node")
    node_meta = node_obj.get("metadata", {})
    node_status = node_obj.get("status", {})
    node_info = node_status.get("nodeInfo", {})
    require(node_meta.get("name") == node_name and bool(UID.fullmatch(node_meta.get("uid", ""))),
            "Node identity mismatch")
    require(node_info.get("operatingSystem") == "linux", "selected Kubernetes node does not report Linux")
    require(node_info.get("kubeletVersion") == review["expected_stack"]["kubelet"],
            "Node kubelet version differs from reviewed pin")
    allocatable = node_status.get("allocatable", {}).get(GPU_RESOURCE)
    require(allocatable is not None and str(allocatable).isdigit() and int(allocatable) >= 1,
            "selected Node does not report at least one allocatable GPU")
    node_capture = {"name": node_name, "uid": node_meta["uid"],
                    "allocatable": {GPU_RESOURCE: str(allocatable)}, "captured_at_utc": utc_now()}

    version_obj = kubectl(kubectl_bin, kubeconfig, ["version", "-o", "json"], "Kubernetes version")
    server_version = version_obj.get("serverVersion", {}).get("gitVersion")
    require(server_version == review["expected_stack"]["kubernetes"],
            "Kubernetes API server version differs from reviewed pin")
    runtime_version = node_info.get("containerRuntimeVersion")
    require(isinstance(runtime_version, str) and runtime_version, "Node container runtime version is missing")

    exporter_list = kubectl(kubectl_bin, kubeconfig,
        ["-n", OBS_NS, "get", "pods", "-l", EXPORTER_SELECTOR, "-o", "json"], "DCGM exporter Pod list")
    exporter_obj, exporter_id = choose_one_ready(exporter_list.get("items", []), OBS_NS,
        "exporter", node_name, PORTS["exporter_remote"])
    exporter_ip = exporter_id.get("pod_ip")
    require(isinstance(exporter_ip, str) and "." in exporter_ip and ":" not in exporter_ip,
            "selected exporter Pod has no IPv4 Pod IP")
    exporter_image = exporter_id.get("image", "")
    exporter_image_id = exporter_id.get("image_id", "")
    pinned_exporter_digest = "@" + review["expected_stack"]["exporter_image_digest"]
    require(exporter_image.endswith(pinned_exporter_digest),
            "exporter image reference differs from the pinned immutable digest")
    require(exporter_image_id.endswith(pinned_exporter_digest),
            "exporter container imageID differs from pinned immutable digest")
    exporter_pod = {k: exporter_id[k] for k in ("namespace", "name", "uid", "node", "pod_ip", "phase")}
    exporter_pod["captured_at_utc"] = utc_now()
    target = {"namespace": OBS_NS, "pod": exporter_id["name"], "pod_uid": exporter_id["uid"],
              "node": node_name, "pod_ip": exporter_ip, "port": 9400, "job": "saf-t4-dcgm",
              "instance": f"{exporter_ip}:9400", "scrape_url": f"http://{exporter_ip}:9400/metrics",
              "scrape_interval_seconds": 5}

    prom_list = kubectl(kubectl_bin, kubeconfig,
        ["-n", OBS_NS, "get", "pods", "-l", PROM_SELECTOR, "-o", "json"], "Prometheus Pod list")
    prom_obj, prom_id = choose_one_ready(prom_list.get("items", []), OBS_NS, "prometheus", None, 9090)

    plugin_list = kubectl(kubectl_bin, kubeconfig,
        ["-n", PLUGIN_NS, "get", "pods", "-l", PLUGIN_SELECTOR, "-o", "json"], "device-plugin Pod list")
    plugin_obj, plugin_id = choose_one_ready(plugin_list.get("items", []), PLUGIN_NS,
        "nvidia-device-plugin-ctr", node_name, None)
    require("v0.20.2" in plugin_id.get("image", ""), "NVIDIA device-plugin image is not pinned v0.20.2")
    require(bool(SHA.search(plugin_id.get("image_id", ""))),
            "device-plugin container imageID has no immutable digest")

    # The PodResources API itself exposes Pod/container and device allocation, not UID/node.
    # This explicit local call records host and node context separately from its filtered allocation.
    try:
        pr_result = subprocess.run([str(PODRESOURCES), "--node-name", node_name,
            "--namespace", WORKLOAD_NS, "--pod", WORKLOAD_POD, "--container", WORKLOAD_CONTAINER,
            "--expected-device-count", "1"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError("bounded local PodResources capture failed") from exc
    if pr_result.returncode != 0 or len(pr_result.stdout) > MAX_JSON:
        raise CaptureError("local PodResources client rejected the exact allocation")
    try:
        podresources_raw = json.loads(pr_result.stdout)
    except json.JSONDecodeError as exc:
        raise CaptureError("local PodResources output is invalid") from exc
    require(podresources_raw.get("schema") == "saf-k8s-podresources-source-v1"
            and podresources_raw.get("host_os") == "linux"
            and podresources_raw.get("host_architecture") == "amd64"
            and podresources_raw.get("node_name") == node_name
            and podresources_raw.get("hostname") == node_name,
            "PodResources local host/node identity mismatch")
    require(len(podresources_raw.get("entries", [])) == 1, "PodResources did not yield one exact allocation")
    allocation = podresources_raw["entries"][0]
    gpu_ids = allocation.get("device_ids", [])
    require(allocation.get("namespace") == WORKLOAD_NS and allocation.get("pod") == WORKLOAD_POD
            and allocation.get("container") == WORKLOAD_CONTAINER and allocation.get("resource_name") == GPU_RESOURCE
            and len(gpu_ids) == 1, "PodResources allocation does not match exact workload request")
    smi = local_nvidia_smi(gpu_ids[0])
    require(smi["driver"] == review["expected_stack"]["driver"], "nvidia-smi driver differs from reviewed pin")

    prom_port_forward = None
    exporter_port_forward = None
    output_root.mkdir(parents=True, exist_ok=True)
    capture_dir = output_root / ("capture-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    capture_dir.mkdir(mode=0o700)
    try:
        exporter_port_forward, exporter_pf_time = start_forward(kubectl_bin, kubeconfig, OBS_NS,
            exporter_id["name"], PORTS["exporter_local"], PORTS["exporter_remote"])
        prom_port_forward, prom_pf_time = start_forward(kubectl_bin, kubeconfig, OBS_NS,
            prom_id["name"], PORTS["prometheus_local"], PORTS["prometheus_remote"])
        # Allow two configured five-second scrape cycles so the exact active target
        # and at least one real scrape sample fall inside this bounded interval.
        time.sleep(2 * target["scrape_interval_seconds"])

        host_meta = {"hostname": podresources_raw["hostname"], "os": "linux", "architecture": "amd64"}
        hardware = {"gpu_uuid": smi["gpu_uuid"], "model": smi["model"],
                    "category": review["hardware_category"],
                    "classification_basis": review["classification_basis"]}
        versions = {"driver": smi["driver"], "container_runtime": runtime_version,
                    "device_plugin": review["expected_stack"]["device_plugin_version"],
                    "kubelet": node_info["kubeletVersion"], "kubernetes": server_version,
                    "dcgm": review["expected_stack"]["dcgm"],
                    "exporter_version": review["expected_stack"]["exporter_version"],
                    "exporter_image_digest": review["expected_stack"]["exporter_image_digest"]}
        compat = review["compatibility_assessment"]
        require(compat.get("driver") == versions["driver"] and compat.get("dcgm") == versions["dcgm"]
                and compat.get("exporter_version") == versions["exporter_version"],
                "compatibility review does not match observed stack")
        selected_fields = review["selected_fields"]
        for field in selected_fields:
            require(field.get("support", {}).get("device_model") == smi["model"]
                    and field["support"].get("dcgm") == versions["dcgm"]
                    and field["support"].get("exporter_version") == versions["exporter_version"],
                    "metric support review does not match observed hardware/stack")

        # Persist narrow source projections; full Kubernetes objects are not written.
        write_json(capture_dir / "workload-pod-before.json", pod_before)
        write_json(capture_dir / "node.json", node_capture)
        write_json(capture_dir / "podresources.raw.json", podresources_raw)
        write_json(capture_dir / "nvidia-smi-selected.json", {k: v for k, v in smi.items() if k != "raw_selected_row"})
        write_json(capture_dir / "software-provenance.json", {
            "captured_at_utc": utc_now(),
            "kubernetes_server_version": server_version,
            "node_name": node_name,
            "node_uid": node_meta["uid"],
            "node_kubelet_version": node_info["kubeletVersion"],
            "node_container_runtime_version": runtime_version,
            "exporter_pod": exporter_pod,
            "exporter_container": "exporter",
            "exporter_image": exporter_image,
            "exporter_image_id": exporter_image_id,
            "device_plugin_namespace": PLUGIN_NS,
            "device_plugin_pod": plugin_id["name"],
            "device_plugin_pod_uid": plugin_id["uid"],
            "device_plugin_container": "nvidia-device-plugin-ctr",
            "device_plugin_image": plugin_id["image"],
            "device_plugin_image_id": plugin_id["image_id"],
            "podresources_node_socket": {k: podresources_raw[k] for k in
                ("host_os", "host_architecture", "hostname", "node_name", "socket_path", "api_version", "api", "kubelet_module")},
        })
        write_json(capture_dir / "capture-review.json", review)

        # The input file is deliberately built from the independent narrow captures and fixed review.
        input_obj = {
            "schema": "saf-k8s-dcgm-capture-input-v1", "evidence_kind": "sanitized_host_capture",
            "capture_id": review["capture_id"], "observation_start_utc": observation_start,
            "max_observation_seconds": review["max_observation_seconds"],
            "host": host_meta, "hardware": hardware, "versions": versions,
            "compatibility_assessment": compat, "pod_before": pod_before,
            "exporter_pod": exporter_pod,
            "port_forward": {"mode": "kubectl-port-forward", "target_namespace": OBS_NS,
                "target_pod": exporter_id["name"], "target_pod_uid": exporter_id["uid"],
                "remote_port": 9400, "local_port": PORTS["exporter_local"],
                "captured_at_utc": exporter_pf_time},
            "node": node_capture,
            "pod_resources": {"captured_at_utc": podresources_raw["captured_at_utc"],
                "entries": [{k: allocation[k] for k in ("namespace", "pod", "container", "resource_name", "device_ids")}]},
            "exporter_target": target, "selected_fields": selected_fields,
            "max_sample_skew_seconds": review["max_sample_skew_seconds"],
        }
        input_path = capture_dir / "capture-inputs.json"
        write_json(input_path, input_obj)
        collection_path = capture_dir / "collection.json"
        collect = subprocess.run([sys.executable, str(CAPTURE), "collect", "--inputs", str(input_path),
            "--exporter-url", f"http://127.0.0.1:{PORTS['exporter_local']}",
            "--prometheus-url", f"http://127.0.0.1:{PORTS['prometheus_local']}",
            "--output", str(collection_path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=45, check=False)
        if collect.returncode != 0:
            raise CaptureError(adapter_failure(collect.stdout, "bounded DCGM/Prometheus collection"))
    finally:
        if prom_port_forward is not None:
            stop_forward(prom_port_forward)
        if exporter_port_forward is not None:
            stop_forward(exporter_port_forward)

    after_obj = kubectl(kubectl_bin, kubeconfig,
        ["-n", WORKLOAD_NS, "get", "pod", WORKLOAD_POD, "-o", "json"], "workload Pod after capture")
    after_meta = after_obj.get("metadata", {})
    after_spec = after_obj.get("spec", {})
    after_status = after_obj.get("status", {})
    after_container, _ = get_container(after_obj, WORKLOAD_CONTAINER)
    after_gpu = after_container.get("resources", {}).get("requests", {}).get(GPU_RESOURCE)
    pod_after = {"schema": "saf-k8s-dcgm-pod-after-v1", "namespace": after_meta.get("namespace"),
        "name": after_meta.get("name"), "uid": after_meta.get("uid"), "container": WORKLOAD_CONTAINER,
        "node": after_spec.get("nodeName"), "phase": after_status.get("phase"),
        "gpu_request": str(after_gpu), "captured_at_utc": utc_now()}
    after_path = capture_dir / "workload-pod-after.json"
    write_json(after_path, pod_after)
    receipt_path = capture_dir / "receipt.json"
    finalize = subprocess.run([sys.executable, str(CAPTURE), "finalize", "--collection", str(collection_path),
        "--pod-after", str(after_path), "--output", str(receipt_path)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=False)
    if finalize.returncode != 0:
        raise CaptureError(adapter_failure(finalize.stdout, "bounded receipt finalization"))
    validation = subprocess.run([sys.executable, str(VALIDATOR), str(receipt_path)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
    if validation.returncode != 0:
        raise CaptureError(adapter_failure(validation.stdout, "offline receipt consistency validation"))
    try:
        validator_result = json.loads(validation.stdout)
    except json.JSONDecodeError as exc:
        raise CaptureError("offline validator output is invalid") from exc
    require(validator_result.get("status") == "consistent_capture_requires_provenance_review",
            "offline validator did not return its consistency-only status")

    write_json(capture_dir / "port-forward-provenance.json", {
        "kubeconfig_explicit": True,
        "forwards": [
            {"mode": "kubectl-port-forward", "address": "127.0.0.1",
             "namespace": OBS_NS, "pod": exporter_id["name"], "pod_uid": exporter_id["uid"],
             "local_port": PORTS["exporter_local"], "remote_port": PORTS["exporter_remote"],
             "ready_at_utc": exporter_pf_time},
            {"mode": "kubectl-port-forward", "address": "127.0.0.1",
             "namespace": OBS_NS, "pod": prom_id["name"], "pod_uid": prom_id["uid"],
             "local_port": PORTS["prometheus_local"], "remote_port": PORTS["prometheus_remote"],
             "ready_at_utc": prom_pf_time},
        ]})
    artifact_names = ["workload-pod-before.json", "node.json", "podresources.raw.json",
        "nvidia-smi-selected.json", "software-provenance.json", "capture-inputs.json",
        "collection.json", "workload-pod-after.json", "receipt.json", "port-forward-provenance.json",
        "capture-review.json"]
    manifest = {"schema": "saf-k8s-t4-capture-manifest-v1", "evidence_kind": "sanitized_host_capture",
        "capture_directory": capture_dir.name, "validator_status": validator_result["status"],
        "limitations": ["offline consistency only; source authenticity requires human provenance review",
                        "no NVIDIA certification or fleet/sustained coverage claim",
                        "PodResources API does not provide Pod UID or node name; raw local node/socket record is separately hashed"],
        "artifacts": {name: {"sha256": sha256(capture_dir / name), "bytes": (capture_dir / name).stat().st_size}
                      for name in artifact_names},
        "tooling": {name: {"path": str(path.relative_to(BASE)), "sha256": sha256(path)} for name, path in {
            "capture_harness": BASE / "capture_t4.py",
            "dcgm_adapter": CAPTURE,
            "receipt_validator": VALIDATOR,
            "podresources_client": PODRESOURCES,
            "podresources_source": BASE / "podresources-list" / "main.go",
            "podresources_go_mod": BASE / "podresources-list" / "go.mod",
            "podresources_go_sum": BASE / "podresources-list" / "go.sum",
        }.items()}}
    write_json(capture_dir / "capture-manifest.json", manifest)
    return {"status": validator_result["status"], "capture_directory": str(capture_dir),
            "receipt_sha256": sha256(receipt_path), "manifest_sha256": sha256(capture_dir / "capture-manifest.json"),
            "device_uuid": smi["gpu_uuid"], "device_model": smi["model"],
            "selected_sample_count": validator_result.get("selected_sample_count")}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kubeconfig", required=True, help="explicit kubeconfig file; never inferred")
    parser.add_argument("--review", default=str(BASE / "capture_review.json"), help="reviewed fixed stack/metric metadata JSON")
    parser.add_argument("--output-root", default=str(BASE / "captures"), help="output directory inside this capture workspace")
    args = parser.parse_args()
    try:
        result = capture(args)
    except (CaptureError, OSError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
