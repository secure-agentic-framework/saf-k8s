#!/usr/bin/env python3
"""Read-only, explicit-kubeconfig preflight for an already running A100 fixture."""

import argparse
import csv
import hashlib
import json
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, build_opener


MAX_JSON = 2_000_000
MAX_TEXT = 256_000
METRIC = "DCGM_FI_DEV_FB_USED"
K8S_UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


LOOPBACK_OPENER = build_opener(_NoRedirect)


class Blocked(RuntimeError):
    pass


def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def run(command, *, input_bytes=None, timeout=12):
    try:
        result = subprocess.run(command, input=input_bytes, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("A bounded local preflight command failed") from exc
    if result.returncode != 0 or len(result.stdout) > MAX_JSON:
        raise Blocked("A bounded local preflight command returned an invalid result")
    return result.stdout


def kubectl(binary, kubeconfig, *args):
    raw = run([binary, "--kubeconfig", str(kubeconfig), "--request-timeout=8s", *args])
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Blocked("Kubernetes returned invalid JSON") from exc


def ready_pod(pods, namespace, node=None, port=None):
    candidates = []
    for pod in pods:
        meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
        if meta.get("namespace") != namespace or (node and spec.get("nodeName") != node):
            continue
        if status.get("phase") != "Running":
            continue
        statuses = {row.get("name"): row for row in status.get("containerStatuses", [])}
        for container in spec.get("containers", []):
            cstatus = statuses.get(container.get("name"), {})
            ports = [p for p in container.get("ports", []) if p.get("containerPort") == port] if port else [True]
            if cstatus.get("ready") is True and len(ports) == 1:
                candidates.append((pod, container, cstatus))
    if len(candidates) != 1:
        raise Blocked("Expected exactly one Ready matching Pod/container")
    return candidates[0]


def start_forward(kubectl_bin, kubeconfig, namespace, pod, local_port, remote_port):
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            probe.bind(("127.0.0.1", local_port))
        except OSError as exc:
            raise Blocked("The requested loopback port is already in use") from exc
    proc = subprocess.Popen([kubectl_bin, "--kubeconfig", str(kubeconfig), "-n", namespace,
                             "port-forward", "--address", "127.0.0.1", "pod/" + pod,
                             f"{local_port}:{remote_port}"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            proc.wait()
            raise Blocked("The owned loopback port-forward exited before readiness")
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=0.25):
                return proc
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait(timeout=2)
    raise Blocked("The bounded loopback port-forward did not become ready")


def stop_forward(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait(timeout=2)


def get_json(url):
    try:
        if not url.startswith("http://127.0.0.1:"):
            raise Blocked("Only an IPv4 loopback endpoint is allowed")
        with LOOPBACK_OPENER.open(url, timeout=4) as response:
            data = response.read(MAX_JSON + 1)
    except Exception as exc:
        raise Blocked("A local loopback read failed") from exc
    if len(data) > MAX_JSON:
        raise Blocked("A loopback JSON response exceeded the bound")
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        raise Blocked("A loopback endpoint returned invalid JSON") from exc


def parse_metric_line(line):
    match = re.fullmatch(r"([A-Za-z_:][A-Za-z0-9_:]*)\{(.*)\}\s+([^\s]+)(?:\s+([^\s]+))?", line)
    if not match:
        return None
    labels = {}
    for pair in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)="((?:\\.|[^"])*)"(?:,|$)', match.group(2)):
        labels[pair.group(1)] = bytes(pair.group(2), "utf-8").decode("unicode_escape")
    try:
        value = float(match.group(3))
    except ValueError:
        return None
    return {"metric": match.group(1), "labels": labels, "value": value}


def exporter_samples(port, workload):
    try:
        with LOOPBACK_OPENER.open(f"http://127.0.0.1:{port}/metrics", timeout=5) as response:
            text = response.read(MAX_TEXT + 1).decode("utf-8")
    except Exception as exc:
        raise Blocked("The bounded local exporter read failed") from exc
    if len(text.encode("utf-8")) > MAX_TEXT:
        raise Blocked("Exporter response exceeded the text bound")
    output = []
    for line in text.splitlines():
        if not line.startswith(METRIC + "{"):
            continue
        row = parse_metric_line(line)
        if row and all(row["labels"].get(key) == value for key, value in workload.items()):
            output.append(row)
    if len(output) != 1:
        raise Blocked("Expected one exporter framebuffer sample for the exact workload identity")
    return output[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True, help="existing absolute kubeconfig; never inferred")
    parser.add_argument("--workload-namespace", default="saf-gpu-a100")
    parser.add_argument("--workload-pod", default="a100-vector-witness")
    parser.add_argument("--workload-container", default="vector")
    parser.add_argument("--exporter-namespace", default="saf-gpu-observe")
    parser.add_argument("--exporter-selector", required=True, help="exact reviewed selector for the owned exporter")
    parser.add_argument("--prometheus-namespace", default="saf-gpu-observe")
    parser.add_argument("--prometheus-selector", default="app.kubernetes.io/name=saf-prometheus")
    parser.add_argument("--prometheus-job", default="saf-a100-dcgm")
    parser.add_argument("--podresources-binary", required=True, help="reviewed local PodResources v1 helper")
    parser.add_argument("--podresources-socket", default="/var/lib/kubelet/pod-resources/kubelet.sock")
    parser.add_argument("--framebuffer-helper", help="original reviewed 128 MiB CUDA allocator binary, when available")
    parser.add_argument("--exporter-port", type=int, default=19401)
    parser.add_argument("--prometheus-port", type=int, default=19091)
    parser.add_argument("--output", required=True, help="explicit private output JSON path")
    args = parser.parse_args(argv)
    kubeconfig = Path(args.kubeconfig).expanduser()
    helper = Path(args.podresources_binary).expanduser()
    framebuffer_helper = Path(args.framebuffer_helper).expanduser() if args.framebuffer_helper else None
    output = Path(args.output).expanduser()
    if not (kubeconfig.is_absolute() and kubeconfig.is_file() and helper.is_absolute() and helper.is_file()
            and output.is_absolute()):
        raise Blocked("Kubeconfig/helper/output paths must be explicit absolute paths")
    framebuffer_sha = None
    if framebuffer_helper is not None:
        if not framebuffer_helper.is_absolute() or not framebuffer_helper.is_file():
            raise Blocked("The optional allocator path must be an explicit absolute file")
        framebuffer_sha = hashlib.sha256(framebuffer_helper.read_bytes()).hexdigest()
        if framebuffer_sha != "68820dd2b481cf7440c62991d1ecb71af2887f63bfbeb594150ca9c92a640db7":
            raise Blocked("The 128 MiB allocator binary differs from the reviewed fixture pin")
    kubectl_bin = shutil.which("kubectl")
    if not kubectl_bin:
        raise Blocked("kubectl is unavailable")

    server = kubectl(kubectl_bin, kubeconfig, "version", "-o", "json").get("serverVersion", {})
    workload_obj = kubectl(kubectl_bin, kubeconfig, "-n", args.workload_namespace,
                           "get", "pod", args.workload_pod, "-o", "json")
    wmeta, wspec, wstatus = (workload_obj.get("metadata", {}), workload_obj.get("spec", {}),
                              workload_obj.get("status", {}))
    containers = [c for c in wspec.get("containers", []) if c.get("name") == args.workload_container]
    statuses = [c for c in wstatus.get("containerStatuses", []) if c.get("name") == args.workload_container]
    if len(containers) != 1 or len(statuses) != 1 or statuses[0].get("ready") is not True:
        raise Blocked("The exact owned workload container is not uniquely Ready")
    if not K8S_UID.fullmatch(wmeta.get("uid", "")):
        raise Blocked("The exact workload Pod UID is invalid")
    wc = containers[0]
    gpu_req = wc.get("resources", {}).get("requests", {}).get("nvidia.com/gpu")
    if str(gpu_req) != "1" or wstatus.get("phase") != "Running":
        raise Blocked("The exact workload must be Running and request one GPU")
    workload_image = wc.get("image", "")
    workload_status = statuses[0]
    workload_digest = re.search(r"@sha256:[0-9a-f]{64}$", workload_image)
    if not workload_digest or not workload_status.get("imageID", "").endswith(workload_digest.group(0)[1:]):
        raise Blocked("The known-good workload image reference and runtime imageID are not digest-bound")
    command_text = json.dumps({"command": wc.get("command", []), "args": wc.get("args", [])})
    if (wspec.get("runtimeClassName") != "nvidia"
            or wspec.get("automountServiceAccountToken") is not False
            or wspec.get("securityContext", {}).get("runAsNonRoot") is not True
            or wc.get("securityContext", {}).get("allowPrivilegeEscalation") is not False
            or wc.get("securityContext", {}).get("readOnlyRootFilesystem") is not True
            or "ALL" not in wc.get("securityContext", {}).get("capabilities", {}).get("drop", [])
            or "vectorAdd" not in command_text):
        raise Blocked("The workload no longer matches the bounded known-good GPU fixture profile")
    if any("hostPath" in volume for volume in wspec.get("volumes", [])):
        raise Blocked("The known-good fixture must not mount host paths")
    node_name = wspec.get("nodeName")
    node_obj = kubectl(kubectl_bin, kubeconfig, "get", "node", node_name, "-o", "json")
    nmeta = node_obj.get("metadata", {})
    nstatus = node_obj.get("status", {})
    ninfo = nstatus.get("nodeInfo", {})
    if int(nstatus.get("allocatable", {}).get("nvidia.com/gpu", 0)) < 1:
        raise Blocked("The selected node does not report one allocatable NVIDIA GPU")
    if not K8S_UID.fullmatch(nmeta.get("uid", "")):
        raise Blocked("The selected node UID is invalid")
    workload_list = run([str(helper), "--socket", args.podresources_socket,
                         "--node-name", node_name, "--namespace", args.workload_namespace,
                         "--pod", args.workload_pod, "--container", args.workload_container,
                         "--expected-device-count", "1"])
    try:
        pr = json.loads(workload_list)
    except json.JSONDecodeError as exc:
        raise Blocked("PodResources helper output was invalid") from exc
    entries = pr.get("entries", [])
    if len(entries) != 1 or entries[0].get("resource_name") != "nvidia.com/gpu" or len(entries[0].get("device_ids", [])) != 1:
        raise Blocked("PodResources did not show exactly one allocated NVIDIA GPU")

    smi = run(["nvidia-smi", "--query-gpu=uuid,name,driver_version", "--format=csv,noheader,nounits"], timeout=8)
    if len(smi) > MAX_TEXT:
        raise Blocked("nvidia-smi response exceeded the bound")
    try:
        smi_rows = list(csv.reader(smi.decode("utf-8").splitlines(), skipinitialspace=True))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise Blocked("nvidia-smi identity response was invalid") from exc
    matches = [row for row in smi_rows if len(row) == 3 and row[0].strip() == entries[0]["device_ids"][0]]
    if len(matches) != 1:
        raise Blocked("PodResources device ID did not match exactly one nvidia-smi GPU")
    gpu_uuid, model, driver = (part.strip() for part in matches[0])
    if "A100" not in model.upper():
        raise Blocked("The selected live profile is not identified as NVIDIA A100")

    exporters = kubectl(kubectl_bin, kubeconfig, "-n", args.exporter_namespace,
                        "get", "pods", "-l", args.exporter_selector, "-o", "json").get("items", [])
    exp_pod, exp_container, exp_status = ready_pod(exporters, args.exporter_namespace, node_name, 9400)
    exp_meta, exp_stat = exp_pod.get("metadata", {}), exp_pod.get("status", {})
    if not K8S_UID.fullmatch(exp_meta.get("uid", "")):
        raise Blocked("The selected exporter Pod UID is invalid")
    exp_ip = exp_stat.get("podIP")
    if not exp_ip or ":" in exp_ip:
        raise Blocked("The selected exporter does not have an IPv4 Pod IP")
    exp_image_id = exp_status.get("imageID", "")
    exp_image = exp_container.get("image", "")
    image_digest = re.search(r"@sha256:[0-9a-f]{64}$", exp_image)
    if not image_digest or not exp_image_id.endswith(image_digest.group(0)[1:]):
        raise Blocked("Exporter container imageID lacks an immutable digest")

    plugin_pods = kubectl(kubectl_bin, kubeconfig, "-n", "kube-system", "get", "pods",
                          "-l", "name=nvidia-device-plugin-ds", "-o", "json").get("items", [])
    plugin_pod, plugin_container, plugin_status = ready_pod(plugin_pods, "kube-system", node_name, None)
    plugin_meta = plugin_pod.get("metadata", {})
    plugin_image = plugin_container.get("image", "")
    plugin_image_id = plugin_status.get("imageID", "")
    if not K8S_UID.fullmatch(plugin_meta.get("uid", "")) or "sha256:" not in plugin_image_id:
        raise Blocked("The selected NVIDIA device-plugin identity is not digest-bound")

    prom_pods = kubectl(kubectl_bin, kubeconfig, "-n", args.prometheus_namespace,
                        "get", "pods", "-l", args.prometheus_selector, "-o", "json").get("items", [])
    prom_pod, _, _ = ready_pod(prom_pods, args.prometheus_namespace, None, 9090)
    pmeta = prom_pod.get("metadata", {})

    exporter_forward = prometheus_forward = None
    try:
        exporter_forward = start_forward(kubectl_bin, kubeconfig, args.exporter_namespace,
                                         exp_meta["name"], args.exporter_port, 9400)
        workload_labels = {"namespace": args.workload_namespace, "pod": args.workload_pod,
                           "container": args.workload_container,
                           "pod_uid": wmeta.get("uid", ""), "UUID": gpu_uuid}
        direct = exporter_samples(args.exporter_port, workload_labels)
        prometheus_forward = start_forward(kubectl_bin, kubeconfig, args.prometheus_namespace,
                                           pmeta["name"], args.prometheus_port, 9090)
        target_response = get_json(f"http://127.0.0.1:{args.prometheus_port}/api/v1/targets?state=active")
        active = target_response.get("data", {}).get("activeTargets", [])
        target_matches = [target for target in active
                          if target.get("labels", {}).get("job") == args.prometheus_job
                          and target.get("discoveredLabels", {}).get("__meta_kubernetes_pod_uid") == exp_meta.get("uid")
                          and target.get("discoveredLabels", {}).get("__meta_kubernetes_namespace") == args.exporter_namespace
                          and target.get("discoveredLabels", {}).get("__meta_kubernetes_pod_name") == exp_meta.get("name")
                          and target.get("discoveredLabels", {}).get("__meta_kubernetes_pod_node_name") == node_name
                          and target.get("discoveredLabels", {}).get("__meta_kubernetes_pod_ip") == exp_ip
                          and target.get("scrapeUrl") == f"http://{exp_ip}:9400/metrics"
                          and target.get("health") == "up"]
        if len(target_matches) != 1:
            raise Blocked("Prometheus has no unique healthy target joined to the selected exporter Pod UID")
        labels = direct["labels"]
        selectors = {"namespace": args.workload_namespace, "pod": args.workload_pod,
                     "container": args.workload_container, "pod_uid": wmeta.get("uid", ""), "UUID": gpu_uuid}
        selector = ",".join(f'{key}="{value}"' for key, value in selectors.items())
        query_url = f"http://127.0.0.1:{args.prometheus_port}/api/v1/query?" + urlencode({"query": f"{METRIC}{{{selector}}}"})
        query = get_json(query_url)
        rows = query.get("data", {}).get("result", [])
        exact = [row for row in rows if all(row.get("metric", {}).get(k) == v for k, v in selectors.items())
                 and row.get("metric", {}).get("job") == args.prometheus_job
                 and row.get("metric", {}).get("instance") == f"{exp_ip}:9400"]
        if query.get("status") != "success" or len(exact) != 1:
            raise Blocked("Prometheus did not expose one exact workload/device framebuffer series")
        prom_value = float(exact[0]["value"][1])
        output_obj = {
            "schema": "saf-a100-live-readiness-v1", "status": "profile_observed_review_required",
            "captured_at_utc": utc_now(), "field_support_reviewed": False,
            "source_commit": "23a8b7a4be1fec186b4138fc30e12ab0964e33b9",
            "historical_reference_summary_sha256": "907e0801f74229eb074bb04c8fc70681ab181cd908281076b5f123af436f0b68",
            "host": {"os": "linux", "architecture": ninfo.get("architecture"),
                     "hostname_sha256": sha(socket.gethostname())},
            "kubernetes": {"server": server.get("gitVersion"), "kubelet": ninfo.get("kubeletVersion"),
                           "container_runtime": ninfo.get("containerRuntimeVersion"),
                           "node_uid_sha256": sha(nmeta.get("uid", "")),
                           "gpu_allocatable": str(nstatus["allocatable"]["nvidia.com/gpu"])},
            "hardware": {"model": model, "driver": driver, "gpu_uuid_sha256": sha(gpu_uuid),
                         "resource_name": "nvidia.com/gpu", "allocated_device_count": 1},
            "workload": {"namespace": args.workload_namespace, "name": args.workload_pod,
                         "container": args.workload_container, "uid_sha256": sha(wmeta.get("uid", "")),
                         "container_image": workload_image, "image_id": workload_status.get("imageID"),
                         "gpu_request": str(gpu_req), "runtime_class": wspec.get("runtimeClassName"),
                         "fixture_spec_sha256": sha(json.dumps({
                             "image": workload_image, "image_id": workload_status.get("imageID"),
                             "command_sha256": sha(command_text), "gpu_request": str(gpu_req),
                             "runtime_class": wspec.get("runtimeClassName"), "token_automount": False,
                             "run_as_nonroot": True, "read_only_root": True,
                             "no_privilege_escalation": True, "drop_all_capabilities": True},
                             sort_keys=True, separators=(",", ":")))},
            "framebuffer_helper": {"sha256": framebuffer_sha, "allocated_bytes": 134217728} if framebuffer_sha is not None else None,
            "exporter": {"namespace": args.exporter_namespace, "pod_uid_sha256": sha(exp_meta.get("uid", "")),
                         "node_match": exp_pod.get("spec", {}).get("nodeName") == node_name,
                         "image": exp_image, "image_id": exp_image_id,
                         "port": 9400, "target_health": target_matches[0].get("health"),
                         "job": args.prometheus_job},
            "device_plugin": {"namespace": "kube-system", "pod_uid_sha256": sha(plugin_meta.get("uid", "")),
                              "image": plugin_image, "image_id": plugin_image_id,
                              "node_match": plugin_pod.get("spec", {}).get("nodeName") == node_name},
            "selected_metric": {"name": METRIC, "unit": "MiB", "support_reviewed": False,
                                "direct_value": direct["value"], "prometheus_value": prom_value,
                                "absolute_delta": abs(direct["value"] - prom_value),
                                "workload_uid_label_matches": labels.get("pod_uid") == wmeta.get("uid"),
                                "device_uuid_label_matches": labels.get("UUID") == gpu_uuid},
            "limitations": ["read-only readiness capture; no alert rule or response was run",
                            "live DCGM support and version compatibility require explicit review",
                            "no incident, misuse, production authorization, or freshness guarantee"],
        }
    finally:
        stop_forward(prometheus_forward)
        stop_forward(exporter_forward)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(output_obj, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": output_obj["status"], "output": str(output),
                      "model": model, "metric_present": True,
                      "workload_uid_bound": output_obj["selected_metric"]["workload_uid_label_matches"],
                      "exporter_target_up": output_obj["exporter"]["target_health"] == "up"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Blocked as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        sys.exit(2)
