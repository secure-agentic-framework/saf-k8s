#!/usr/bin/env python3
"""Run the bounded live A100 alert-to-hold reference on an existing cluster."""

import argparse
import csv
from contextlib import ExitStack
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from ipaddress import IPv4Address
from urllib.parse import urlencode

import a100_admission as gate

from a100_readiness import (
    FRAMEBUFFER_FIXTURES, K8S_UID, METRIC, PODRESOURCES_FIXTURE, Blocked, exporter_samples,
    get_json, sha, start_forward, stop_forward,
)


PROM_IMAGE = "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
ALERTMANAGER_IMAGE = ("docker.io/prom/alertmanager:v0.28.1@sha256:"
                      "27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba")
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
WORKLOAD_NS = gate.NAMESPACE
WORKLOAD_POD = "a100-vector-witness"
WORKLOAD_CONTAINER = "vector"
OBS_NS = "saf-gpu-observe"
JOB = "saf-a100-catch-hold"
HELD_BYTES = 128 * 1024 * 1024
SOURCE_COMMIT = "23a8b7a4be1fec186b4138fc30e12ab0964e33b9"
SOURCE_SUMMARY_SHA = "907e0801f74229eb074bb04c8fc70681ab181cd908281076b5f123af436f0b68"


def now():
    return datetime.now(timezone.utc)


def utc(value=None):
    return (value or now()).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def run_cmd(command, *, input_bytes=None, timeout=20, allow_failure=False, stderr_pipe=False):
    try:
        proc = subprocess.run(command, input=input_bytes, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE if stderr_pipe else subprocess.DEVNULL,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("A bounded local or Kubernetes operation failed") from exc
    if not allow_failure and proc.returncode != 0:
        raise Blocked("A bounded Kubernetes operation returned a nonzero status")
    if len(proc.stdout) > 2_000_000:
        raise Blocked("A bounded command response exceeded the size limit")
    if stderr_pipe and len(proc.stderr) > 64_000:
        raise Blocked("A bounded diagnostic response exceeded the size limit")
    return proc


def kube(kubectl, kubeconfig, *args, input_bytes=None, timeout=20, allow_failure=False, stderr_pipe=False):
    return run_cmd([kubectl, "--kubeconfig", str(kubeconfig), f"--request-timeout={max(1, timeout - 4)}s", *args],
                   input_bytes=input_bytes, timeout=timeout, allow_failure=allow_failure,
                   stderr_pipe=stderr_pipe)


def kube_json(kubectl, kubeconfig, *args):
    result = kube(kubectl, kubeconfig, *args)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise Blocked("Kubernetes returned invalid JSON") from exc


def read_profile(path):
    raw = Path(path).read_bytes()
    if len(raw) > 64_000:
        raise Blocked("Readiness profile exceeded the bound")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Blocked("Readiness profile is invalid") from exc
    if (doc.get("schema") != "saf-a100-live-readiness-v1"
            or doc.get("status") != "profile_observed_review_required"
            or doc.get("field_support_reviewed") is not False
            or doc.get("historical_reference_summary_sha256") != SOURCE_SUMMARY_SHA
            or doc.get("hardware", {}).get("model", "").upper().find("A100") < 0):
        raise Blocked("Readiness profile does not identify the reviewed A100 reference")
    age = (now() - datetime.fromisoformat(doc["captured_at_utc"].replace("Z", "+00:00"))).total_seconds()
    if age < 0 or age > 120:
        raise Blocked("A fresh readiness profile no older than two minutes is required")
    if doc.get("selected_metric", {}).get("name") != METRIC:
        raise Blocked("Readiness profile selected a different telemetry field")
    return doc


def ensure_pod_profile(kubectl, kubeconfig, profile):
    pod = kube_json(kubectl, kubeconfig, "-n", WORKLOAD_NS, "get", "pod", WORKLOAD_POD, "-o", "json")
    meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
    containers = [c for c in spec.get("containers", []) if c.get("name") == WORKLOAD_CONTAINER]
    statuses = [c for c in status.get("containerStatuses", []) if c.get("name") == WORKLOAD_CONTAINER]
    if len(containers) != 1 or len(statuses) != 1 or statuses[0].get("ready") is not True:
        raise Blocked("The exact A100 fixture workload container is no longer Ready")
    c = containers[0]
    if sha(meta.get("uid", "")) != profile.get("workload", {}).get("uid_sha256"):
        raise Blocked("The live workload Pod UID differs from the readiness profile")
    if (status.get("phase") != "Running" or str(c.get("resources", {}).get("requests", {}).get("nvidia.com/gpu")) != "1"
            or spec.get("runtimeClassName") != "nvidia"):
        raise Blocked("The live workload no longer matches the reviewed one-GPU fixture profile")
    if (c.get("image") != profile.get("workload", {}).get("container_image")
            or statuses[0].get("imageID") != profile.get("workload", {}).get("image_id")):
        raise Blocked("The workload image reference or runtime digest changed after preflight")
    return pod, c, statuses[0]


def nvidia_device(kubectl, kubeconfig, helper, profile):
    pod = kube_json(kubectl, kubeconfig, "-n", WORKLOAD_NS, "get", "pod", WORKLOAD_POD, "-o", "json")
    node_name = pod.get("spec", {}).get("nodeName", "")
    uid = pod.get("metadata", {}).get("uid", "")
    pr = run_cmd([str(helper), "--socket", "/var/lib/kubelet/pod-resources/kubelet.sock",
                  "--node-name", node_name, "--namespace", WORKLOAD_NS, "--pod", WORKLOAD_POD,
                  "--container", WORKLOAD_CONTAINER, "--expected-device-count", "1"], timeout=12)
    try:
        entries = json.loads(pr.stdout).get("entries", [])
    except json.JSONDecodeError as exc:
        raise Blocked("PodResources output is invalid") from exc
    if (len(entries) != 1 or entries[0].get("resource_name") != "nvidia.com/gpu"
            or len(entries[0].get("device_ids", [])) != 1):
        raise Blocked("PodResources no longer binds exactly one device to the fixture")
    gpu_id = entries[0]["device_ids"][0]
    smi = run_cmd(["nvidia-smi", "--query-gpu=uuid,name,driver_version", "--format=csv,noheader,nounits"], timeout=8)
    rows = list(csv.reader(smi.stdout.decode("utf-8").splitlines(), skipinitialspace=True))
    matches = [row for row in rows if len(row) == 3 and row[0].strip() == gpu_id]
    if len(matches) != 1 or "A100" not in matches[0][1].upper():
        raise Blocked("The allocated device no longer matches the verified A100 profile")
    device_uuid, model, driver = (item.strip() for item in matches[0])
    if sha(device_uuid) != profile.get("hardware", {}).get("gpu_uuid_sha256"):
        raise Blocked("The A100 device identity differs from the readiness profile")
    if sha(uid) != profile.get("workload", {}).get("uid_sha256"):
        raise Blocked("The workload identity differs from the readiness profile")
    return pod, device_uuid, model, driver


def find_exporter(kubectl, kubeconfig, selector, node_name):
    pods = kube_json(kubectl, kubeconfig, "-n", OBS_NS, "get", "pods", "-l", selector, "-o", "json").get("items", [])
    matches = []
    for pod in pods:
        meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
        if spec.get("nodeName") != node_name or status.get("phase") != "Running":
            continue
        for container in spec.get("containers", []):
            st = next((x for x in status.get("containerStatuses", []) if x.get("name") == container.get("name")), {})
            ports = [x for x in container.get("ports", []) if x.get("containerPort") == 9400]
            if st.get("ready") is True and len(ports) == 1:
                matches.append((pod, container, st))
    if len(matches) != 1:
        raise Blocked("Expected one Ready selected DCGM exporter on the A100 workload node")
    return matches[0]


def prom_static_target_config(exporter_ip, exporter_uid_hash, node_uid_hash, am_target):
    return {
        "global": {"scrape_interval": "2s", "scrape_timeout": "1s", "evaluation_interval": "2s"},
        "scrape_configs": [{"job_name": JOB, "scrape_interval": "2s", "scrape_timeout": "1s",
                            "static_configs": [{"targets": [f"{exporter_ip}:9400"], "labels": {
                                "exporter_uid_ref": exporter_uid_hash, "node_uid_ref": node_uid_hash,
                                "scrape_source": "owned-a100-exporter"}}]}],
        "rule_files": ["/fixture/rules.yml"],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": [am_target]}]}]},
    }


def receiver_source():
    return r'''import hashlib,json,math,re
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from threading import Lock
records=[]; lock=Lock(); LIMIT=8192; MAX=6
def h(v): return hashlib.sha256(str(v).encode()).hexdigest()
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path=="/health": self.send_response(200);self.end_headers();self.wfile.write(b"ok\n");return
  if self.path!="/events": self.send_error(404);return
  with lock: body=json.dumps(records,sort_keys=True,separators=(",",":")).encode()
  self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
 def do_POST(self):
  if self.path!="/events": self.send_error(404);return
  try:
   n=int(self.headers.get("Content-Length","-1"))
   if n<0 or n>LIMIT: self.send_error(413);return
   doc=json.loads(self.rfile.read(n)); alerts=doc.get("alerts",[])
   if not isinstance(alerts,list) or not 1<=len(alerts)<=2: self.send_error(413);return
   for a in alerts:
    labels=a.get("labels",{}); annotations=a.get("annotations",{})
    if not isinstance(labels,dict) or not isinstance(annotations,dict): self.send_error(400);return
    observed=float(annotations.get("observed_mib","nan")); threshold=float(labels.get("threshold_mib","nan"))
    if not math.isfinite(observed) or not math.isfinite(threshold): self.send_error(400);return
    if not re.fullmatch(r"[0-9a-f]{16}",a.get("fingerprint","")): self.send_error(400);return
    row={"receiver":str(doc.get("receiver",""))[:80],"status":str(a.get("status",""))[:30],
      "alertname":str(labels.get("alertname",""))[:100],"source_age":str(labels.get("source_age",""))[:30],
      "workload_class":str(labels.get("workload_class",""))[:60],"workload_ref":str(labels.get("workload_ref",""))[:64],
      "device_ref":h(labels.get("UUID","")),"pod_ref":h(labels.get("pod_uid","")),
      "metric":str(labels.get("metric_name",""))[:80],"threshold_mib":threshold,"observed_mib":observed,
      "fingerprint_sha256":h(a.get("fingerprint","")),"starts_at":str(a.get("startsAt",""))[:40],
      "source_kind":str(labels.get("source_kind",""))[:40],"capture_ref":str(labels.get("capture_ref",""))[:80]}
    if row["alertname"]!="SAF_A100_FramebufferThreshold" or row["receiver"]!="case-local-live-hold": self.send_error(400);return
    if not row["fingerprint_sha256"] or not row["pod_ref"] or not row["device_ref"]: self.send_error(400);return
    with lock:
     if len(records)>=MAX: self.send_error(429);return
     records.append(row)
  except (ValueError,TypeError,AttributeError): self.send_error(400);return
  self.send_response(200);self.end_headers();self.wfile.write(b"{}\n")
 def log_message(self,*_): pass
ThreadingHTTPServer(("0.0.0.0",18082),H).serve_forever()
'''


def pod_resource(name, image, command, config_name, container_name, port, *, readiness_path, service=True):
    label = {"app": name}
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": label},
           "spec": {"restartPolicy": "Always", "terminationGracePeriodSeconds": 5, "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "fsGroup": 65534,
                                        "fsGroupChangePolicy": "OnRootMismatch",
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": container_name, "image": image, "imagePullPolicy": "IfNotPresent",
                                    "command": command, "ports": [{"containerPort": port}],
                                    "readinessProbe": {"httpGet": {"path": readiness_path, "port": port},
                                                       "periodSeconds": 2, "timeoutSeconds": 2,
                                                       "failureThreshold": 40},
                                    "resources": {"requests": {"cpu": "25m", "memory": "64Mi"},
                                                  "limits": {"cpu": "400m", "memory": "512Mi"}},
                                    "securityContext": {"allowPrivilegeEscalation": False,
                                                        "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}},
                                    "volumeMounts": [{"name": "config", "mountPath": "/fixture", "readOnly": True},
                                                     {"name": "scratch", "mountPath": "/scratch"}]}],
                    "volumes": [{"name": "config", "configMap": {"name": config_name}},
                                {"name": "scratch", "emptyDir": {"sizeLimit": "64Mi"}}]}}
    resources = [pod]
    if service:
        resources.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                          "spec": {"selector": label, "ports": [{"port": port, "targetPort": port}]}})
    return resources


def query_metric(port, selector):
    data = get_json(f"http://127.0.0.1:{port}/api/v1/query?" + urlencode({"query": f"{METRIC}{{{selector}}}[20s]"}))
    if data.get("status") != "success" or data.get("data", {}).get("resultType") != "matrix":
        return None
    rows = data.get("data", {}).get("result", [])
    if len(rows) != 1:
        return None
    labels = rows[0].get("metric", {})
    values = rows[0].get("values", [])
    if not values:
        return None
    stamp, value = values[-1]
    stamp, value = float(stamp), float(value)
    if not math.isfinite(stamp) or not math.isfinite(value) or value < 0:
        raise Blocked("Prometheus returned a non-finite or negative framebuffer sample")
    return {"labels": labels, "timestamp": stamp, "value_mib": value}


def alert_state(port):
    data = get_json(f"http://127.0.0.1:{port}/api/v1/alerts")
    if data.get("status") != "success":
        return None
    rows = []
    for item in data.get("data", {}).get("alerts", []):
        labels = item.get("labels", {})
        if labels.get("alertname") == "SAF_A100_FramebufferThreshold" and item.get("state") == "firing":
            rows.append({"labels": labels, "active_at": item.get("activeAt")})
    return rows


def wait_for(probe, seconds=70):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(1)
    return None


def deploy_monitors(kubectl, kubeconfig, owned, runid, exporter_ip, profile, threshold):
    prefix = "saf-a100-catch-" + runid
    exporter_uid_ref = profile["exporter"]["pod_uid_sha256"]
    node_uid_ref = profile["kubernetes"]["node_uid_sha256"]
    cfg_name = prefix + "-assets"
    owned.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": prefix}})
    pod_ref = profile["workload"]["uid_sha256"]
    device_ref = profile["hardware"]["gpu_uuid_sha256"]
    prom_config = prom_static_target_config(exporter_ip, exporter_uid_ref, node_uid_ref,
                                            prefix + "-alertmanager:9093")
    # Keep raw Pod and GPU identifiers out of the persisted Prometheus rules. The
    # one-GPU workload name is selected here; runtime series labels are compared
    # to current API/PodResources identities in memory and hashed in the receiver.
    selector = f'namespace="{WORKLOAD_NS}",pod="{WORKLOAD_POD}",container="{WORKLOAD_CONTAINER}"'
    rules = {"groups": [{"name": "saf-a100-live-catch", "rules": [{
        "alert": "SAF_A100_FramebufferThreshold",
        "expr": f"{METRIC}{{{selector}}} > {threshold:.6f}",
        "for": "2s",
        "labels": {"severity": "warning", "source_age": "live", "workload_class": "known-good-fixture",
                   "workload_ref": pod_ref, "device_ref": device_ref, "metric_name": METRIC,
                   "source_kind": "live-dcgm", "capture_ref": runid, "threshold_mib": f"{threshold:.6f}"},
        "annotations": {"observed_mib": "{{ $value }}",
                        "summary": "Live A100 framebuffer threshold for known-good fixture workload"},
    }]}]}
    am_config = {"route": {"receiver": "discard", "group_by": ["alertname", "capture_ref"],
                           "group_wait": "1s", "group_interval": "10s", "repeat_interval": "1h",
                           "routes": [{"receiver": "case-local-live-hold",
                                       "matchers": ['alertname="SAF_A100_FramebufferThreshold"']} ]},
                 "receivers": [{"name": "discard"}, {"name": "case-local-live-hold",
                              "webhook_configs": [{"url": f"http://saf-a100-catch-{runid}-receiver:18082/events",
                                                   "send_resolved": False, "max_alerts": 1}]}]}
    assets = {"prometheus.yml": json.dumps(prom_config), "rules.yml": json.dumps(rules),
              "alertmanager.yml": json.dumps(am_config), "receiver.py": receiver_source()}
    owned.create({"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": cfg_name, "namespace": prefix}, "immutable": True, "data": assets})
    for resource in pod_resource(prefix + "-receiver", PYTHON_IMAGE,
                                 ["python", "-B", "/fixture/receiver.py"], cfg_name, "receiver", 18082,
                                 readiness_path="/health"):
        resource["metadata"]["namespace"] = prefix
        owned.create(resource)
    for resource in pod_resource(prefix + "-alertmanager", ALERTMANAGER_IMAGE,
                                 ["/bin/alertmanager", "--config.file=/fixture/alertmanager.yml",
                                  "--storage.path=/scratch", "--cluster.listen-address="],
                                 cfg_name, "alertmanager", 9093, readiness_path="/-/ready"):
        resource["metadata"]["namespace"] = prefix
        owned.create(resource)
    for resource in pod_resource(prefix + "-prometheus", PROM_IMAGE,
                                 ["/bin/prometheus", "--config.file=/fixture/prometheus.yml",
                                  "--storage.tsdb.path=/scratch", "--storage.tsdb.retention.time=10m"],
                                 cfg_name, "prometheus", 9090, readiness_path="/-/ready"):
        resource["metadata"]["namespace"] = prefix
        owned.create(resource)
    pods = [f"pod/{prefix}-{component}" for component in ("receiver", "alertmanager", "prometheus")]
    kube(kubectl, kubeconfig, "-n", prefix, "wait", "--for=condition=Ready", *pods,
         "--timeout=100s", timeout=105)
    return prefix


def write_checkpoint(path, document):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(document, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def finish_allocator(worker, helper_log, allocator_sha):
    try:
        if worker.wait(timeout=125) != 0:
            return False
    except subprocess.TimeoutExpired:
        return False
    lines = helper_log.read_text().splitlines()
    return (any(line.startswith(allocator_sha + "  /tmp/saf-framebuffer-witness.") for line in lines)
            and "framebuffer_witness_released=1" in lines
            and "FRAMEBUFFER_WITNESS_PASS" in lines)


def approved_source(kubectl, kubeconfig, helper, profile, exporter_selector):
    workload, _, _ = ensure_pod_profile(kubectl, kubeconfig, profile)
    allocated, device_id, model, driver = nvidia_device(kubectl, kubeconfig, helper, profile)
    node_name = workload["spec"]["nodeName"]
    if (allocated["spec"]["nodeName"] != node_name
            or (model, driver) != (profile["hardware"]["model"], profile["hardware"]["driver"])):
        raise Blocked("Live GPU model, driver or node differs from the reviewed profile")
    exporter, container, status = find_exporter(kubectl, kubeconfig, exporter_selector, node_name)
    exporter_ref = sha(exporter["metadata"]["uid"])
    expected = profile["exporter"]
    if (exporter_ref, container["image"], status["imageID"]) != (
            expected["pod_uid_sha256"], expected["image"], expected["image_id"]):
        raise Blocked("Live exporter identity or image differs from the reviewed profile")
    node = kube_json(kubectl, kubeconfig, "get", "node", node_name, "-o", "json")
    node_ref = sha(node["metadata"]["uid"])
    if node_ref != profile["kubernetes"]["node_uid_sha256"]:
        raise Blocked("Live node UID differs from the reviewed profile")
    return {"node": node_name, "node_ref": node_ref, "workload_uid": workload["metadata"]["uid"],
            "device_id": device_id, "model": model, "driver": driver, "exporter_ref": exporter_ref,
            "exporter_name": exporter["metadata"]["name"], "ip": str(IPv4Address(exporter["status"]["podIP"])),
            "exporter_image_id": status["imageID"]}


def present_sample(sample, expected, earliest):
    return bool(sample and all(sample["labels"].get(key) == value for key, value in expected.items())
                and sample["timestamp"] >= earliest and -2 <= time.time() - sample["timestamp"] <= 15)


def bound_delivery(delivered, firing, alertmanager, labels, runid, threshold, earliest):
    expected = {"alertname": "SAF_A100_FramebufferThreshold", "workload_ref": sha(labels["pod_uid"]),
                "source_age": "live", "source_kind": "live-dcgm", "workload_class": "known-good-fixture",
                "pod_ref": sha(labels["pod_uid"]), "device_ref": sha(labels["UUID"]), "capture_ref": runid,
                "metric": METRIC, "receiver": "case-local-live-hold", "status": "firing",
                "threshold_mib": threshold}
    if any(delivered.get(key) != value for key, value in expected.items()):
        return False
    firing_labels = firing["labels"]
    exact = {**labels, "capture_ref": runid, "source_kind": expected["source_kind"],
             "source_age": "live", "metric_name": METRIC,
             "workload_ref": expected["workload_ref"], "device_ref": expected["device_ref"]}
    if any(firing_labels.get(key) != value for key, value in exact.items()):
        return False
    for event in alertmanager:
        fp = event.get("fingerprint", "")
        if (event.get("labels") == firing_labels and re.fullmatch(r"[0-9a-f]{16}", fp)
                and sha(fp) == delivered.get("fingerprint_sha256")):
            started_at = delivered.get("starts_at", "")
            try:
                when = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+(?=Z|[+-])", r"\1",
                                                        started_at).replace("Z", "+00:00")).timestamp()
            except (TypeError, ValueError, OSError):
                return False
            return (started_at == event.get("startsAt") and earliest <= when <= time.time() + 2
                    and math.isfinite(delivered["observed_mib"]) and delivered["observed_mib"] >= threshold)
    return False


def manager_alerts(request, namespace):
    script = ("import sys,urllib.request; "
              "print(urllib.request.urlopen(sys.argv[1],timeout=4).read().decode())")
    response = request("-n", namespace, "exec", "pod/" + namespace + "-receiver", "--", "python", "-c", script,
                       f"http://{namespace}-alertmanager:9093/api/v2/alerts", timeout=12)
    return json.loads(response.stdout)


def stop_worker(worker):
    if worker.poll() is None:
        worker.terminate()
        try:
            worker.wait(timeout=3)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait(timeout=3)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--profile", required=True, help="fresh safe A100 readiness JSON")
    parser.add_argument("--support-review", required=True, help="operator-reviewed A100 metric/version support statement")
    parser.add_argument("--exporter-selector", required=True, help="exact selector used by readiness preflight")
    parser.add_argument("--podresources-binary", required=True)
    parser.add_argument("--framebuffer-helper", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--exporter-port", type=int, default=19402)
    parser.add_argument("--prometheus-port", type=int, default=19092)
    args = parser.parse_args(argv)
    kubeconfig = Path(args.kubeconfig).expanduser()
    helper = Path(args.podresources_binary).expanduser()
    allocator = Path(args.framebuffer_helper).expanduser()
    evidence_dir = Path(args.evidence_dir).expanduser()
    if not (kubeconfig.is_absolute() and kubeconfig.is_file() and helper.is_file()
            and allocator.is_file() and evidence_dir.is_absolute()):
        raise Blocked("Explicit existing kubeconfig, reviewed binaries, and absolute evidence directory are required")
    if digest_bytes(helper.read_bytes()) != PODRESOURCES_FIXTURE:
        raise Blocked("PodResources helper differs from the reviewed A100 fixture pin")
    allocator_bytes = allocator.read_bytes()
    allocator_sha = digest_bytes(allocator_bytes)
    if allocator_sha not in FRAMEBUFFER_FIXTURES:
        raise Blocked("Known-good 128 MiB allocator does not match its reviewed SHA-256")
    profile = read_profile(args.profile)
    review = json.loads(Path(args.support_review).read_text())
    if profile.get("framebuffer_helper", {}).get("sha256") != allocator_sha:
        raise Blocked("The readiness profile refers to a different allocator build")
    if (review.get("schema") != "saf-a100-metric-support-review-v1"
            or review.get("status") != "reviewed-supported"
            or review.get("metric") != METRIC
            or review.get("device_model") != profile["hardware"]["model"]
            or review.get("driver") != profile["hardware"]["driver"]
            or review.get("exporter_image_digest") != profile["exporter"]["image_id"].split("sha256:")[-1]
            or not review.get("dcgm_version") or not review.get("exporter_version")
            or not isinstance(review.get("official_sources"), list) or not review["official_sources"]):
        raise Blocked("A reviewed A100/DCGM support statement must match the observed profile")
    evidence_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(evidence_dir, 0o700)
    kubectl = shutil.which("kubectl")
    if not kubectl:
        raise Blocked("kubectl is unavailable")

    runid = hashlib.sha256((utc() + profile["workload"]["uid_sha256"]).encode()).hexdigest()[:8]
    def read_source():
        return approved_source(kubectl, kubeconfig, helper, profile, args.exporter_selector)

    source = read_source()
    workload_uid = source["workload_uid"]
    device_id = source["device_id"]
    exporter_ip = source["ip"]
    node_name = source["node"]
    labels = {"namespace": WORKLOAD_NS, "pod": WORKLOAD_POD,
              "container": WORKLOAD_CONTAINER, "pod_uid": workload_uid, "UUID": device_id}
    scrape_labels = {**labels, "job": JOB, "instance": f"{exporter_ip}:9400",
                     "exporter_uid_ref": source["exporter_ref"], "node_uid_ref": source["node_ref"]}
    selector = ",".join(f"{key}={json.dumps(value)}" for key, value in scrape_labels.items())
    hold_name = gate.names(runid)[0]

    def request(*parts, obj=None, allow_failure=False, timeout=20):
        body = json.dumps(obj).encode() if obj is not None else None
        result = kube(kubectl, kubeconfig, *parts, input_bytes=body, timeout=timeout,
                      allow_failure=allow_failure, stderr_pipe=True)
        return subprocess.CompletedProcess(result.args, result.returncode,
                                           result.stdout.decode("utf-8"), result.stderr.decode("utf-8", "replace"))

    with gate.OwnedResources(request) as owned, ExitStack() as processes:
        gate.configure_identity(owned, runid)
        gate.wait_for_roles(request, runid)
        approval_hash = gate.create_approval(request, owned, runid)
        gate.install(owned, runid)
        monitor_epoch = time.time()
        forward = start_forward(kubectl, kubeconfig, OBS_NS, source["exporter_name"], args.exporter_port, 9400)
        processes.callback(stop_forward, forward)

        def direct_value():
            value = exporter_samples(args.exporter_port, labels)["value"]
            if not math.isfinite(value) or value < 0:
                raise Blocked("The joined direct exporter value is non-finite or negative")
            return value

        base = direct_value()
        threshold = base + HELD_BYTES / (1024 * 1024)
        prefix = deploy_monitors(kubectl, kubeconfig, owned, runid, exporter_ip, profile, threshold)
        for component, local, remote in (("prometheus", args.prometheus_port, 9090),
                                         ("receiver", args.exporter_port + 1, 18082)):
            proxy = start_forward(kubectl, kubeconfig, prefix, f"{prefix}-{component}", local, remote)
            processes.callback(stop_forward, proxy)

        def current_target():
            state = get_json(f"http://127.0.0.1:{args.prometheus_port}/api/v1/targets?state=active")
            rows = state.get("data", {}).get("activeTargets", [])
            matches = [row for row in rows if row.get("scrapePool") == JOB
                       and row.get("scrapeUrl") == f"http://{exporter_ip}:9400/metrics"
                       and row.get("health") == "up"
                       and all(row.get("labels", {}).get(key) == scrape_labels[key]
                               for key in ("job", "instance", "exporter_uid_ref", "node_uid_ref"))]
            return len(matches) == 1

        def receiver_events():
            return get_json(f"http://127.0.0.1:{args.exporter_port + 1}/events")

        if not wait_for(current_target, seconds=60):
            raise Blocked("Prometheus did not verify the exact healthy exporter target")

        def fresh_sample(earliest):
            candidate = query_metric(args.prometheus_port, selector)
            return candidate if present_sample(candidate, scrape_labels, earliest) else None

        baseline = wait_for(lambda: fresh_sample(monitor_epoch), seconds=40)
        if (not baseline or abs(baseline["value_mib"] - base) > 16 or baseline["value_mib"] >= threshold
                or alert_state(args.prometheus_port) != [] or receiver_events() != []):
            raise Blocked("The fresh sourced baseline or empty receiver check failed")

        first_allocation_time = time.time()
        helper_log = evidence_dir / "framebuffer-worker.private.log"
        with helper_log.open("xb") as log:
            remote = (
                'command -v timeout >/dev/null || exit 90; umask 077; '
                'p=$(mktemp /tmp/saf-framebuffer-witness.XXXXXX) || exit; '
                'trap \'rm -f -- "$p"\' EXIT; '
                'cat > "$p" && chmod 700 "$p" && sha256sum "$p" && timeout -k 5s 135s "$p"'
            )
            worker = subprocess.Popen([kubectl, "--kubeconfig", str(kubeconfig), "-n", WORKLOAD_NS,
                                       "exec", "-i", "pod/" + WORKLOAD_POD, "-c", WORKLOAD_CONTAINER,
                                       "--", "/bin/sh", "-c", remote],
                                      stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
            processes.callback(stop_worker, worker)
            try:
                worker.stdin.write(allocator_bytes)
                worker.stdin.close()
            except OSError as exc:
                raise Blocked("The bounded allocator could not be sent to the fixture Pod") from exc
        allocated = "framebuffer_witness_allocated_bytes=134217728"
        if not wait_for(lambda: allocated in helper_log.read_text().splitlines(), seconds=20) or worker.poll() is not None:
            raise Blocked("The running helper did not report the exact bounded allocation")

        def alert_data():
            sample = fresh_sample(first_allocation_time)
            direct = direct_value()
            firing = alert_state(args.prometheus_port)
            deliveries = receiver_events()
            if (sample and direct >= threshold and sample["value_mib"] >= threshold and firing
                    and len(firing) == 1 and isinstance(deliveries, list) and len(deliveries) == 1):
                return sample, direct, firing[0], deliveries[0]
            return None

        captured = wait_for(alert_data, seconds=80)
        if captured is None:
            raise Blocked("No fresh threshold sample, exact firing alert and one case-local delivery were observed")
        sample, observed_direct, firing, delivered = captured
        alertmanager = manager_alerts(request, prefix)
        if (not isinstance(alertmanager, list) or len(alertmanager) != 1 or not current_target()
                or read_source() != source
                or not bound_delivery(delivered, firing, alertmanager, labels, runid, threshold, first_allocation_time)
                or not present_sample(sample, scrape_labels, first_allocation_time)):
            raise Blocked("Routed evidence no longer matches the exact current workload, device and reviewed source")
        if (observed_direct - base < HELD_BYTES / (1024 * 1024)
                or sample["value_mib"] - baseline["value_mib"] < HELD_BYTES / (1024 * 1024)):
            raise Blocked("Direct and scraped values do not both cover the expected framebuffer allocation")

        sample_time = utc(datetime.fromtimestamp(sample["timestamp"], timezone.utc))
        receipt = {
            "schema": "saf-a100-live-threshold-evidence-v1", "source_age_class": "live",
            "captured_at_utc": utc(), "hardware_model": source["model"], "driver": source["driver"],
            "workload": {"namespace": WORKLOAD_NS, "name": WORKLOAD_POD, "container": WORKLOAD_CONTAINER,
                         "uid_sha256": sha(workload_uid)},
            "device": {"gpu_uuid_sha256": sha(device_id), "resource_name": "nvidia.com/gpu"},
            "exporter": {"pod_uid_sha256": source["exporter_ref"], "image_id": source["exporter_image_id"],
                         "prometheus_job": JOB, "target_health": "up"},
            "metric": METRIC, "unit": "MiB", "baseline_direct_mib": base,
            "baseline_prometheus_mib": baseline["value_mib"], "observed_direct_mib": observed_direct,
            "observed_prometheus_mib": sample["value_mib"], "threshold_mib": threshold,
            "expected_fixture_allocation_bytes": HELD_BYTES, "source_sample_timestamp_utc": sample_time,
            "freshness_window_seconds": 15, "sample_labels_match_workload_and_device": True,
            "alert_fingerprint_sha256": delivered["fingerprint_sha256"],
            "source_summary_sha256": SOURCE_SUMMARY_SHA, "historical_reference_summary_sha256": SOURCE_SUMMARY_SHA,
            "historical_reference_used_as_live_input": False,
        }
        receipt_path = evidence_dir / "live-threshold-evidence.json"
        write_checkpoint(receipt_path, receipt)
        receipt_hash = digest_bytes(receipt_path.read_bytes())
        hold_data = {"disposition": "hold", "signal": "high", "workload": "approved",
                     "corroboration": "missing", "source_age": "live", "source_kind": "dcgm-live",
                     "receipt_sha256": receipt_hash, "alert_fingerprint_sha256": delivered["fingerprint_sha256"],
                     "workload_ref": sha(workload_uid), "device_ref": sha(device_id), "hold_name": hold_name,
                     "metric": METRIC, "threshold_mib": f"{threshold:.6f}",
                     "observed_mib": f"{sample['value_mib']:.6f}", "capture_ref": runid, "known_good_fixture": "true"}
        hold_obj = {"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": hold_name, "namespace": WORKLOAD_NS},
                    "immutable": True, "data": hold_data}
        escalation = gate.escalation_for(hold_obj, runid)
        attempts = gate.establish_enforcement(request, runid, hold_obj, escalation)
        still_live = fresh_sample(first_allocation_time)
        if (worker.poll() is not None or not still_live
                or still_live["value_mib"] < threshold or direct_value() < threshold):
            raise Blocked("The bounded allocation stopped before the hold could be recorded")
        decision = gate.retain_hold_and_check(request, runid, hold_obj, escalation)
        if worker.poll() is not None:
            raise Blocked("The bounded allocation stopped while retaining the hold")
        approval = gate.verify_corroboration(request, runid, hold_obj)
        write_checkpoint(evidence_dir / "admission-decision.json", {
            "schema": "saf-a100-admission-checkpoint-v2", **decision, **approval,
            "independent_approval_sha256": approval_hash, "threshold_receipt_sha256": receipt_hash})
        if not all(decision.values()) or not all(approval.values()) or not attempts:
            raise Blocked("The exact hold, escalation denial or separate comparator decision failed")
        if not finish_allocator(worker, helper_log, allocator_sha):
            raise Blocked("The allocator did not confirm release and a clean exit")

        def released_sample():
            value = direct_value()
            return {"direct_mib": value, "observed_at_utc": utc()} if abs(value - base) <= 16 else None

        release = wait_for(released_sample, seconds=45)
        after = kube_json(kubectl, kubeconfig, "-n", WORKLOAD_NS, "get", "pod", WORKLOAD_POD, "-o", "json")
        if (release is None or read_source() != source or after["metadata"]["uid"] != workload_uid
                or after["status"]["phase"] != "Running" or after["spec"]["nodeName"] != node_name):
            raise Blocked("The original running workload and source did not confirm framebuffer recovery")
        write_checkpoint(evidence_dir / "allocator-release.json", {
            "schema": "saf-a100-framebuffer-release-v1", "workload_ref": sha(workload_uid),
            "device_ref": sha(device_id), "allocator_sha256": allocator_sha,
            "baseline_direct_mib": base, "recovery_tolerance_mib": 16, **release})
        raw = {
            "schema": "saf-a100-catch-hold-raw-v2", "status": "passed",
            "profile_readiness_timestamp_utc": profile["captured_at_utc"],
            "profile_model": source["model"], "source_support_review": review,
            "workload_ref": sha(workload_uid), "device_ref": sha(device_id),
            "exporter_ref": source["exporter_ref"], "node_ref": source["node_ref"],
            "metric": METRIC, "unit": "MiB", "baseline_direct_mib": base,
            "baseline_prometheus_mib": baseline["value_mib"], "observed_direct_mib": observed_direct,
            "observed_prometheus_mib": sample["value_mib"], "threshold_mib": threshold,
            "source_sample_timestamp_utc": sample_time, "source_age_class": "live",
            "allocator_bytes": HELD_BYTES, "allocator_sha256": allocator_sha, "allocator_release_verified": True,
            **decision, **approval, "independent_approval_sha256": approval_hash,
            "alert_route_bound_to_known_good_fixture": True, "escalation_readiness_attempts": attempts,
            "effective_binding_proved_before_hold": True, "workload_same_uid_running": True,
            "disruptive_action_requested": False, "incident_or_misuse_claimed": False,
            "freshness_window_seconds": 15, "historical_context_is_not_live_input": True,
        }
    retained = json.loads(request("-n", WORKLOAD_NS, "get", "configmap", hold_name, "-o", "json").stdout)
    if retained["immutable"] is not True or retained["data"] != hold_data:
        raise Blocked("The retained hold differed after the case-owned resources were removed")
    raw.update(fixture_resources_removed=True, hold_preserved_after_cleanup=True)
    write_checkpoint(evidence_dir / "catch-hold.raw.json", raw)
    print(json.dumps({"status": raw["status"], "receipt_sha256": receipt_hash}, sort_keys=True))
    return 0


def interrupted(_signal, _frame):
    raise Blocked("A100 hold check interrupted before a complete receipt")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main())
    except (Blocked, gate.AdmissionError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)
