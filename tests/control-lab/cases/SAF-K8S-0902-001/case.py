"""Exercise a synthetic inference workload's hardened runtime contract."""
import hashlib
import ipaddress
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0902-001"
NAMESPACE = "saf-0902-001"
APP = "mock-inference"
POD_LABELS = {"app": APP, "saf-lab.example/control": CONTROL_ID}
MODEL_CONFIG = "synthetic-model"
DEPLOYMENT = APP
APPROVED_DEPLOYMENT = "approved-local-sink"
UNAPPROVED_DEPLOYMENT = "unapproved-local-sink"
POLICY = "inference-egress"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "One disposable Kind v1.36.1 cluster with a synthetic inference HTTP Pod and two owned HTTP sinks. "
    "An independent runtime probe verifies the effective nonroot identity, root filesystem and model "
    "mounts, exact synthetic model bytes, and permitted scratch writes. An egress allowlist keeps "
    "one Ready peer reachable and denies the other while an unselected peer still reaches it. "
    "A controlled setting change verifies the root filesystem write comparator. "
    "Actual serving stacks, production dependencies, network boundaries and patch cadence require "
    "separate evidence."
)


def fixture():
    data = json.loads((HERE / "fixtures.json").read_text())
    model_bytes = (json.dumps(data["model"], sort_keys=True, separators=(",", ":")) + "\n").encode()
    if hashlib.sha256(model_bytes).hexdigest() != data["expected_sha256"]:
        raise ValueError("Pinned synthetic model fixture hash does not match its contents")
    data["model_bytes"] = model_bytes.decode()
    return data


def _labels(extra=None):
    return {**POD_LABELS, **(extra or {})}


def resources(data):
    model = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": MODEL_CONFIG, "namespace": NAMESPACE,
                     "labels": {"saf-lab.example/control": CONTROL_ID,
                                "saf-lab.example/fixture": "synthetic"}},
        "data": {"model.json": data["model_bytes"]},
    }
    namespace = {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": NAMESPACE,
                     "labels": {"saf-lab.example/control": CONTROL_ID,
                                "pod-security.kubernetes.io/enforce": "restricted",
                                "pod-security.kubernetes.io/enforce-version": "v1.36"}},
    }
    inference_code = '''
import http.server
import json
import pathlib
from urllib.parse import parse_qs, urlparse

model = json.loads(pathlib.Path("/opt/model/model.json").read_text())

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ready":
            payload = {"ready": True, "model_id": model["model_id"]}
            status = 200
        elif self.path.startswith("/infer?"):
            key = parse_qs(urlparse(self.path).query).get("input", [""])[0]
            payload = {"model_id": model["model_id"], "result": model["weights"].get(key, "unknown")}
            status = 200
        else:
            payload, status = {"error": "not found"}, 404
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''
    sink_code = '''
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"synthetic-sink-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''
    workload_base = {
        "replicas": 1,
        "selector": {"matchLabels": {"app": APP}},
        "template": {
            "metadata": {"labels": _labels()},
            "spec": {
                "automountServiceAccountToken": False,
                "terminationGracePeriodSeconds": 1,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "fsGroup": 10001,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "mock-inference", "image": PYTHON_IMAGE,
                    "imagePullPolicy": "IfNotPresent", "command": ["python", "-c", inference_code],
                    "ports": [{"name": "http", "containerPort": 8080}],
                    "readinessProbe": {"httpGet": {"path": "/ready", "port": "http"},
                                        "periodSeconds": 2, "failureThreshold": 15},
                    "securityContext": {"allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [
                        {"name": "model", "mountPath": "/opt/model", "readOnly": True},
                        {"name": "case-work", "mountPath": "/case-work", "readOnly": False},
                    ],
                    "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                  "limits": {"cpu": "100m", "memory": "96Mi"}},
                }],
                "volumes": [
                    {"name": "model", "configMap": {"name": MODEL_CONFIG,
                                                       "items": [{"key": "model.json", "path": "model.json"}]}},
                    {"name": "case-work", "emptyDir": {}},
                ],
            },
        },
    }
    inference = {"apiVersion": "apps/v1", "kind": "Deployment",
                 "metadata": {"name": DEPLOYMENT, "namespace": NAMESPACE,
                              "labels": {"saf-lab.example/control": CONTROL_ID}},
                 "spec": workload_base}
    sinks = []
    for name, approved in ((APPROVED_DEPLOYMENT, "true"), (UNAPPROVED_DEPLOYMENT, "false")):
        labels = _labels({"egress-approved": approved, "role": "local-sink"})
        sinks.append({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": NAMESPACE,
                         "labels": {"saf-lab.example/control": CONTROL_ID}},
            "spec": {
                "replicas": 1, "selector": {"matchLabels": {"app": name}},
                "template": {"metadata": {"labels": {**labels, "app": name}}, "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "sink", "image": PYTHON_IMAGE,
                                    "imagePullPolicy": "IfNotPresent", "command": ["python", "-c", sink_code],
                                    "ports": [{"name": "http", "containerPort": 8080}],
                                    "readinessProbe": {"httpGet": {"path": "/", "port": "http"},
                                                        "periodSeconds": 2, "failureThreshold": 15},
                                    "securityContext": {"allowPrivilegeEscalation": False,
                                                        "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}},
                                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                  "limits": {"cpu": "50m", "memory": "64Mi"}}}],
                }},
            },
        })
    policy = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": POLICY, "namespace": NAMESPACE},
        "spec": {"podSelector": {"matchLabels": {"app": APP}}, "policyTypes": ["Egress"],
                 "egress": [{"to": [{"podSelector": {"matchLabels": {"role": "local-sink",
                                                                    "egress-approved": "true"}}}],
                             "ports": [{"protocol": "TCP", "port": 8080}]}]},
    }
    services = []
    for name in (APPROVED_DEPLOYMENT, UNAPPROVED_DEPLOYMENT):
        services.append({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": NAMESPACE,
                         "labels": {"saf-lab.example/control": CONTROL_ID}},
            "spec": {"selector": {"app": name},
                     "ports": [{"name": "http", "port": 8080, "targetPort": "http"}]},
        })
    return [namespace, model, *sinks, *services, inference], policy


def apply_resource(lab, resource):
    namespace = resource["metadata"].get("namespace")
    args = ["-n", namespace] if namespace else []
    lab.kubectl(*args, "apply", "-f", "-", payload=json.dumps(resource))


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def save_raw(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def wait_ready(lab, name):
    lab.kubectl("-n", NAMESPACE, "rollout", "status", f"deployment/{name}",
                "--timeout=150s", timeout=160)
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready",
                f"pod", "-l", f"app={name}", "--timeout=30s", timeout=40)


def deployment_and_pod(lab, name):
    deployment = get_json(lab, "-n", NAMESPACE, "get", "deployment", name)
    pods = get_json(lab, "-n", NAMESPACE, "get", "pods", "-l", f"app={name}")
    active = [pod for pod in pods.get("items", []) if not pod["metadata"].get("deletionTimestamp")]
    if len(active) != 1:
        lab.block(f"Expected exactly one active Pod for {name}")
    pod = active[0]
    if pod.get("metadata", {}).get("uid") is None:
        lab.block(f"Live Pod UID missing for {name}")
    return deployment, pod


def endpoint_ready(lab, service):
    doc = get_json(lab, "-n", NAMESPACE, "get", "endpointslices.discovery.k8s.io",
                   "-l", f"kubernetes.io/service-name={service}")
    ready = []
    for endpoint_slice in doc.get("items", []):
        for endpoint in endpoint_slice.get("endpoints", []):
            if endpoint.get("conditions", {}).get("ready") is True:
                ready.extend(endpoint.get("addresses", []))
    return ready, doc


def exec_python(lab, pod_name, container, code, *args):
    return lab.kubectl("-n", NAMESPACE, "exec", pod_name, "-c", container,
                       "--", "python", "-c", code, *args, timeout=23).stdout.strip()


def runtime_probe(lab, pod_name):
    return json.loads(exec_python(lab, pod_name, "mock-inference", (HERE / "runtime.py").read_text()))


def http_probe(lab, pod_name, container, ip):
    address = str(ipaddress.ip_address(ip))
    return json.loads(exec_python(lab, pod_name, container, (HERE / "network.py").read_text(), address))


def peer_ready(lab, name):
    _, pod = deployment_and_pod(lab, name)
    ip = pod["status"]["podIP"]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        endpoints, document = endpoint_ready(lab, name)
        if endpoints == [ip]:
            return pod["metadata"]["name"], ip, document
        time.sleep(0.25)
    lab.block("The expected owned endpoint did not become Ready")


def run(lab):
    data = fixture()
    objects, policy = resources(data)
    for resource in objects:
        apply_resource(lab, resource)
    for name in (APPROVED_DEPLOYMENT, UNAPPROVED_DEPLOYMENT, DEPLOYMENT):
        wait_ready(lab, name)

    dep, pod = deployment_and_pod(lab, DEPLOYMENT)
    spec = dep["spec"]["template"]["spec"]
    container = spec["containers"][0]
    api_posture = {
        "pod_uid": pod["metadata"]["uid"],
        "namespace_uid": get_json(lab, "get", "namespace", NAMESPACE)["metadata"]["uid"],
        "pod_phase": pod.get("status", {}).get("phase"),
        "pod_ready": any(c.get("type") == "Ready" and c.get("status") == "True"
                          for c in pod.get("status", {}).get("conditions", [])),
        "container_image": container["image"],
        "service_account_token_automount": spec.get("automountServiceAccountToken"),
        "pod_security_context": spec.get("securityContext"),
        "container_security_context": container.get("securityContext"),
        "volume_mounts": container.get("volumeMounts", []),
        "model_configmap_uid": get_json(lab, "-n", NAMESPACE, "get", "configmap", MODEL_CONFIG)["metadata"]["uid"],
    }
    pod_name = pod["metadata"]["name"]
    runtime = runtime_probe(lab, pod_name)
    witness, approved_ip, approved_api = peer_ready(lab, APPROVED_DEPLOYMENT)
    _, blocked_ip, unapproved_api = peer_ready(lab, UNAPPROVED_DEPLOYMENT)
    success = {"status": 200, "body": "synthetic-sink-ok"}
    baseline = [http_probe(lab, pod_name, "mock-inference", ip)
                for ip in (approved_ip, blocked_ip)]
    if baseline != [success, success]:
        lab.block(f"Both owned listeners must work before applying policy: {baseline}")
    lab.check("red", "Before policy, both ready local listeners return their fixture marker",
              baseline == [success, success], {"source_received_both_exact_markers": True})

    apply_resource(lab, policy)
    deadline = time.monotonic() + 18
    pair = []
    while time.monotonic() < deadline:
        pair = [http_probe(lab, pod_name, "mock-inference", ip)
                for ip in (approved_ip, blocked_ip)]
        if pair == [success, {"error": "TimeoutError"}]:
            break
        time.sleep(0.25)
    witness_result = http_probe(lab, witness, "sink", blocked_ip)
    network_observation = {"baseline": baseline, "after_policy": pair, "witness": witness_result}
    live_policy = get_json(lab, "-n", NAMESPACE, "get", "networkpolicy", POLICY)
    api_posture["network_policy"] = live_policy
    inference_result = json.loads(lab.kubectl(
        "-n", NAMESPACE, "exec", pod["metadata"]["name"], "-c", "mock-inference", "--",
        "python", "-c",
        "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/infer?input=fixture-alpha').read().decode())",
        timeout=30,
    ).stdout.strip().splitlines()[-1])
    raw = {"api_posture": api_posture, "runtime_probe": runtime,
           "endpoint_slices": {"approved": approved_api, "unapproved": unapproved_api},
           "network_observation": network_observation, "benign_inference": inference_result,
           "fixture": {"notice": data["fixture_notice"], "model_id": data["model"]["model_id"],
                       "expected_sha256": data["expected_sha256"]}}
    save_raw(lab, "inference-hardening.raw.json", raw)

    pod_sec = api_posture["pod_security_context"] or {}
    csec = api_posture["container_security_context"] or {}
    mounts = api_posture["volume_mounts"]
    model_mounts = [mount for mount in mounts if mount.get("mountPath") == "/opt/model"]
    work_mounts = [mount for mount in mounts if mount.get("mountPath") == "/case-work"]
    lab.check("green", "Live API posture is restricted and model mount is exactly read-only",
              api_posture["pod_ready"] and api_posture["pod_uid"] and
              api_posture["container_image"] == PYTHON_IMAGE and
              "@sha256:" in api_posture["container_image"] and
              api_posture["service_account_token_automount"] is False and
              pod_sec.get("runAsNonRoot") is True and pod_sec.get("runAsUser") == 10001 and
              pod_sec.get("seccompProfile", {}).get("type") == "RuntimeDefault" and
              csec.get("allowPrivilegeEscalation") is False and
              csec.get("readOnlyRootFilesystem") is True and
              csec.get("capabilities", {}).get("drop") == ["ALL"] and
              len(model_mounts) == 1 and model_mounts[0].get("readOnly") is True and
              len(work_mounts) == 1 and work_mounts[0].get("readOnly", False) is False,
              {"pod_uid_present": bool(api_posture["pod_uid"]),
               "security_context_matches": {"runAsNonRoot": pod_sec.get("runAsNonRoot"),
                                             "runAsUser": pod_sec.get("runAsUser"),
                                             "readOnlyRootFilesystem": csec.get("readOnlyRootFilesystem")},
               "exact_model_mount_count": len(model_mounts),
               "model_mount_readOnly": model_mounts[0].get("readOnly") if model_mounts else None})

    lab.check("positive", "Runtime reads the exact fixture model, runs as the declared UID, blocks protected writes and writes only to case scratch",
              runtime.get("uid") == 10001 and
              runtime.get("model_sha256") == data["expected_sha256"] and
              runtime.get("model_mountpoint") == "/opt/model" and
              "ro" in runtime.get("model_mount_options", "").split(",") and
              runtime.get("model_write_errno") == 30 and runtime.get("rootfs_write_errno") == 30 and
              runtime.get("rootfs_readonly") is True and
              runtime.get("scratch_readback") == "synthetic-write-ok" and
              inference_result == {"model_id": data["model"]["model_id"], "result": "synthetic-label-a"},
              {"runtime_uid": runtime.get("uid"), "model_sha256_matches": runtime.get("model_sha256") == data["expected_sha256"],
               "model_mount_options": runtime.get("model_mount_options"),
               "model_write_errno": runtime.get("model_write_errno"),
               "rootfs_readonly": runtime.get("rootfs_readonly"),
               "rootfs_write_errno": runtime.get("rootfs_write_errno"),
               "case_scratch_readback": runtime.get("scratch_readback"),
               "synthetic_inference_result": inference_result})

    lab.check("green", "The exact egress allowlist permits the approved peer and denies the other",
              live_policy["spec"] == policy["spec"]
              and pair == [success, {"error": "TimeoutError"}] and witness_result == success,
              {"exact_policy_readback": live_policy["spec"] == policy["spec"],
               "approved_marker_received": pair[0] == success,
               "unapproved_peer_timed_out": pair[1] == {"error": "TimeoutError"},
               "same_unapproved_listener_remained_available": witness_result == success})

    patch = [{"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
              "value": False}]
    lab.kubectl("-n", NAMESPACE, "patch", "deployment", DEPLOYMENT, "--type=json", "-p", json.dumps(patch))
    wait_ready(lab, DEPLOYMENT)
    _, comparator = deployment_and_pod(lab, DEPLOYMENT)
    comparator_runtime = runtime_probe(lab, comparator["metadata"]["name"])
    raw["writable_root_comparator"] = comparator_runtime
    save_raw(lab, "inference-hardening.raw.json", raw)
    lab.check("red", "Disabling the root read-only setting permits the identical fixture write",
              comparator["metadata"]["uid"] != pod["metadata"]["uid"]
              and comparator_runtime["rootfs_readonly"] is False
              and comparator_runtime["rootfs_write_errno"] is None
              and comparator_runtime["rootfs_write_readback"] == "synthetic",
              {"separate_comparator_pod": comparator["metadata"]["uid"] != pod["metadata"]["uid"],
               "root_mount_readonly": comparator_runtime["rootfs_readonly"],
               "root_probe_write_errno": comparator_runtime["rootfs_write_errno"],
               "root_probe_readback": comparator_runtime["rootfs_write_readback"]})
