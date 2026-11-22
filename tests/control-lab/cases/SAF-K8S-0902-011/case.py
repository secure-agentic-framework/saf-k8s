"""Verify a bounded synthetic marker filter at one Kubernetes mock endpoint."""
import http.client
import json
from pathlib import Path
import socket
import subprocess
import time


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0902-011"
NAMESPACE = "saf-test"
DEPLOYMENT = "saf-0902-011-stream-filter"
SERVICE = DEPLOYMENT
CONFIG = DEPLOYMENT
APP_LABEL = "saf-k8s.example/0902-011"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster and one case-owned, single-replica Python mock endpoint. "
    "A bounded, fixed-marker streaming filter receives three benign fixture chunks and holds at most a chunk "
    "plus the longest marker window. Separate loopback HTTP clients collect the disabled-filter control and "
    "enabled-filter response over HTTP/1.1 chunked encoding, with a client acknowledgement before the source releases the rest. The evidence establishes only withholding of one fixture-designated dummy word "
    "across chunk seams while a permitted public synthetic marker remains visible. It does not validate real "
    "PII/secret classes, policy classifiers, real protocols or serving stacks, model safety, or production controls."
)


def fixture():
    return json.loads((HERE / "fixtures.json").read_text())


def evidence(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def port_forward(lab):
    # Bind only the local loopback; the selected cluster/context comes from the runner.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--namespace", NAMESPACE, "port-forward", f"service/{SERVICE}", f"{port}:8080",
         "--address", "127.0.0.1"],
        env=lab.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            lab.block("Loopback port-forward exited before the mock endpoint became reachable")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return process, port
        except OSError:
            time.sleep(0.2)
    process.terminate()
    process.wait(timeout=5)
    lab.block("Loopback port-forward did not become ready")


def collect(port, filter_mode, read_size):
    """Collect bytes independently from the client side in deliberately small reads."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request("GET", f"/stream?filter={filter_mode}", headers={"Connection": "close"})
        response = connection.getresponse()
        prefix = response.read(read_size)
        advance = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            advance.request("GET", f"/advance?filter={filter_mode}")
            acknowledgment = advance.getresponse().status
        finally:
            advance.close()
        pieces = [prefix]
        read_sizes = [len(prefix)]
        while True:
            part = response.read(read_size)
            if not part:
                break
            pieces.append(part)
            read_sizes.append(len(part))
        return {
            "status": response.status,
            "filter_header": response.getheader("X-SAF-Filter"),
            "body": b"".join(pieces).decode("utf-8"),
            "client_read_sizes": read_sizes,
            "encoding": response.getheader("Transfer-Encoding"),
            "prefix_before_remaining_source": prefix.decode("ascii"),
            "source_advance_ack": acknowledgment,
        }
    finally:
        connection.close()


def split_across_fixture_chunks(chunks, marker):
    joined = "".join(chunks)
    start = joined.index(marker)
    end = start + len(marker)
    return any(start < len("".join(chunks[:index])) < end for index in range(1, len(chunks)))


def run(lab):
    data = fixture()
    permitted = data["permitted_marker"]
    forbidden = data["forbidden_dummy_marker"]
    chunks = data["chunks"]
    limits = data["limits"]
    source_size = sum(len(item.encode("utf-8")) for item in chunks)
    max_marker = max(len(permitted), len(forbidden))
    both_split = split_across_fixture_chunks(chunks, permitted) and split_across_fixture_chunks(chunks, forbidden)
    bounded_fixture = (source_size <= limits["max_response_bytes"]
                       and all(len(item.encode("utf-8")) <= limits["max_chunk_bytes"] for item in chunks))
    lab.check("positive", "Fixed benign source fixture is bounded and splits both markers across chunks",
              both_split and bounded_fixture,
              {"both_markers_cross_chunk_boundaries": both_split,
               "source_bytes_within_limit": source_size <= limits["max_response_bytes"],
               "each_chunk_within_limit": all(len(item.encode("utf-8")) <= limits["max_chunk_bytes"]
                                               for item in chunks),
               "longest_marker_window_characters": max_marker})

    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG, "labels": {APP_LABEL: "fixture"}},
        "data": {"endpoint.py": (HERE / "endpoint.py").read_text(),
                 "fixtures.json": json.dumps(data, sort_keys=True)},
    })
    labels = {"app": DEPLOYMENT, APP_LABEL: "fixture"}
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": DEPLOYMENT, "labels": {APP_LABEL: "fixture"}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": DEPLOYMENT}},
                 "template": {"metadata": {"labels": labels}, "spec": {
                     "automountServiceAccountToken": False,
                     "terminationGracePeriodSeconds": 3,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                          "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "mock-stream", "image": IMAGE,
                                     "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-B", "/case/endpoint.py"],
                                     "ports": [{"name": "http", "containerPort": 8080}],
                                     "readinessProbe": {"httpGet": {"path": "/healthz", "port": "http"},
                                                        "periodSeconds": 1},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                          "readOnlyRootFilesystem": True,
                                                          "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"requests": {"cpu": "10m", "memory": "20Mi"},
                                                   "limits": {"cpu": "100m", "memory": "64Mi"}},
                                     "volumeMounts": [{"name": "fixture", "mountPath": "/case",
                                                        "readOnly": True}]}],
                     "volumes": [{"name": "fixture", "configMap": {"name": CONFIG,
                                                                        "defaultMode": 292}}]}}},
    })
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": SERVICE, "labels": {APP_LABEL: "fixture"}},
                "spec": {"type": "ClusterIP", "selector": {"app": DEPLOYMENT},
                         "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})
    lab.kubectl("rollout", "status", f"deployment/{DEPLOYMENT}", "--timeout=120s", timeout=130)
    deployment = json.loads(lab.kubectl("get", "deployment", DEPLOYMENT, "-o", "json").stdout)
    ready = deployment.get("status", {}).get("readyReplicas", 0) == 1
    uid = deployment.get("metadata", {}).get("uid")
    evidence(lab, "endpoint-deployment.raw.json", deployment)
    lab.check("positive", "The owned mock streaming endpoint is API-observed Ready",
              ready and bool(uid), {"ready_replicas": deployment.get("status", {}).get("readyReplicas", 0),
                                   "deployment_uid_present": bool(uid), "image": IMAGE})

    forward, port = port_forward(lab)
    try:
        baseline = collect(port, "off", limits["client_read_bytes"])
        # Do not persist or print the disabled-filter body; retain only independent observations.
        prefix = chunks[0][:limits["client_read_bytes"]]
        red = {"status": baseline["status"], "filter_header": baseline["filter_header"],
               "client_read_sizes": baseline["client_read_sizes"],
               "permitted_marker_reached_client": permitted in baseline["body"],
               "dummy_marker_reached_client": forbidden in baseline["body"],
               "chunked_prefix_before_source_continued": baseline["encoding"] == "chunked"
               and baseline["prefix_before_remaining_source"] == prefix and baseline["source_advance_ack"] == 204}
        evidence(lab, "filter-disabled-client-observation.raw.json", red)
        lab.check("red", "Without filtering, the fixture-designated dummy marker reaches the client",
                  baseline["status"] == 200 and baseline["filter_header"] == "disabled"
                  and red["chunked_prefix_before_source_continued"]
                  and baseline["body"] == "".join(chunks) and forbidden in baseline["body"], red)

        filtered = collect(port, "on", limits["client_read_bytes"])
        green = {"status": filtered["status"], "filter_header": filtered["filter_header"],
                 "client_read_sizes": filtered["client_read_sizes"],
                 "dummy_marker_absent_from_client": forbidden not in filtered["body"],
                 "redaction_marker_present": data["replacement"] in filtered["body"],
                 "permitted_marker_reached_client": permitted in filtered["body"],
                 "client_body": filtered["body"],
                 "chunked_prefix_before_source_continued": filtered["encoding"] == "chunked"
                 and filtered["prefix_before_remaining_source"] == prefix and filtered["source_advance_ack"] == 204}
        evidence(lab, "filter-enabled-client-stream.raw.json", green)
        lab.check("green", "With filtering enabled, the dummy marker never reaches the client",
                  filtered["status"] == 200 and filtered["filter_header"] == "enabled"
                  and green["chunked_prefix_before_source_continued"]
                  and filtered["body"] == "".join(chunks).replace(forbidden, data["replacement"])
                  and forbidden not in filtered["body"] and data["replacement"] in filtered["body"], green)
        lab.check("positive", "The permitted public synthetic marker still reaches the client",
                  permitted in filtered["body"],
                  {"permitted_marker_reached_client": permitted in filtered["body"],
                   "status": filtered["status"], "filter_header": filtered["filter_header"]})
    finally:
        forward.terminate()
        try:
            forward.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forward.kill()
            forward.wait(timeout=5)
