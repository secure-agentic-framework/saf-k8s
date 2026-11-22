"""Bounded sensitivity-stage reachability comparison for a disposable Kind cluster."""
from datetime import datetime, timezone
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
LOW_NS = "saf-0904-011-low"
HIGH_NS = "saf-0904-011-high"
SERVER = "saf-0904-011-endpoint"
LOW_PROBE = "saf-0904-011-low-probe"
HIGH_PROBE = "saf-0904-011-high-peer"
SERVICE = "saf-0904-011-endpoint"
PORT = 18080
MARKER = "SAF-K8S-0904-011-INERT"
ARTIFACT = "saf-0904-011-marker"
PROBE_IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
               "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
SCOPE = (
    "One fresh disposable Kubernetes v1.36.1 Kind cluster from the control lab, using its "
    "stock kindnet networking. Two case-owned namespaces are labeled low and high sensitivity. "
    "Distinct non-default ServiceAccounts with API-token automount disabled identify the low "
    "probe, high endpoint, and permitted high peer. A low-stage probe first fetches one exact "
    "inert marker from an HTTP endpoint in the high namespace before any NetworkPolicy exists. "
    "A case-owned standard Kubernetes NetworkPolicy then allows only the same-namespace high "
    "peer to the same endpoint; bounded requests verify low-stage denial and high-stage success. "
    "Native RBAC separately permits the exact synthetic artifact ConfigMap to the high peer "
    "and denies it to the low identity. Production orchestrator, runtime, and storage boundaries "
    "and complete policy coverage need separate evidence."
)


def _create(lab, obj):
    namespace = obj["metadata"]["namespace"]
    return json.loads(lab.kubectl("--namespace", namespace, "create", "-f", "-", "-o", "json",
                                  payload=json.dumps(obj)).stdout)


def _service_account(lab, namespace, name):
    _create(lab, {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": namespace},
        "automountServiceAccountToken": False,
    })


def _container(name, command):
    return {
        "name": name,
        "image": IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": ["sh", "-ec", command],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "resources": {
            "requests": {"cpu": "10m", "memory": "8Mi"},
            "limits": {"cpu": "100m", "memory": "32Mi"},
        },
    }


def _pod(namespace, name, stage, service_account, container, *, volumes=None):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"saf-k8s.example/stage": stage, "app": name},
        },
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "serviceAccountName": service_account,
            "containers": [container],
            **({"volumes": volumes} if volumes else {}),
        },
    }


def _create_namespace(lab, name, sensitivity):
    lab.kubectl("create", "namespace", name)
    lab.kubectl(
        "label", "namespace", name,
        f"saf-k8s.example/sensitivity={sensitivity}",
        "saf-k8s.example/owner=SAF-K8S-0904-011", "--overwrite",
    )


def _wait_ready(lab, namespace, name):
    lab.kubectl(
        "--namespace", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
        "--timeout=75s", timeout=85,
    )


def _fetch(lab, namespace, pod_name, ip):
    script = """
import http.client
import sys
connection = http.client.HTTPConnection(sys.argv[1], int(sys.argv[2]), timeout=1.5)
try:
    connection.request("GET", "/marker.txt")
    response = connection.getresponse()
    if response.status != 200:
        raise RuntimeError("unexpected fixture status")
    print("FETCH_OK|" + response.read().decode().strip())
except TimeoutError:
    print("FETCH_DENIED|timeout")
finally:
    connection.close()
"""
    started = time.monotonic()
    result = lab.kubectl("--namespace", namespace, "exec", pod_name, "--",
                         "python", "-B", "-c", script, ip, str(PORT), timeout=7)
    return result.stdout.strip(), round(time.monotonic() - started, 3), f"http://{ip}:{PORT}/marker.txt"


def _probe_container():
    result = _container("probe", "exec sleep 600")
    result["image"] = PROBE_IMAGE
    return result


def _pod_identity(lab, namespace, name):
    obj = json.loads(lab.kubectl("--namespace", namespace, "get", "pod", name, "-o", "json").stdout)
    metadata = obj["metadata"]
    return {
        "namespace": namespace,
        "name": name,
        "uid": metadata.get("uid"),
        "created_at": metadata.get("creationTimestamp"),
        "service_account": obj["spec"].get("serviceAccountName"),
        "labels": metadata.get("labels", {}),
    }


def run(lab):
    _create_namespace(lab, LOW_NS, "low")
    _create_namespace(lab, HIGH_NS, "high")
    _service_account(lab, LOW_NS, "low-stage")
    _service_account(lab, HIGH_NS, "high-endpoint")
    _service_account(lab, HIGH_NS, "high-stage-peer")

    _create(lab, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-0904-011-marker", "namespace": HIGH_NS},
        "data": {"marker.txt": MARKER + "\n"},
    })
    server_pod = _pod(
        HIGH_NS, SERVER, "high", "high-endpoint",
        _container("http", "exec busybox httpd -f -p 8080 -h /www"),
        volumes=[{"name": "inert-marker", "configMap": {"name": "saf-0904-011-marker"}}],
    )
    server_pod["spec"]["containers"][0]["volumeMounts"] = [
        {"name": "inert-marker", "mountPath": "/www", "readOnly": True},
    ]
    _create(lab, server_pod)
    _create(lab, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": HIGH_NS},
        "spec": {
            "selector": {"app": SERVER},
            "ports": [{"name": "http", "port": PORT, "targetPort": 8080, "protocol": "TCP"}],
        },
    })
    _create(lab, _pod(LOW_NS, LOW_PROBE, "low", "low-stage", _probe_container()))
    _create(lab, _pod(HIGH_NS, HIGH_PROBE, "high", "high-stage-peer", _probe_container()))
    _wait_ready(lab, HIGH_NS, SERVER)
    _wait_ready(lab, LOW_NS, LOW_PROBE)
    _wait_ready(lab, HIGH_NS, HIGH_PROBE)

    service = json.loads(lab.kubectl("--namespace", HIGH_NS, "get", "service", SERVICE, "-o", "json").stdout)
    service_ip = service["spec"]["clusterIP"]
    endpoint_url = f"http://{service_ip}:{PORT}/marker.txt"
    server_info = _pod_identity(lab, HIGH_NS, SERVER)
    end = time.monotonic() + 12
    while time.monotonic() < end:
        slices = json.loads(lab.kubectl("--namespace", HIGH_NS, "get", "endpointslice", "-l",
            f"kubernetes.io/service-name={SERVICE}", "-o", "json").stdout)
        ready = [entry.get("targetRef", {}).get("uid")
                 for item in slices["items"] for entry in (item.get("endpoints") or [])
                 if entry.get("conditions", {}).get("ready") is True]
        if ready == [server_info["uid"]]:
            break
        time.sleep(0.25)
    else:
        lab.block("Service did not converge to the exact owned endpoint")
    pre_policy = json.loads(lab.kubectl(
        "--namespace", HIGH_NS, "get", "networkpolicy", "-o", "json",
    ).stdout)
    if pre_policy.get("items"):
        lab.block("Unexpected NetworkPolicy exists in the case-owned high namespace before the red probe")
    red_output, red_seconds, _ = _fetch(lab, LOW_NS, LOW_PROBE, service_ip)
    if red_output != "FETCH_OK|" + MARKER:
        lab.block("The pre-policy low-stage request did not reach the exact owned endpoint; comparison is invalid")
    red_raw = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": red_seconds,
        "request_output": red_output,
        "endpoint_url": endpoint_url,
        "service_cluster_ip": service["spec"].get("clusterIP"),
        "low_probe": _pod_identity(lab, LOW_NS, LOW_PROBE),
        "high_endpoint": _pod_identity(lab, HIGH_NS, SERVER),
        "network_policy_present": False,
        "pre_policy_count": len(pre_policy.get("items", [])),
    }
    raw = {"red": red_raw}
    raw_path = lab.evidence / "stage-probe-raw.json"
    raw_path.write_text(json.dumps(raw, indent=2) + "\n")
    lab.check(
        "red", "With no case NetworkPolicy installed, the low-sensitivity stage reaches the exact high endpoint marker",
        True,
        {"request": "reached", "source_stage": "low", "marker": MARKER,
         "endpoint": "saf-0904-011-endpoint:18080/marker.txt", "network_policy": "absent"},
    )

    high_pre_output, high_pre_seconds, _ = _fetch(lab, HIGH_NS, HIGH_PROBE, service_ip)
    if high_pre_output != "FETCH_OK|" + MARKER:
        lab.block("The permitted high-stage peer could not reach the owned endpoint before policy")
    raw["high_peer_before_policy"] = {
        "elapsed_seconds": high_pre_seconds,
        "request_output": high_pre_output,
    }
    raw_path.write_text(json.dumps(raw, indent=2) + "\n")
    lab.kubectl("--namespace", HIGH_NS, "apply", "-f", str(HERE / "network-policy.yaml"))
    installed = json.loads(lab.kubectl(
        "--namespace", HIGH_NS, "get", "networkpolicy", "saf-0904-011-high-endpoint-ingress", "-o", "json",
    ).stdout)
    if installed.get("spec", {}).get("podSelector", {}).get("matchLabels", {}).get("app") != SERVER:
        lab.block("The installed NetworkPolicy does not select the owned high endpoint")

    blocked_output = None
    attempts = 0
    streak = 0
    elapsed = 0.0
    deadline = time.monotonic() + 24
    while time.monotonic() < deadline:
        attempts += 1
        blocked_output, duration, _ = _fetch(lab, LOW_NS, LOW_PROBE, service_ip)
        elapsed += duration
        if blocked_output == "FETCH_DENIED|timeout":
            streak += 1
            if streak == 2:
                break
            continue
        streak = 0
        if blocked_output != "FETCH_OK|" + MARKER:
            lab.block("Low-stage post-policy probe returned an unexpected endpoint response")
        time.sleep(0.5)

    low_blocked = streak == 2
    green_raw = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 3),
        "attempts": attempts,
        "last_request_output": blocked_output,
        "endpoint_url": endpoint_url,
        "service_cluster_ip": service["spec"].get("clusterIP"),
        "low_probe": _pod_identity(lab, LOW_NS, LOW_PROBE),
        "network_policy_present": True,
    }
    raw["green"] = green_raw
    raw_path.write_text(json.dumps(raw, indent=2) + "\n")
    lab.check(
        "green", "After policy convergence, the same low-stage workload cannot fetch that same high-stage marker",
        low_blocked,
        {"request": "blocked" if low_blocked else "still_reached",
         "source_stage": "low", "marker": MARKER if not low_blocked else None,
         "endpoint": "saf-0904-011-endpoint:18080/marker.txt",
         "network_policy": "present", "outcome": "denied" if low_blocked else "not_enforced"},
    )

    positive_output, positive_seconds, _ = _fetch(lab, HIGH_NS, HIGH_PROBE, service_ip)
    positive = positive_output == "FETCH_OK|" + MARKER
    positive_raw = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": positive_seconds,
        "request_output": positive_output,
        "endpoint_url": endpoint_url,
        "service_cluster_ip": service["spec"].get("clusterIP"),
        "high_peer": _pod_identity(lab, HIGH_NS, HIGH_PROBE),
        "network_policy_present": True,
    }
    raw["positive"] = positive_raw
    raw_path.write_text(json.dumps(raw, indent=2) + "\n")
    if not positive:
        lab.block("The ordinary high-stage peer did not reach the endpoint after policy; positive path failed")
    lab.check(
        "positive", "The ordinary permitted high-stage peer still fetches the exact marker after policy",
        positive,
        {"request": "reached", "source_stage": "high", "marker": MARKER,
         "endpoint": "saf-0904-011-endpoint:18080/marker.txt",
         "network_policy": "present", "outcome": "permitted"},
    )

    _create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                  "metadata": {"name": "high-stage-artifact-reader", "namespace": HIGH_NS},
                  "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                             "resourceNames": [ARTIFACT], "verbs": ["get"]}]})
    _create(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                  "metadata": {"name": "high-stage-artifact-reader", "namespace": HIGH_NS},
                  "subjects": [{"kind": "ServiceAccount", "name": "high-stage-peer",
                                "namespace": HIGH_NS}],
                  "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                              "name": "high-stage-artifact-reader"}})
    low = lab.kubectl("--namespace", HIGH_NS, "get", "configmap", ARTIFACT, "-o", "json",
                      f"--as=system:serviceaccount:{LOW_NS}:low-stage", allow_failure=True)
    high = lab.kubectl("--namespace", HIGH_NS, "get", "configmap", ARTIFACT, "-o", "json",
                       f"--as=system:serviceaccount:{HIGH_NS}:high-stage-peer")
    high_marker = json.loads(high.stdout)["data"]["marker.txt"]
    lower_denied = low.returncode != 0 and "forbidden" in low.stderr.lower() and ARTIFACT in low.stderr
    lab.check("green", "The low-stage identity is also forbidden to read the exact high-stage fixture object",
              lower_denied, {"low_identity_api_denied": lower_denied})
    lab.check("positive", "The narrowly bound high-stage identity reads the exact fixture object",
              high_marker == MARKER + "\n", {"permitted_identity_marker": high_marker.strip()})
