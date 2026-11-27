"""Bounded bundled-kindnet connectivity comparison for the model evaluator selector."""
import json
import time

NAMESPACE = "saf-test"
PEER = "native-model-unrelated-peer"
CLIENT = "native-model-connectivity-client"
EVALUATOR_LABEL = {"app": "native-model-evaluator"}
SERVER_LABEL = {"fixture": "saf-0905-045-native-model-server"}
PEER_LABEL = {"fixture": "saf-0905-045-unrelated-peer"}
PEER_CODE = "native-model-peer-code"

PEER_SCRIPT = r'''from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        body = b"peer-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''

PROBE_SCRIPT = r'''import json
import socket
import sys
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

client = build_opener(ProxyHandler({}))

def probe(address, expected):
    req = Request("http://" + address + ":8080/health", headers={"Connection": "close"})
    try:
        with client.open(req, timeout=3) as response:
            body = response.read(128)
            body_matches = (json.loads(body) == {"status": "ok"} if expected == "model-ok"
                            else body == b"peer-ok")
            if response.status == 200 and body_matches:
                return "reachable"
            return "unexpected"
    except (TimeoutError, socket.timeout):
        return "blocked"
    except URLError as error:
        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            return "blocked"
        raise

print(json.dumps({"model": probe(sys.argv[1], "model-ok"),
                  "peer": probe(sys.argv[2], "peer-ok")}, sort_keys=True))
'''


def _wait_ready(lab, resource, name, timeout=90):
    lab.kubectl("wait", "--for=condition=Ready", f"{resource}/{name}",
                f"--timeout={timeout}s", timeout=timeout + 10)


def _pod(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)


def _probe(lab, model_ip, peer_ip):
    result = lab.kubectl("exec", "pod/" + CLIENT, "--", "python", "-B", "-c",
                         PROBE_SCRIPT, model_ip, peer_ip, timeout=15, allow_failure=True)
    if result.returncode != 0:
        lab.block("The fixed sandbox connectivity client did not complete its bounded probe")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("The fixed sandbox connectivity client returned invalid JSON")
    return value


def run(lab, python_image, model_pod_ip):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": PEER_CODE}, "immutable": True,
                "data": {"peer.py": PEER_SCRIPT}})
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": PEER, "labels": PEER_LABEL},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "code", "configMap": {"name": PEER_CODE,
                                                            "defaultMode": 292}}],
            "containers": [{
                "name": "peer", "image": python_image, "imagePullPolicy": "Never",
                "command": ["python", "-B", "/fixture/peer.py"],
                "ports": [{"name": "http", "containerPort": 8080}],
                "readinessProbe": {"httpGet": {"path": "/health", "port": "http"},
                                   "periodSeconds": 2, "timeoutSeconds": 2,
                                   "failureThreshold": 5},
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "code", "mountPath": "/fixture",
                                  "readOnly": True}],
            }],
        },
    })
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": CLIENT, "labels": EVALUATOR_LABEL},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "probe", "image": python_image, "imagePullPolicy": "Never",
                "command": ["python", "-B", "-c", "import time; time.sleep(360)"],
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
            }],
        },
    })
    _wait_ready(lab, "pod", PEER)
    _wait_ready(lab, "pod", CLIENT)
    peer = _pod(lab, PEER)
    client = _pod(lab, CLIENT)
    peer_ip = peer.get("status", {}).get("podIP")
    if not peer_ip or not model_pod_ip:
        lab.block("The owned model/peer Pod IPs were not available")
    pre = _probe(lab, model_pod_ip, peer_ip)
    lab.check("red", "Before the sandbox policy the fixed client reaches both owned HTTP peers",
              pre == {"model": "reachable", "peer": "reachable"}, pre)

    lab.create({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "native-model-server-ingress"},
        "spec": {"podSelector": {"matchLabels": SERVER_LABEL},
                 "policyTypes": ["Ingress", "Egress"],
                 "ingress": [{"from": [{"podSelector": {"matchLabels": EVALUATOR_LABEL}}],
                              "ports": [{"protocol": "TCP", "port": 8080}]}]},
    })
    lab.create({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "native-model-evaluator-egress"},
        "spec": {"podSelector": {"matchLabels": EVALUATOR_LABEL},
                 "policyTypes": ["Ingress", "Egress"],
                 "egress": [{"to": [{"podSelector": {"matchLabels": SERVER_LABEL}}],
                             "ports": [{"protocol": "TCP", "port": 8080}]}]},
    })
    policy_deadline = time.monotonic() + 30
    post = None
    while time.monotonic() < policy_deadline:
        observed = _probe(lab, model_pod_ip, peer_ip)
        if observed == {"model": "reachable", "peer": "blocked"}:
            post = observed
            break
        time.sleep(0.5)
    if post is None:
        post = observed
    policy_objects = {}
    for name in ("native-model-server-ingress", "native-model-evaluator-egress"):
        policy_objects[name] = json.loads(lab.kubectl("get", "networkpolicy", name,
                                                       "-o", "json").stdout)
    expected_specs = {
        "native-model-server-ingress": {
            "podSelector": {"matchLabels": SERVER_LABEL},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": EVALUATOR_LABEL}}],
                         "ports": [{"protocol": "TCP", "port": 8080}]}],
        },
        "native-model-evaluator-egress": {
            "podSelector": {"matchLabels": EVALUATOR_LABEL},
            "policyTypes": ["Ingress", "Egress"],
            "egress": [{"to": [{"podSelector": {"matchLabels": SERVER_LABEL}}],
                        "ports": [{"protocol": "TCP", "port": 8080}]}],
        },
    }
    selectors_match = all(policy_objects[name].get("spec") == expected_specs[name]
                          for name in expected_specs)
    client_bound = client.get("metadata", {}).get("labels", {}).get("app") == EVALUATOR_LABEL["app"]
    client_after = _pod(lab, CLIENT)
    peer_after = _pod(lab, PEER)
    same_client = (client_after["metadata"]["uid"] == client["metadata"]["uid"]
                   and client_after["status"]["podIP"] == client["status"]["podIP"])
    same_peer = (peer_after["metadata"]["uid"] == peer["metadata"]["uid"]
                 and peer_after["status"]["podIP"] == peer_ip)
    local_health = lab.kubectl(
        "exec", "pod/" + PEER, "--", "python", "-B", "-c",
        "from urllib.request import urlopen; print(urlopen('http://127.0.0.1:8080/health',timeout=3).read().decode())",
        timeout=12,
    ).stdout.strip()
    peer_healthy = same_peer and local_health == "peer-ok"
    lab.check(
        "green", "The enforced evaluator selector keeps the model route and blocks the unrelated peer",
        post == {"model": "reachable", "peer": "blocked"} and selectors_match and client_bound and same_client and peer_healthy,
        {"post_policy": post, "policy_specs_match": selectors_match,
         "client_matches_evaluator_selector": client_bound,
         "same_client_uid": same_client, "same_peer_still_healthy": peer_healthy},
    )
    raw = {"client_pod_uid": client.get("metadata", {}).get("uid"),
           "client_pod_ip": client.get("status", {}).get("podIP"),
           "client_labels": client.get("metadata", {}).get("labels", {}),
           "peer_pod_uid": peer.get("metadata", {}).get("uid"),
           "peer_pod_ip": peer_ip, "model_pod_ip": model_pod_ip,
           "before_policy": pre, "after_policy": post,
           "same_client_uid": same_client, "same_peer_still_healthy": peer_healthy,
           "network_policies": policy_objects}
    (lab.evidence / "native-model-network.raw.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n")
    (lab.evidence / "native-model-network.normalized.json").write_text(json.dumps({
        "control_id": "SAF-K8S-0905-045",
        "owned_http_peer_ready": bool(peer.get("status", {}).get("podIP")),
        "pre_policy_model_and_peer_reachable": pre == {"model": "reachable", "peer": "reachable"},
        "post_policy_model_reachable_peer_blocked":
            post == {"model": "reachable", "peer": "blocked"},
        "exact_selector_and_route_observed": selectors_match and client_bound,
        "network_policy_enforcement_plugin": "bundled kindnet",
    }, indent=2, sort_keys=True) + "\n")
    return {"pre": pre, "post": post, "selectors_match": selectors_match,
            "client_matches_evaluator_selector": client_bound}
