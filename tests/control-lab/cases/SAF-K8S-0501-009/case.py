"""Verify network-path separation for synthetic model and training markers."""
import json
import time
from ipaddress import IPv4Address


NAMESPACES = {
    "model": "saf-0501-009-model",
    "training": "saf-0501-009-training",
    "shared": "saf-0501-009-shared",
}
PORT = 8080
LABEL_DOMAIN = "saf-k8s.example/domain"
LABEL_ROLE = "saf-k8s.example/role"
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
CLIENTS = {
    "model": {"pod": "model-client"},
    "training": {"pod": "training-client"},
}
ENDPOINTS = {
    "model": {"pod": "model-mirror", "marker": "saf-0501-009-model-mirror"},
    "training": {"pod": "training-store", "marker": "saf-0501-009-training-store"},
}
CLIENT_NAMESPACES = {item["pod"]: NAMESPACES[domain] for domain, item in CLIENTS.items()}
SHARED = {"pod": "shared-path-listener", "model": "saf-0501-009-shared-model-path",
          "training": "saf-0501-009-shared-training-path"}
SCOPE = (
    "One disposable kind v0.32.0 cluster using its bundled kindnet and Kubernetes v1.36.1; "
    "three case-owned namespaces with two non-root BusyBox clients and three inert HTTP Pods. "
    "The case proves the four model/training client-to-model-mirror/training-store TCP/8080 "
    "marker paths before policy; then applies pod-selected egress NetworkPolicies and proves "
    "model-client->model-mirror and training-client->training-store remain useful while the "
    "two cross-domain paths time out. A third listener serves separate /model and /training "
    "HTTP paths; a permitted model-client-to-listener network path can fetch both markers, "
    "demonstrating that native NetworkPolicy does not distinguish URI paths. No Services, "
    "DNS, external targets, IPv6, production CNI, external model/data sources, artifact "
    "integrity, TLS, application authorization, or production routing are evaluated. A denied "
    "probe is attributed only to this controlled scenario after healthy endpoints and a "
    "successful no-policy baseline; NetworkPolicy exposes no per-packet drop reason."
)


class ProbeAmbiguous(Exception):
    """A failed HTTP request did not establish the expected network result."""


def _container(name, command):
    return {
        "name": name,
        "image": IMAGE,
        "command": command,
        "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                      "limits": {"cpu": "75m", "memory": "24Mi"}},
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def _pod(name, role, domain, command):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACES[domain],
                     "labels": {LABEL_ROLE: role, LABEL_DOMAIN: domain}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                 "terminationGracePeriodSeconds": 1,
                 "containers": [_container(name, command)]},
    }


def _client(name, domain):
    return _pod(name, "client", domain, ["sh", "-ec", "exec sleep 900"])


def _http_endpoint(name, role, domain, paths):
    setup = "mkdir -p /tmp/www"
    for path, marker in paths.items():
        setup += f"; printf %s {marker} > /tmp/www/{path}"
    return _pod(name, role, domain, [
        "sh", "-ec", setup + f"; exec httpd -f -p {PORT} -h /tmp/www",
    ])


def _create(lab, resource):
    lab.kubectl("-n", resource["metadata"]["namespace"], "create", "-f", "-",
                payload=json.dumps(resource))


def _wait_ready(lab, namespace, pod_name):
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{pod_name}",
                "--timeout=90s", timeout=100)
    pod = json.loads(lab.kubectl("-n", namespace, "get", "pod", pod_name,
                                 "-o", "json").stdout)
    address = pod.get("status", {}).get("podIP")
    if pod.get("status", {}).get("phase") != "Running" or not address:
        lab.block(f"Case-owned Pod {pod_name} is not running with a Pod IP")
    ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                for c in pod.get("status", {}).get("conditions", []))
    if not ready:
        lab.block(f"Case-owned Pod {pod_name} is not Ready")
    return str(IPv4Address(address))


def _request(lab, client, address, path, expected_marker=None):
    result = lab.kubectl(
        "-n", CLIENT_NAMESPACES[client], "exec", f"pod/{client}", "--", "wget", "-q", "-T", "3",
        "-O", "-", f"http://{address}:{PORT}/{path}", allow_failure=True, timeout=15,
    )
    if result.returncode == 0:
        marker = result.stdout.strip()
        if expected_marker is None:
            return {"outcome": "marker", "marker": marker}
        if marker != expected_marker:
            lab.block(f"HTTP probe returned unexpected marker from {client}/{path}")
        return {"outcome": "marker", "marker": marker}
    combined = (result.stdout + result.stderr).lower()
    if "timed out" in combined or "timeout" in combined:
        return {"outcome": "timeout"}
    raise ProbeAmbiguous(f"{client} GET /{path} failed without a timeout")


def _repeat(lab, client, address, path, expected_marker=None, *, denied=False):
    observations = []
    for _ in range(3):
        observed = _request(lab, client, address, path, expected_marker)
        observations.append(observed)
        if denied and observed != {"outcome": "timeout"}:
            break
        if not denied and observed.get("outcome") != "marker":
            break
        time.sleep(0.2)
    matched = len(observations) == 3 and all(
        o == {"outcome": "timeout"} if denied
        else o == {"outcome": "marker", "marker": expected_marker}
        for o in observations
    )
    return matched, {"client": client,
                     "path": f"/{path}", "expected": "timeout" if denied else expected_marker,
                     "observations": observations, "three_consecutive": matched,
                     "attribution": "controlled policy scenario; API does not report drop reason"
                     if denied else "fixed case-owned HTTP marker"}


def _policy(name, client_domain, destinations):
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": NAMESPACES[client_domain]},
        "spec": {
            "podSelector": {"matchLabels": {LABEL_ROLE: "client", LABEL_DOMAIN: client_domain}},
            "policyTypes": ["Egress"],
            "egress": [{
                "to": [{
                    "namespaceSelector": {"matchLabels": {
                        "kubernetes.io/metadata.name": NAMESPACES[domain],
                    }},
                    "podSelector": {"matchLabels": {LABEL_ROLE: role, LABEL_DOMAIN: domain}},
                } for role, domain in destinations],
                "ports": [{"protocol": "TCP", "port": PORT}],
            }],
        },
    }


def _verify_policy(lab, policy):
    namespace = policy["metadata"]["namespace"]
    items = json.loads(lab.kubectl("-n", namespace, "get", "networkpolicies",
                                   "-o", "json").stdout).get("items", [])
    if (len(items) != 1 or items[0]["metadata"]["name"] != policy["metadata"]["name"]
            or items[0]["spec"] != policy["spec"]):
        lab.block(f"Egress rules did not match reviewed policy in {namespace}")


def _check_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected kind v0.32.0, got {kind_version!r}")
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server_version = version.get("serverVersion", {}).get("gitVersion")
    if server_version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server_version!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    daemonset = json.loads(lab.kubectl("-n", "kube-system", "get", "daemonset",
                                       "kindnet", "-o", "json").stdout)
    images = [c["image"] for c in daemonset["spec"]["template"]["spec"]["containers"]]
    if not any("kindnetd" in image for image in images):
        lab.block("Ready kube-system/kindnet does not identify a kindnetd image")
    lab.check("positive", "Runner is pinned to kind v0.32.0 / Kubernetes v1.36.1 with kindnet",
              True, {"kind_version": kind_version, "kubernetes_version": server_version,
                     "daemonset": "kube-system/kindnet", "images": images})


def run(lab):
    _check_platform(lab)
    for namespace in NAMESPACES.values():
        lab.kubectl("create", "namespace", namespace)
    resources = [
        _client(CLIENTS["model"]["pod"], "model"),
        _client(CLIENTS["training"]["pod"], "training"),
        _http_endpoint(ENDPOINTS["model"]["pod"], "endpoint", "model",
                       {"index.html": ENDPOINTS["model"]["marker"]}),
        _http_endpoint(ENDPOINTS["training"]["pod"], "endpoint", "training",
                       {"index.html": ENDPOINTS["training"]["marker"]}),
        _http_endpoint(SHARED["pod"], "shared", "shared",
                       {"model": SHARED["model"], "training": SHARED["training"]}),
    ]
    addresses = {}
    for resource in resources:
        _create(lab, resource)
    for resource in resources:
        pod = resource["metadata"]
        addresses[pod["name"]] = _wait_ready(lab, pod["namespace"], pod["name"])

    model_client, training_client = CLIENTS["model"]["pod"], CLIENTS["training"]["pod"]
    model_endpoint, training_endpoint = ENDPOINTS["model"], ENDPOINTS["training"]
    baseline = [
        (model_client, model_endpoint, "index.html", model_endpoint["marker"]),
        (model_client, training_endpoint, "index.html", training_endpoint["marker"]),
        (training_client, model_endpoint, "index.html", model_endpoint["marker"]),
        (training_client, training_endpoint, "index.html", training_endpoint["marker"]),
    ]
    for client, endpoint, path, marker in baseline:
        matched, receipt = _repeat(lab, client, addresses[endpoint["pod"]], path, marker)
        lab.check("red", f"No-policy baseline {client} reaches {endpoint['pod']} marker",
                  matched, receipt)

    # Both model endpoints are distinct peer Pods but share the same permitted TCP port.
    model = _policy("allow-model-to-model-and-shared", "model",
                    [("endpoint", "model"), ("shared", "shared")])
    training = _policy("allow-training-to-training", "training", [("endpoint", "training")])
    for policy in (model, training):
        _create(lab, policy)
        _verify_policy(lab, policy)
    policies = [policy["metadata"]["name"] for policy in (model, training)]

    # Wait for both denied paths to converge instead of assuming a fixed
    # reconciliation delay. The separate evidence probes repeat each result.
    pairs = ((model_client, training_endpoint), (training_client, model_endpoint))
    deadline = time.monotonic() + 45
    for client, endpoint in pairs:
        while (_request(lab, client, addresses[endpoint["pod"]], "index.html",
                        endpoint["marker"])["outcome"] != "timeout"):
            if time.monotonic() >= deadline:
                break
            time.sleep(0.5)

    for client, endpoint, path, marker in (
        (model_client, model_endpoint, "index.html", model_endpoint["marker"]),
        (training_client, training_endpoint, "index.html", training_endpoint["marker"]),
    ):
        matched, receipt = _repeat(lab, client, addresses[endpoint["pod"]], path, marker)
        lab.check("positive", f"Permitted {client} to {endpoint['pod']} path still works",
                  matched, receipt)

    for client, endpoint in pairs:
        matched, receipt = _repeat(lab, client, addresses[endpoint["pod"]], "index.html",
                                   endpoint["marker"], denied=True)
        lab.check("green", f"Policy denies cross-domain {client} to {endpoint['pod']}",
                  matched, receipt)

    shared_ip = addresses[SHARED["pod"]]
    shared_observations = []
    for path, marker in (("model", SHARED["model"]), ("training", SHARED["training"])):
        matched, receipt = _repeat(lab, model_client, shared_ip, path, marker)
        shared_observations.append(receipt)
        lab.check("positive", f"Allowed shared listener serves /{path} to model client",
                  matched, receipt)
    lab.check("positive", "Observed NetworkPolicy cannot distinguish HTTP URI paths on one allowed Pod/port",
              all(len(item["observations"]) == 3 for item in shared_observations),
              {"destination_pod": SHARED["pod"], "destination_port": PORT,
               "policy_names": policies, "both_paths_returned_markers": True,
               "boundary": "application-layer route controls or separate network identities are needed"})
