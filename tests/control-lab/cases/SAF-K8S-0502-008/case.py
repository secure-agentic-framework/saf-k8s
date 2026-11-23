"""Exercise SAF-K8S-0502-008 with inert TCP/HTTP marker workloads.

The supervisor's lab runner supplies a fresh kind v0.32.0 / Kubernetes
v1.36.1 cluster and a Lab object compatible with reference/lab.py. This case
does not create clusters, access external networks, or use credentials.
"""
import json
import time
from ipaddress import IPv4Address


SCOPE = (
    "One disposable kind v0.32.0 cluster with Kubernetes v1.36.1 and its "
    "bundled kindnet. Case-owned training, registry, inference, gateway, and "
    "untrusted namespaces use non-root BusyBox Pods and synthetic TCP/HTTP "
    "markers only. It measures no-policy baseline routes, then checks a "
    "job-label-scoped TCP interval using the CNI-supported endPort field, an "
    "adjacent out-of-range port, a same-port neighbor with another job label, "
    "an approved versus unapproved registry Pod, and inference ingress "
    "allowed only from a fixture gateway. No DNS, Services, external traffic, "
    "NCCL process, GPU, RDMA, production CNI, label authorization/integrity, "
    "real registry, application authentication, or production deployment is "
    "evaluated. A timeout is attributed to this controlled policy scenario "
    "only after healthy endpoints and a successful no-policy baseline; the "
    "NetworkPolicy API itself does not report a packet drop reason."
)

IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
LABEL = "saf-k8s.example"
NS = {
    "training": "saf-0502-008-training",
    "registry": "saf-0502-008-registry",
    "inference": "saf-0502-008-inference",
    "gateway": "saf-0502-008-gateway",
    "untrusted": "saf-0502-008-untrusted",
}
JOB_PORTS = (31000, 31001, 31002)
OUTSIDE_PORT = 31003
HTTP_PORT = 8080


class ProbeAmbiguous(Exception):
    """A failed controlled request did not establish an expected denial."""


def _container(command):
    return {
        "name": "fixture",
        "image": IMAGE,
        "command": command,
        "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                      "limits": {"cpu": "100m", "memory": "32Mi"}},
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def _pod(name, namespace, labels, command):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                 "terminationGracePeriodSeconds": 1,
                 "containers": [_container(command)]},
    }


def _labels(**values):
    return {f"{LABEL}/{key.replace('_', '-')}": value for key, value in values.items()}


def _client(name, namespace, role, **extra):
    return _pod(name, namespace, _labels(role=role, **extra),
                ["sh", "-ec", "exec sleep 900"])


def _listener(name, namespace, role, marker, ports, **extra):
    """Serve one inert marker on each listed port using BusyBox httpd."""
    setup = "mkdir -p /tmp/www"
    commands = []
    for port in ports:
        root = f"/tmp/www/{port}"
        setup += f"; mkdir -p {root}; printf %s {marker}-{port} > {root}/marker"
        commands.append(f"httpd -f -p {port} -h {root} &")
    command = setup + "; " + " ".join(commands) + " wait"
    return _pod(name, namespace, _labels(role=role, **extra), ["sh", "-ec", command])


def _http_marker(name, namespace, role, marker, **extra):
    command = ("mkdir -p /tmp/www; printf %s " + marker +
               f" > /tmp/www/marker; exec httpd -f -p {HTTP_PORT} -h /tmp/www")
    return _pod(name, namespace, _labels(role=role, **extra), ["sh", "-ec", command])


def _create(lab, resource):
    lab.kubectl("-n", resource["metadata"]["namespace"], "create", "-f", "-",
                payload=json.dumps(resource))


def _ready(lab, resource):
    namespace = resource["metadata"]["namespace"]
    name = resource["metadata"]["name"]
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    pod = json.loads(lab.kubectl("-n", namespace, "get", "pod", name,
                                 "-o", "json").stdout)
    status = pod.get("status", {})
    address = status.get("podIP")
    ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                for c in status.get("conditions", []))
    if status.get("phase") != "Running" or not address or not ready:
        lab.block(f"Fixture Pod {namespace}/{name} is not healthy with a Pod IP")
    return str(IPv4Address(address))


def _request(lab, client, address, port, path="marker", marker=None):
    namespace = CLIENTS[client]["namespace"]
    result = lab.kubectl(
        "-n", namespace, "exec", f"pod/{client}", "--", "wget", "-q", "-T", "3",
        "-O", "-", f"http://{address}:{port}/{path}", allow_failure=True, timeout=15,
    )
    if result.returncode == 0:
        observed = result.stdout.strip()
        if marker is not None and observed != marker:
            lab.block(f"Unexpected marker from {client} at {address}:{port}/{path}")
        return {"outcome": "marker", "marker": observed}
    combined = (result.stdout + result.stderr).lower()
    if "timed out" in combined or "timeout" in combined:
        return {"outcome": "timeout"}
    raise ProbeAmbiguous(f"{client} HTTP request failed without a timeout")


def _repeat(lab, client, address, port, marker=None, *, denied=False):
    observations = []
    for _ in range(3):
        observations.append(_request(lab, client, address, port, marker=marker))
        if denied and observations[-1] != {"outcome": "timeout"}:
            break
        if not denied and observations[-1].get("outcome") != "marker":
            break
        time.sleep(0.15)
    expected = {"outcome": "timeout"} if denied else {"outcome": "marker", "marker": marker}
    matched = len(observations) == 3 and all(item == expected for item in observations)
    return matched, {
        "client": client, "port": port,
        "expected": expected, "observations": observations,
        "three_consecutive": matched,
        "attribution": "controlled policy scenario; API has no packet drop reason"
        if denied else "fixed case-owned marker",
    }


def _np(name, namespace, pod_selector, *, ingress=None, egress=None):
    spec = {"podSelector": {"matchLabels": pod_selector},
            "policyTypes": (["Ingress"] if egress is None else
                            ["Egress"] if ingress is None else ["Ingress", "Egress"])}
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace}, "spec": spec}


def _peer(namespace, selector):
    return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
            "podSelector": {"matchLabels": selector}}


def _port_rule(port):
    return {"protocol": "TCP", "port": port}


def _check_policy(lab, policy):
    namespace = policy["metadata"]["namespace"]
    items = json.loads(lab.kubectl("-n", namespace, "get", "networkpolicies",
                                   "-o", "json").stdout).get("items", [])
    matching = [item for item in items if item["metadata"]["name"] == policy["metadata"]["name"]]
    if len(matching) != 1 or matching[0].get("spec") != policy["spec"]:
        lab.block(f"API-stored policy differs from reviewed fixture {policy['metadata']['name']}")


CLIENTS = {
    "job-a-client": {"namespace": NS["training"]},
    "job-b-peer": {"namespace": NS["training"]},
    "registry-client": {"namespace": NS["registry"]},
    "gateway": {"namespace": NS["gateway"]},
    "untrusted": {"namespace": NS["untrusted"]},
}


def run(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected kind v0.32.0, got {kind_version!r}")
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server = version.get("serverVersion", {}).get("gitVersion")
    if server != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    lab.check("positive", "Runner is pinned to kind v0.32.0 / Kubernetes v1.36.1 with kindnet",
              True, {"kind_version": kind_version, "kubernetes_version": server,
                     "network_plugin": "bundled kindnet"})

    for name in NS.values():
        lab.kubectl("create", "namespace", name)

    job_a = _labels(role="training-peer", job="job-a")
    pods = [
        _client("job-a-client", NS["training"], "training-peer", job="job-a"),
        _listener("job-a-peer", NS["training"], "training-peer", "job-a", JOB_PORTS + (OUTSIDE_PORT,), job="job-a"),
        _listener("job-b-peer", NS["training"], "training-peer", "job-b", JOB_PORTS, job="job-b"),
        _client("registry-client", NS["registry"], "model-client"),
        _http_marker("approved-registry", NS["registry"], "registry", "approved-model", name_tag="approved"),
        _http_marker("other-registry", NS["registry"], "registry", "other-model", name_tag="unapproved"),
        _http_marker("inference", NS["inference"], "inference", "inference-ready"),
        _client("gateway", NS["gateway"], "gateway"),
        _client("untrusted", NS["untrusted"], "client"),
    ]
    addresses = {}
    for pod in pods:
        _create(lab, pod)
    for pod in pods:
        addresses[pod["metadata"]["name"]] = _ready(lab, pod)

    # The red phase proves that the exact probes work before isolation.
    for port in JOB_PORTS:
        for peer, marker in (("job-a-peer", f"job-a-{port}"), ("job-b-peer", f"job-b-{port}")):
            matched, receipt = _repeat(lab, "job-a-client", addresses[peer], port, marker)
            lab.check("red", f"No-policy baseline job-a-client reaches {peer}:{port}", matched, receipt)
    matched, receipt = _repeat(lab, "job-a-client", addresses["job-a-peer"], OUTSIDE_PORT,
                               f"job-a-{OUTSIDE_PORT}")
    lab.check("red", "No-policy baseline reaches same-job port just outside interval", matched, receipt)
    for peer, marker in (("approved-registry", "approved-model"), ("other-registry", "other-model")):
        matched, receipt = _repeat(lab, "registry-client", addresses[peer], HTTP_PORT, marker)
        lab.check("red", f"No-policy baseline registry client reaches {peer}", matched, receipt)
    for source in ("gateway", "untrusted"):
        matched, receipt = _repeat(lab, source, addresses["inference"], HTTP_PORT, "inference-ready")
        lab.check("red", f"No-policy baseline {source} reaches inference marker", matched, receipt)

    matched, receipt = _repeat(lab, "job-b-peer", addresses["job-a-peer"],
                               JOB_PORTS[1], f"job-a-{JOB_PORTS[1]}")
    lab.check("red", "No-policy baseline another job can initiate toward job A", matched, receipt)

    interval = {"protocol": "TCP", "port": JOB_PORTS[0], "endPort": JOB_PORTS[-1]}
    job_a_ingress = [{"from": [{"podSelector": {"matchLabels": job_a}}], "ports": [interval]}]
    job_a_egress = [{"to": [_peer(NS["training"], job_a)], "ports": [interval]}]
    train_policy = _np("job-a-only-interval", NS["training"], job_a,
                       ingress=job_a_ingress, egress=job_a_egress)

    registry_policy = _np("model-client-to-approved-registry", NS["registry"],
                          _labels(role="model-client"),
                          egress=[{"to": [_peer(NS["registry"], _labels(role="registry", name_tag="approved"))],
                                   "ports": [_port_rule(HTTP_PORT)]}])
    inference_policy = _np(
        "inference-from-fixture-gateway", NS["inference"], _labels(role="inference"),
        ingress=[{"from": [_peer(NS["gateway"], _labels(role="gateway"))],
                  "ports": [_port_rule(HTTP_PORT)]}],
    )

    for policy in (train_policy, registry_policy, inference_policy):
        _create(lab, policy)
        _check_policy(lab, policy)

    # Allowed cases prove interval edges, approved registry identity, and gateway path.
    for port in JOB_PORTS:
        matched, receipt = _repeat(lab, "job-a-client", addresses["job-a-peer"], port,
                                   f"job-a-{port}")
        lab.check("positive", f"Same-job path remains allowed on reviewed port {port}", matched, receipt)
    matched, receipt = _repeat(lab, "registry-client", addresses["approved-registry"], HTTP_PORT,
                               "approved-model")
    lab.check("positive", "Model client reaches approved registry marker", matched, receipt)
    matched, receipt = _repeat(lab, "gateway", addresses["inference"], HTTP_PORT, "inference-ready")
    lab.check("positive", "Fixture gateway reaches inference marker", matched, receipt)

    denied = [
        ("job-a-client", "job-b-peer", JOB_PORTS[1], f"job-b-{JOB_PORTS[1]}",
         "Training egress denies same-port neighboring job"),
        ("job-b-peer", "job-a-peer", JOB_PORTS[1], f"job-a-{JOB_PORTS[1]}",
         "Training ingress denies same-port neighboring job"),
        ("job-a-client", "job-a-peer", OUTSIDE_PORT, f"job-a-{OUTSIDE_PORT}",
         "Same-job port outside reviewed interval is denied"),
        ("registry-client", "other-registry", HTTP_PORT, "other-model",
         "Unapproved registry endpoint is denied"),
        ("untrusted", "inference", HTTP_PORT, "inference-ready",
         "Inference denies non-gateway fixture source"),
    ]
    for client, peer, port, marker, claim in denied:
        deadline = time.monotonic() + 30
        while _request(lab, client, addresses[peer], port, marker=marker)["outcome"] != "timeout":
            if time.monotonic() >= deadline:
                lab.block(f"Policy did not converge for {claim}")
            time.sleep(0.3)
        matched, receipt = _repeat(lab, client, addresses[peer], port, marker, denied=True)
        lab.check("green", claim, matched, receipt)
