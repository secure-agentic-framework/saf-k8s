"""Check scoped downloads of inert model JSON under Kubernetes NetworkPolicy."""
from hashlib import sha256
from ipaddress import IPv4Address
import json
import time

from fixtures import BUSYBOX_IMAGE, container, pod

PROTECTED = "saf-model-protected"
CONTROL = "saf-model-control"
PROXY = "saf-model-proxy"
HUB = "saf-model-hub"
PORT = 8080
APPROVED = '{"model":"approved-proxy","weight":2}'
HUB_ARTIFACT = '{"model":"direct-hub","weight":3}'
EXTERNAL = '{"model":"external-fixture-hub","weight":4}'
SCOPE = (
    "A disposable Kubernetes v1.36.1 cluster with bundled kindnet compares the same "
    "protected client's HTTP model downloads before and after a native NetworkPolicy. "
    "The policy allows CoreDNS and the exact labeled proxy namespace and Pods. The case "
    "checks in-cluster Service and direct Pod IP paths and a case-owned off-cluster Docker "
    "peer on an internal bridge. The unselected namespace can still reach denied targets. "
    "The synthetic JSON requests use TCP/8080. Production telemetry, public-hub and domain "
    "identity, proxy upstream governance, provider paths and non-Pod consumers are open."
)


def _create(lab, ns, resource):
    return json.loads(lab.kubectl("-n", ns, "create", "-f", "-", "-o", "json",
                                 payload=json.dumps(resource)).stdout)


def _get(lab, ns, resource, name):
    return json.loads(lab.kubectl("-n", ns, "get", resource, name, "-o", "json").stdout)


def _serve(body):
    return ["sh", "-ec", f"printf '%s' '{body}' >/tmp/model.json; exec httpd -f -p {PORT} -h /tmp"]


def _start_pod(lab, ns, name, role, command, *, listener=False):
    probe = {"readinessProbe": {"tcpSocket": {"port": PORT}, "periodSeconds": 1}} if listener else {}
    c = container("fixture", command=command,
                  resources={"requests": {"cpu": "10m", "memory": "12Mi"},
                             "limits": {"cpu": "100m", "memory": "32Mi"}}, **probe)
    resource = pod(name, [c], automountServiceAccountToken=False)
    resource["metadata"]["labels"] = {"app": role}
    _create(lab, ns, resource)


def _wait(lab, ns, name):
    lab.kubectl("-n", ns, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=70s", timeout=80)
    return _get(lab, ns, "pod", name)


def _service(lab, ns, role):
    svc = _create(lab, ns, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "models"},
                            "spec": {"selector": {"app": role},
                                     "ports": [{"port": PORT, "targetPort": PORT}]}})
    return svc["spec"]["clusterIP"]


def _url(target):
    return f"http://{target}:{PORT}/model.json"


def _request(lab, ns, host, exact):
    r = lab.kubectl("-n", ns, "exec", "client", "--", "wget", "-qT", "2", "-O-", _url(host),
                    timeout=12, allow_failure=True)
    if r.returncode == 0:
        if r.stdout != exact:
            lab.block("Owned model listener served different fixture bytes")
        return True
    if any(reason in r.stderr.lower() for reason in ("timed out", "timeout", "operation timed out")):
        return False
    lab.block(f"Model request failed outside the expected timeout: {r.stderr.strip()}")


def _check(lab, phase, claim, ns, host, model, allowed):
    deadline = time.monotonic() + 26
    consecutive = 0
    reachable = None
    while consecutive < 2 and time.monotonic() < deadline:
        reachable = _request(lab, ns, host, model)
        consecutive = consecutive + 1 if reachable == allowed else 0
        if consecutive < 2:
            time.sleep(0.25)
    lab.check(phase, claim, consecutive == 2,
              {"source_namespace": ns, "reachable": reachable, "consecutive_observations": consecutive,
               "model_sha256": sha256(model.encode()).hexdigest() if reachable else None})


def _resolve(lab, host, expected):
    output = lab.kubectl("-n", PROTECTED, "exec", "client", "--", "nslookup",
                         "-timeout=2", "-retry=1", host, timeout=12).stdout
    return expected in output.split()


def _policy(lab):
    def targets(ns, key, value, ports):
        return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
                        "podSelector": {"matchLabels": {key: value}}}],
                "ports": [{"protocol": protocol, "port": port} for protocol, port in ports]}
    return _create(lab, PROTECTED, {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "model-downloads"},
        "spec": {"podSelector": {}, "policyTypes": ["Egress"],
                 "egress": [targets(PROXY, "app", "approved-proxy", [("TCP", PORT)]),
                            targets("kube-system", "k8s-app", "kube-dns", [("UDP", 53), ("TCP", 53)])]},
    })


def run(lab):
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    for ns in (PROTECTED, CONTROL, PROXY, HUB):
        lab.kubectl("create", "namespace", ns)
    for ns, role, body in ((PROXY, "approved-proxy", APPROVED), (HUB, "direct-hub", HUB_ARTIFACT)):
        _start_pod(lab, ns, "models", role, _serve(body), listener=True)
    for ns in (PROTECTED, CONTROL):
        _start_pod(lab, ns, "client", "client", ["sleep", "900"])
    uid = _wait(lab, PROTECTED, "client")["metadata"]["uid"]
    _wait(lab, CONTROL, "client")
    _wait(lab, PROXY, "models")
    hub_ip = str(IPv4Address(_wait(lab, HUB, "models")["status"]["podIP"]))
    approved_ip = _service(lab, PROXY, "approved-proxy")
    hub_service_ip = _service(lab, HUB, "direct-hub")
    proxy_host = f"models.{PROXY}.svc.cluster.local"
    hub_host = f"models.{HUB}.svc.cluster.local"

    network = f"{lab.cluster}-private-model-source"
    node = f"{lab.cluster}-control-plane"
    external = f"{lab.cluster}-direct-model-hub"
    connected = running = False
    lab.command("docker", "network", "create", "--internal", network)
    try:
        lab.command("docker", "network", "connect", network, node)
        connected = True
        lab.command("docker", "run", "--rm", "--detach", "--name", external,
                    "--network", network, "--user=65534:65534", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", BUSYBOX_IMAGE, *_serve(EXTERNAL))
        running = True
        inspect = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
        outside = str(IPv4Address(lab.command("docker", "inspect", "--format", inspect, external).stdout.strip()))
        for label, host, model in (("proxy service", proxy_host, APPROVED),
                                   ("in-cluster direct hub service", hub_host, HUB_ARTIFACT),
                                   ("in-cluster hub Pod IP", hub_ip, HUB_ARTIFACT),
                                   ("off-cluster private hub", outside, EXTERNAL)):
            _check(lab, "red", f"Before enforcement the protected client downloads from the {label}",
                   PROTECTED, host, model, True)
        policy = _policy(lab)
        _check(lab, "green", "Protected namespace denies the same direct hub through its Service",
               PROTECTED, hub_host, HUB_ARTIFACT, False)
        _check(lab, "green", "Protected namespace denies the same hub Pod IP",
               PROTECTED, hub_ip, HUB_ARTIFACT, False)
        _check(lab, "green", "Protected namespace denies the same off-cluster hub IP",
               PROTECTED, outside, EXTERNAL, False)
        _check(lab, "positive", "The same protected client retrieves exact approved model bytes through its proxy",
               PROTECTED, proxy_host, APPROVED, True)
        _check(lab, "positive", "The in-cluster hub remains live from the unselected namespace",
               CONTROL, hub_host, HUB_ARTIFACT, True)
        _check(lab, "positive", "The off-cluster fixture remains live from the unselected namespace",
               CONTROL, outside, EXTERNAL, True)
        resolved = {"proxy": _resolve(lab, proxy_host, approved_ip), "hub": _resolve(lab, hub_host, hub_service_ip)}
        same_uid = _get(lab, PROTECTED, "pod", "client")["metadata"]["uid"] == uid
        lab.check("positive", "Both Kubernetes DNS records still resolve and the protected client is unchanged",
                  all(resolved.values()) and same_uid, {"services_resolve": resolved, "same_pod_uid": same_uid})
        path = lab.evidence / "model-source-egress.json"
        path.write_text(json.dumps({"network_policy": policy["spec"], "protected_pod_uid": uid,
                                    "checks": lab.checks}, indent=2) + "\n")
    finally:
        if running:
            lab.command("docker", "rm", "--force", external)
        if connected:
            lab.command("docker", "network", "disconnect", network, node)
        lab.command("docker", "network", "rm", network)
