"""Verify actual SPIRE bundle exchange and explicit application authorization."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import re
import ssl
import time

ROOT = Path(__file__).resolve().parent
NAMESPACES = {"a": "saf-fed-a", "b": "saf-fed-b"}
DOMAINS = {"a": "a.saf.test", "b": "b.saf.test"}
SERVER_POD = "spire-server-0"
SERVER_BIN = "/opt/spire/bin/spire-server"
AGENT_IMAGE = (
    "ghcr.io/spiffe/spire-agent:1.16.0@sha256:"
    "ab3a8ce70435374cc5d84c81eabf0278dc046ddbc0a736d59694ba9e5975b1b6"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
A_WORKLOAD = "spiffe://a.saf.test/lab/verifier"
APPROVED = "spiffe://b.saf.test/lab/approved"
OTHER = "spiffe://b.saf.test/lab/other"
FOREIGN_BUNDLE = "/run/svid/federated_bundle.0.0.pem"

SCOPE = (
    "Two independently attested SPIRE 1.16.0 trust domains in separate namespaces of one "
    "isolated Kubernetes v1.36.1 Kind cluster. A genuine B X.509-SVID fails client certificate "
    "verification before cross-domain trust is configured. A gives its verifier the B bundle "
    "through the SPIRE Workload API after an authenticated federation endpoint refresh. The "
    "eligible B identity then completes mTLS and receives HTTP 200, while another verified "
    "B identity receives HTTP 403. Separate-cluster deployment and ongoing lifecycle governance "
    "require separate evidence."
)


def check_kubelet_serving_identity(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1 or nodes[0]["metadata"]["name"] != f"{lab.cluster}-control-plane":
        lab.block("Expected only the harness-owned Kind node")
    node = nodes[0]["metadata"]["name"]
    address = next(item["address"] for item in nodes[0]["status"]["addresses"] if item["type"] == "InternalIP")
    deadline = time.monotonic() + 30
    while True:
        requests = json.loads(lab.kubectl("get", "csr", "-o", "json").stdout)["items"]
        candidates = [
            item for item in requests
            if item["spec"]["signerName"] == "kubernetes.io/kubelet-serving"
            and item["spec"]["username"] == f"system:node:{node}"
        ]
        if candidates:
            break
        if time.monotonic() >= deadline:
            lab.block("The owned node did not create a kubelet serving CSR")
        time.sleep(0.5)
    names = []
    for csr in candidates:
        details = lab.command(
            "openssl", "req", "-noout", "-verify", "-subject", "-nameopt", "RFC2253", "-text",
            payload=base64.b64decode(csr["spec"]["request"]).decode(),
        )
        endpoint_bound = f"IP Address:{address}" in details.stdout
        subject_bound = f"CN=system:node:{node}" in details.stdout
        if not endpoint_bound or not subject_bound or "server auth" not in csr["spec"]["usages"]:
            lab.block("The owned kubelet CSR did not match its authenticated endpoint")
        names.append(csr["metadata"]["name"])
    lab.kubectl("certificate", "approve", *names)
    deadline = time.monotonic() + 30
    while True:
        status = json.loads(lab.kubectl("get", "csr", *names, "-o", "json").stdout)
        requests = status.get("items", [status])
        if all(csr.get("status", {}).get("certificate") for csr in requests):
            break
        if time.monotonic() >= deadline:
            lab.block("The validated fixture kubelet serving requests were not signed")
        time.sleep(0.5)
    lab.check("positive", "The owned kubelet has a cluster-signed serving credential for its actual endpoint",
              True, {"valid_serving_signer": True, "owned_endpoint_in_csr": True})


def kube(lab, domain, *args, **kwargs):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "-n", NAMESPACES[domain], *args, **kwargs,
    )


def resource(lab, domain, spec):
    kube(lab, domain, "create", "-f", "-", payload=json.dumps(spec))


def config(lab, domain, name, data):
    resource(lab, domain, {
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": data,
    })


def server(lab, domain, *args, **kwargs):
    return kube(lab, domain, "exec", SERVER_POD, "-c", "server", "--", SERVER_BIN, *args, **kwargs)


def public_roots(pem):
    certificates = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    return sorted(sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest() for cert in certificates)


def apply_setup(lab, domain, component):
    manifest = ROOT / "fixtures" / f"{domain}-{component}.yaml"
    kube(lab, domain, "apply", "-f", str(manifest), timeout=40)


def start_server(lab, domain):
    apply_setup(lab, domain, "server")
    ready = kube(lab, domain, "rollout", "status", "statefulset/spire-server", "--timeout=65s",
                 allow_failure=True, timeout=75)
    if ready.returncode:
        kube(lab, domain, "describe", "pod", SERVER_POD, allow_failure=True)
        kube(lab, domain, "logs", SERVER_POD, "-c", "server", allow_failure=True)
        lab.block(f"SPIRE server in fixture domain {domain} did not become ready")
    pem = server(lab, domain, "bundle", "show", "-format", "pem").stdout
    if not public_roots(pem):
        lab.block(f"SPIRE server in fixture domain {domain} did not provide its public root")
    return pem


def start_agent(lab, domain, pem):
    config(lab, domain, "spire-agent-bootstrap", {"bundle.pem": pem})
    apply_setup(lab, domain, "agent")
    result = kube(lab, domain, "rollout", "status", "daemonset/spire-agent", "--timeout=65s",
                  allow_failure=True, timeout=75)
    if result.returncode:
        kube(lab, domain, "describe", "po", "-l", "app=spire-agent", allow_failure=True)
        kube(lab, domain, "logs", "daemonset/spire-agent", "-c", "agent", allow_failure=True)
        lab.block(f"SPIRE agent in fixture domain {domain} was not ready")
    listing = server(lab, domain, "agent", "list").stdout
    expected = rf"spiffe://{re.escape(DOMAINS[domain])}/spire/agent/k8s_psat/saf-{domain}/[a-zA-Z0-9-]+"
    matches = set(re.findall(expected, listing))
    if len(matches) != 1:
        lab.block(f"Expected one attested agent in fixture domain {domain}")
    return matches.pop()


def registration(lab, domain, action, parent, entry, identity, label, *args):
    server(lab, domain, "entry", action, "-entryID", entry, "-parentID", parent, "-spiffeID", identity,
           "-x509SVIDTTL", "600", "-selector", f"k8s:ns:{NAMESPACES[domain]}",
           "-selector", "k8s:sa:saf-workload", "-selector", f"k8s:pod-label:app:{label}",
           "-selector", "k8s:container-name:fetcher", *args)


def workload(lab, domain, name, label, command, extra_volumes=(), extra_mounts=(), ready_file=None,
             wait=True):
    container = {
        "name": "workload", "image": PYTHON_IMAGE, "command": command,
        "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
        "volumeMounts": [
            {"name": "svid", "mountPath": "/run/svid"},
            {"name": "application", "mountPath": "/application", "readOnly": True},
            *extra_mounts,
        ],
    }
    if ready_file:
        container["readinessProbe"] = {
            "exec": {"command": ["test", "-f", ready_file]}, "periodSeconds": 1,
        }
    resource(lab, domain, {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": {"app": label, "instance": name}},
        "spec": {
            "restartPolicy": "OnFailure", "automountServiceAccountToken": False,
            "serviceAccountName": "saf-workload",
            "initContainers": [{
                "name": "fetcher", "image": AGENT_IMAGE, "command": ["/opt/spire/bin/spire-agent"],
                "args": ["api", "fetch", "x509", "-socketPath", "/run/spire/sockets/agent.sock",
                         "-write", "/run/svid", "-silent", "-timeout", "30s"],
                "volumeMounts": [
                    {"name": "sockets", "mountPath": "/run/spire/sockets", "readOnly": True},
                    {"name": "svid", "mountPath": "/run/svid"},
                ],
            }],
            "containers": [container],
            "volumes": [
                {"name": "sockets", "hostPath": {"path": f"/run/spire/federation-{domain}", "type": "Directory"}},
                {"name": "svid", "emptyDir": {"medium": "Memory"}},
                {"name": "application", "configMap": {"name": "federation-app"}},
                *extra_volumes,
            ],
        },
    })
    if not wait:
        return
    ready = kube(lab, domain, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=105s",
                 allow_failure=True, timeout=115)
    if ready.returncode:
        kube(lab, domain, "logs", "daemonset/spire-agent", "-c", "agent", allow_failure=True)
        kube(lab, domain, "describe", "pod", name, allow_failure=True)
        kube(lab, domain, "logs", name, "-c", "fetcher", allow_failure=True)
        kube(lab, domain, "logs", name, "-c", "workload", allow_failure=True)
        lab.block(f"Fixture workload {name} did not become ready")


def activate_federation(lab, roots):
    endpoint = f"https://spire-server.{NAMESPACES['b']}.svc.cluster.local:8443"
    server(lab, "a", "federation", "create", "-trustDomain", DOMAINS["b"],
           "-bundleEndpointURL", endpoint, "-bundleEndpointProfile", "https_spiffe",
           "-endpointSpiffeID", f"spiffe://{DOMAINS['b']}/spire/server",
           "-trustDomainBundlePath", "/run/spire/foreign/foreign.pem")
    deadline = time.monotonic() + 25
    while True:
        result = server(lab, "a", "federation", "refresh", "-id", f"spiffe://{DOMAINS['b']}",
                        allow_failure=True, timeout=12)
        if result.returncode == 0:
            break
        if time.monotonic() >= deadline:
            lab.block("The authenticated B bundle endpoint did not refresh")
        time.sleep(1)
    pem = server(lab, "a", "bundle", "list", "-id", f"spiffe://{DOMAINS['b']}", "-format", "pem").stdout
    matched = public_roots(pem) == roots
    lab.check("green", "SPIRE A refreshes the exact B trust bundle from its authenticated endpoint",
              matched, {"refresh_succeeded": True, "foreign_roots_match": matched})


def start_verifier(lab, name, trust_file):
    command = [
        "python", "/application/workload_tls_server.py",
        "--cert", "/run/svid/svid.0.pem", "--key", "/run/svid/svid.0.key",
        "--bundle", trust_file, "--approved-uri", APPROVED, "--ready-file", "/tmp/listening",
    ]
    deadline = time.monotonic() + 80
    while True:
        # A successful one-shot Workload API response can precede delivery of
        # the updated federated bundle. Refresh it by starting a new fetcher.
        workload(lab, "a", name, "saf-verifier", command, ready_file="/tmp/listening", wait=False)
        ready = kube(lab, "a", "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=20s",
                     allow_failure=True, timeout=25)
        if not ready.returncode:
            break
        logs = kube(lab, "a", "logs", name, "-c", "workload", allow_failure=True)
        missing_bundle = '{"type": "foreign_bundle_not_available"}' in logs.stdout.splitlines()
        if not missing_bundle or time.monotonic() >= deadline:
            kube(lab, "a", "describe", "pod", name, allow_failure=True)
            kube(lab, "a", "logs", name, "-c", "fetcher", allow_failure=True)
            lab.block(f"The owned verifier {name} could not load its Workload API trust data")
        kube(lab, "a", "delete", "pod", name, "--wait=true", "--timeout=35s", timeout=40)
    resource(lab, "a", {
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
        "spec": {"selector": {"instance": name}, "ports": [{"name": "tls", "port": 8443}]},
    })
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        slices = kube(lab, "a", "get", "endpointslice", "-l", f"kubernetes.io/service-name={name}",
                      "-o", "json").stdout
        if any(endpoint["conditions"].get("ready") for item in json.loads(slices)["items"]
               for endpoint in item["endpoints"]):
            return
        time.sleep(0.4)
    lab.block(f"The Ready verifier {name} was not published in its Service EndpointSlice")


def start_probe(lab, name):
    workload(lab, "b", name, name, ["python", "-c", "import time; time.sleep(600)"],
             extra_volumes=[{"name": "verifier-roots", "configMap": {"name": "verifier-roots"}}],
             extra_mounts=[{"name": "verifier-roots", "mountPath": "/verify", "readOnly": True}])


def probe(lab, name, verifier):
    deadline = time.monotonic() + 20
    while True:
        response = kube(
            lab, "b", "exec", name, "-c", "workload", "--", "python", "/application/workload_tls_client.py",
            "--host", f"{verifier}.{NAMESPACES['a']}.svc.cluster.local",
            "--cert", "/run/svid/svid.0.pem", "--key", "/run/svid/svid.0.key",
            "--bundle", "/verify/bundle.pem", "--approved-uri", A_WORKLOAD,
            allow_failure=True, timeout=15,
        )
        try:
            report = json.loads(response.stdout)
        except json.JSONDecodeError:
            lab.block(f"Fixture probe {name} did not return a reviewed TLS or HTTP result")
        if response.returncode == 0:
            return report
        if report.get("type") != "connection_error" or time.monotonic() >= deadline:
            verifier_observations(lab, verifier)
            lab.block(f"Fixture probe {name} returned {report['type']} for {verifier}")
        time.sleep(0.6)


def verifier_observations(lab, name):
    rows = kube(lab, "a", "logs", name, "-c", "workload").stdout.splitlines()
    return [json.loads(row) for row in rows if row.startswith("{")]


def compare_bundle_delivery(lab, verifier, expected):
    delivery = kube(lab, "a", "exec", verifier, "-c", "workload", "--", "cat", FOREIGN_BUNDLE).stdout
    return public_roots(delivery) == expected


def run(lab):
    check_kubelet_serving_identity(lab)
    for namespace in NAMESPACES.values():
        lab.kubectl("create", "namespace", namespace)
    bundle_b = start_server(lab, "b")
    config(lab, "a", "federation-bootstrap-b", {"foreign.pem": bundle_b})
    bundle_a = start_server(lab, "a")
    distinct = not set(public_roots(bundle_a)).intersection(public_roots(bundle_b))
    parents = {"a": start_agent(lab, "a", bundle_a), "b": start_agent(lab, "b", bundle_b)}
    lab.check("positive", "Both SPIRE providers attest an agent and own distinct public roots",
              distinct, {"independent_roots": distinct, "agents_attested": len(parents)})

    scripts = {name: (ROOT / name).read_text() for name in ("workload_tls_client.py", "workload_tls_server.py")}
    for domain in ("a", "b"):
        config(lab, domain, "federation-app", scripts)
    config(lab, "b", "verifier-roots", {"bundle.pem": bundle_a})
    registration(lab, "a", "create", parents["a"], "verifier", A_WORKLOAD, "saf-verifier")
    registration(lab, "b", "create", parents["b"], "approved", APPROVED, "saf-approved")
    registration(lab, "b", "create", parents["b"], "other", OTHER, "saf-other")
    start_probe(lab, "saf-approved")
    start_probe(lab, "saf-other")
    start_verifier(lab, "saf-before", "/run/svid/bundle.0.pem")

    before = probe(lab, "saf-approved", "saf-before")
    before_rows = verifier_observations(lab, "saf-before")
    certificate_reject = any(row.get("type") == "client_certificate_rejected" and row.get("verify_code") == 20
                             for row in before_rows)
    no_request = not any(row.get("type") == "authorized_request" for row in before_rows)
    baseline = {"client_rejected": before == {"type": "client_certificate_rejected"},
                "server_rejected_untrusted_issuer": certificate_reject, "no_request_before_tls": no_request}
    lab.check("red", "Without foreign trust the eligible credential fails chain validation before HTTP",
              all(baseline.values()), baseline)

    foreign_roots = public_roots(bundle_b)
    activate_federation(lab, foreign_roots)
    registration(lab, "a", "update", parents["a"], "verifier", A_WORKLOAD, "saf-verifier",
                 "-federatesWith", f"spiffe://{DOMAINS['b']}")
    start_verifier(lab, "saf-after", FOREIGN_BUNDLE)
    delivered = compare_bundle_delivery(lab, "saf-after", foreign_roots)
    lab.check("green", "The verifier receives the exact foreign roots from its own Workload API",
              delivered, {"foreign_roots_delivered": delivered})

    allowed = probe(lab, "saf-approved", "saf-after")
    denied = probe(lab, "saf-other", "saf-after")
    enforcement = verifier_observations(lab, "saf-after")
    for phase, report, identity, status in (("green", allowed, APPROVED, 200), ("positive", denied, OTHER, 403)):
        observed = {"type": "authorized_request", "peer_uri": [identity], "status": status} in enforcement
        lab.check(phase, f"The TLS-verified identity {identity} receives HTTP {status}",
                  observed and report == {"type": "http_result", "server_uri_verified": True, "status": status},
                  {"verified_client_uri": identity, "server_uri_verified": report.get("server_uri_verified"),
                   "http_status": report.get("status"), "server_decision_observed": observed})
    (lab.evidence / "federation-observations.json").write_text(
        json.dumps({"baseline": baseline, "foreign_roots_delivered": delivered,
                    "eligible": allowed, "other": denied}, indent=2, sort_keys=True) + "\n"
    )
