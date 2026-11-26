"""Self-contained Metrics Server supplement for isolated 1002-005 case staging."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import time
from urllib.parse import urlsplit

METRICS_URL = "https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.1/components.yaml"
METRICS_SHA256 = "4a672c4891902573a3ff753cece5de1bf1f55dd053403dfec39df9d1636b7ff1"
METRICS_IMAGE = "registry.k8s.io/metrics-server/metrics-server@sha256:b2d2efaf5ac3b366ed0f839d2412a2c4279d4fc2a2a733f12c52133faed36c41"
METRICS_OLD_IMAGE = "registry.k8s.io/metrics-server/metrics-server:v0.8.1"
METRICS_NS = "kube-system"
METRICS_API = "v1beta1.metrics.k8s.io"
METRICS_NAMESPACES = ("saf-1002-alpha", "saf-1002-beta")
METRICS_READER = "saf-1002-metrics-reader"
METRICS_UNBOUND = "saf-1002-metrics-unbound"
METRICS_POD = "saf-metrics-marker"
BUSYBOX_IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
KUBELET_CERT_DIR = "/etc/kubernetes/saf-metrics-kubelet-tls"


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(content)
    path.chmod(0o600)


def create_fixture_tls(lab, directory, service):
    """Create a short-lived case CA/leaf with SAN and TLS usage constraints."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_key, root_crt = directory / "ca.key", directory / "ca.crt"
    leaf_key, leaf_crt = directory / "tls.key", directory / "tls.crt"
    request, config = directory / "leaf.csr", directory / "openssl.conf"
    _write(config, "[req]\ndistinguished_name=dn\n[dn]\n"
                   "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                   "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                   f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{service}\n")
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-sha256", "-config", str(config), "-extensions", "ca",
                "-subj", f"/CN=SAF fixture CA for {service}", "-keyout", str(root_key),
                "-out", str(root_crt), timeout=30)
    root_key.chmod(0o600)
    try:
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", str(config),
                    "-subj", f"/CN={service}", "-keyout", str(leaf_key), "-out", str(request), timeout=30)
        leaf_key.chmod(0o600)
        lab.command("openssl", "x509", "-req", "-in", str(request), "-CA", str(root_crt),
                    "-CAkey", str(root_key), "-set_serial", "1", "-days", "1", "-sha256",
                    "-extfile", str(config), "-extensions", "leaf", "-out", str(leaf_crt), timeout=30)
    finally:
        root_key.unlink(missing_ok=True)
        request.unlink(missing_ok=True)


def configure_metrics_server_kind(lab, temporary, config):
    """Add the pinned kubelet TLS files to the existing custom audit Kind profile."""
    kubelet_tls = temporary / "kubelet"
    create_fixture_tls(lab, kubelet_tls, f"{lab.cluster}-control-plane")
    text = config.read_text()
    mount_anchor = "  kubeadmConfigPatches:\n"
    if text.count(mount_anchor) != 1:
        lab.block("Metrics Server supplement could not locate the Kind mount section")
    mount = (f"  - hostPath: {json.dumps(str(kubelet_tls))}\n"
             f"    containerPath: {KUBELET_CERT_DIR}\n    readOnly: true\n")
    text = text.replace(mount_anchor, mount + mount_anchor)
    text += ("  - |\n"
             "    apiVersion: kubelet.config.k8s.io/v1beta1\n"
             "    kind: KubeletConfiguration\n"
             "    serverTLSBootstrap: false\n"
             f"    tlsCertFile: {KUBELET_CERT_DIR}/tls.crt\n"
             f"    tlsPrivateKeyFile: {KUBELET_CERT_DIR}/tls.key\n")
    config.write_text(text)
    return config


def _install_metrics_server(lab, temporary):
    """Install exact released manifest/image and configure verified kubelet/APIService TLS."""
    path = temporary / "metrics-server-components.yaml"
    lab.command("curl", "--fail", "--silent", "--show-error", "--location", METRICS_URL,
                "-o", str(path), timeout=85)
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8")
    if digest != METRICS_SHA256 or text.count(METRICS_OLD_IMAGE) != 1:
        lab.block("Metrics Server installer differs from the reviewed v0.8.1 release")
    path.write_text(text.replace(METRICS_OLD_IMAGE, METRICS_IMAGE))
    node = f"{lab.cluster}-control-plane"
    node_obj = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)
    ipv4 = next(address["address"] for address in node_obj["status"]["addresses"]
                if address["type"] == "InternalIP" and ":" not in address["address"])

    kubelet_ca = temporary / "kubelet" / "ca.crt"
    metrics_tls = temporary / "metrics-api"
    create_fixture_tls(lab, metrics_tls, "metrics-server.kube-system.svc")
    lab.kubectl("-n", METRICS_NS, "create", "configmap", "saf-metrics-kubelet-ca",
                f"--from-file=ca.crt={kubelet_ca}")
    lab.kubectl("-n", METRICS_NS, "create", "secret", "tls", "saf-metrics-api-tls",
                "--cert", str(metrics_tls / "tls.crt"), "--key", str(metrics_tls / "tls.key"))
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "apply", "--server-side", "-f", str(path), timeout=90)
    deployment = json.loads(lab.kubectl("-n", METRICS_NS, "get", "deployment", "metrics-server", "-o", "json").stdout)
    container = next(item for item in deployment["spec"]["template"]["spec"]["containers"]
                     if item["name"] == "metrics-server")
    args = [arg for arg in container["args"] if not arg.startswith("--kubelet-preferred-address-types")]
    args.extend(("--kubelet-preferred-address-types=Hostname",
                 "--kubelet-certificate-authority=/saf-kubelet-ca/ca.crt",
                 "--tls-cert-file=/saf-metrics-api/tls.crt",
                 "--tls-private-key-file=/saf-metrics-api/tls.key"))
    patch = {"spec": {"template": {"spec": {
        "hostAliases": [{"ip": ipv4, "hostnames": [node]}],
        "volumes": [{"name": "saf-kubelet-ca", "configMap": {"name": "saf-metrics-kubelet-ca"}},
                    {"name": "saf-metrics-api", "secret": {"secretName": "saf-metrics-api-tls"}}],
        "containers": [{"name": "metrics-server", "args": args, "volumeMounts": [
            {"name": "saf-kubelet-ca", "mountPath": "/saf-kubelet-ca", "readOnly": True},
            {"name": "saf-metrics-api", "mountPath": "/saf-metrics-api", "readOnly": True}]}]}}}}
    lab.kubectl("-n", METRICS_NS, "patch", "deployment", "metrics-server", "--type=strategic",
                "-p", json.dumps(patch))
    ca_bundle = base64.b64encode((metrics_tls / "ca.crt").read_bytes()).decode("ascii")
    lab.kubectl("patch", "apiservice", METRICS_API, "--type=merge", "-p",
                json.dumps({"spec": {"insecureSkipTLSVerify": False, "caBundle": ca_bundle}}))
    lab.kubectl("-n", METRICS_NS, "rollout", "status", "deployment/metrics-server", "--timeout=100s", timeout=110)
    lab.kubectl("wait", "--for=condition=Available", "apiservice/" + METRICS_API, "--timeout=50s", timeout=60)
    service = json.loads(lab.kubectl("get", "apiservice", METRICS_API, "-o", "json").stdout)
    matched = (service["spec"].get("insecureSkipTLSVerify", False) is False
               and service["spec"].get("caBundle") == ca_bundle
               and service["spec"].get("service", {}).get("name") == "metrics-server"
               and service["spec"].get("service", {}).get("namespace") == METRICS_NS)
    lab.check("positive", "Pinned Metrics Server is registered through its trusted APIService certificate",
              matched, {"api": METRICS_API, "image": METRICS_IMAGE, "tls_verified": matched})


def _pod(name, namespace):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "containers": [{"name": "idle", "image": BUSYBOX_IMAGE, "command": ["sh", "-c", "sleep 3600"],
                                     "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                   "limits": {"cpu": "50m", "memory": "32Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False, "runAsNonRoot": True,
                                                          "runAsUser": 65534, "capabilities": {"drop": ["ALL"]},
                                                          "seccompProfile": {"type": "RuntimeDefault"}}}]}}


def _api_get(lab, token, namespace, pod):
    path = f"/apis/metrics.k8s.io/v1beta1/namespaces/{namespace}/pods/{pod}"
    base = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}"]
    if token is None:
        response = subprocess.run(base + ["get", "--raw", path], env=lab.env,
                                  text=True, capture_output=True, timeout=18)
        if response.returncode:
            return {"status": None, "body": ""}
        return {"status": 200, "body": response.stdout}

    args = base + ["config", "view", "--minify", "--raw", "-o"]
    result = subprocess.run(args + ["jsonpath={.clusters[0].cluster.server}"], env=lab.env,
                            text=True, capture_output=True, timeout=15)
    ca_result = subprocess.run(args + ["jsonpath={.clusters[0].cluster.certificate-authority-data}"], env=lab.env,
                               text=True, capture_output=True, timeout=15)
    if result.returncode or ca_result.returncode:
        raise RuntimeError("Could not read fixture API endpoint trust configuration")
    endpoint = urlsplit(result.stdout.strip())
    if endpoint.scheme != "https" or endpoint.hostname not in {"127.0.0.1", "localhost"}:
        lab.block("Fixture API endpoint did not match the loopback HTTPS guard")
    context = ssl.create_default_context(cadata=base64.b64decode(ca_result.stdout.strip()).decode("ascii"))
    connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port, timeout=12, context=context)
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return {"status": response.status, "body": response.read(65536).decode("utf-8", "replace")}
    finally:
        connection.close()


def _podmetrics(reply, namespace):
    if reply.get("status") != 200:
        return {"status": reply.get("status"), "exact_object": False, "usage_present": False}
    try:
        doc = json.loads(reply.get("body", ""))
        exact = (doc.get("kind") == "PodMetrics" and doc.get("apiVersion") == "metrics.k8s.io/v1beta1"
                 and doc.get("metadata", {}).get("name") == METRICS_POD
                 and doc.get("metadata", {}).get("namespace") == namespace)
        usage = any(row.get("name") == "idle" and all(key in row.get("usage", {}) for key in ("cpu", "memory"))
                    for row in doc.get("containers", []))
        return {"status": 200, "exact_object": exact, "usage_present": usage}
    except (TypeError, ValueError):
        return {"status": 200, "exact_object": False, "usage_present": False}


def _token(lab, namespace, service_account):
    result = subprocess.run(["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                             "-n", namespace, "create", "token", service_account, "--duration=10m"],
                            env=lab.env, text=True, capture_output=True, timeout=30)
    if result.returncode or not result.stdout.strip():
        raise RuntimeError("Could not mint short-lived case-owned ServiceAccount token")
    return result.stdout.strip()


def _wait_for(probe, predicate, description, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(2)
    raise RuntimeError(f"{description} did not become available")


def run_metrics_server_scope(lab):
    """Exercise three native authenticated metrics.k8s.io API decisions."""
    _install_metrics_server(lab, lab.kubeconfig.parent)
    for namespace in METRICS_NAMESPACES:
        for account in (METRICS_READER, METRICS_UNBOUND):
            lab.kubectl("-n", namespace, "create", "serviceaccount", account)
        lab.kubectl("-n", namespace, "apply", "-f", "-", payload=json.dumps(_pod(METRICS_POD, namespace)))
        lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{METRICS_POD}",
                    "--timeout=90s", timeout=95)

    def view_has_metrics_get():
        role = json.loads(lab.kubectl("get", "clusterrole", "view", "-o", "json").stdout)
        return any("metrics.k8s.io" in rule.get("apiGroups", []) and "pods" in rule.get("resources", [])
                   and "get" in rule.get("verbs", []) for rule in role.get("rules", []))

    if not _wait_for(view_has_metrics_get, bool, "Metrics Server aggregated view permissions", timeout=60):
        lab.block("Pinned Metrics Server did not contribute PodMetrics get to the view role")
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
               "metadata": {"name": "saf-metrics-reader-view", "namespace": METRICS_NAMESPACES[0]},
               "subjects": [{"kind": "ServiceAccount", "name": METRICS_READER,
                             "namespace": METRICS_NAMESPACES[0]}],
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"}}
    lab.kubectl("-n", METRICS_NAMESPACES[0], "apply", "-f", "-", payload=json.dumps(binding))
    reader_token = _token(lab, METRICS_NAMESPACES[0], METRICS_READER)
    unbound_token = _token(lab, METRICS_NAMESPACES[0], METRICS_UNBOUND)
    outside_ns = METRICS_NAMESPACES[1]
    _wait_for(lambda: _api_get(lab, None, outside_ns, METRICS_POD),
              lambda reply: _podmetrics(reply, outside_ns)["exact_object"]
              and _podmetrics(reply, outside_ns)["usage_present"],
              "other-namespace fixture PodMetrics readiness")
    own_reply = _wait_for(lambda: _api_get(lab, reader_token, METRICS_NAMESPACES[0], METRICS_POD),
                          lambda reply: _podmetrics(reply, METRICS_NAMESPACES[0])["exact_object"]
                          and _podmetrics(reply, METRICS_NAMESPACES[0])["usage_present"],
                          "authorized namespaced PodMetrics")
    denied_reply = _api_get(lab, unbound_token, METRICS_NAMESPACES[0], METRICS_POD)
    cross_reply = _api_get(lab, reader_token, outside_ns, METRICS_POD)
    own = _podmetrics(own_reply, METRICS_NAMESPACES[0])
    sanitized = {"authorized_own_namespace": own,
                 "authenticated_unbound_same_namespace": {"status": denied_reply.get("status")},
                 "reader_other_namespace": {"status": cross_reply.get("status")},
                 "raw_bodies_retained": False, "tokens_retained": False}
    (lab.evidence / "metrics-server-authorization.json").write_text(json.dumps(sanitized, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Authorized namespaced reader retrieves the exact native PodMetrics object",
              own["status"] == 200 and own["exact_object"] and own["usage_present"], own)
    lab.check("red", "Authenticated unbound comparator is denied the same metrics.k8s.io read",
              denied_reply.get("status") == 403, {"http_status": denied_reply.get("status")})
    lab.check("red", "Namespaced metrics reader is denied a PodMetrics request outside its RoleBinding namespace",
              cross_reply.get("status") == 403, {"http_status": cross_reply.get("status")})
