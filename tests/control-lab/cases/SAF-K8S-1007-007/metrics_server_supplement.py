"""Minimal pinned TLS Metrics Server setup reused from SAF-K8S-1002-005."""
import base64
import hashlib
import json
from pathlib import Path

METRICS_URL = "https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.1/components.yaml"
METRICS_SHA256 = "4a672c4891902573a3ff753cece5de1bf1f55dd053403dfec39df9d1636b7ff1"
METRICS_IMAGE = "registry.k8s.io/metrics-server/metrics-server@sha256:b2d2efaf5ac3b366ed0f839d2412a2c4279d4fc2a2a733f12c52133faed36c41"
METRICS_OLD_IMAGE = "registry.k8s.io/metrics-server/metrics-server:v0.8.1"
METRICS_NS = "kube-system"
METRICS_API = "v1beta1.metrics.k8s.io"
KUBELET_CERT_DIR = "/etc/kubernetes/saf-metrics-kubelet-tls"


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(content)
    path.chmod(0o600)


def create_fixture_tls(lab, directory, service, *, extra_dns=()):
    """Create a short-lived case CA/leaf with SAN and TLS usage constraints."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_key, root_crt = directory / "ca.key", directory / "ca.crt"
    leaf_key, leaf_crt = directory / "tls.key", directory / "tls.crt"
    request, config = directory / "leaf.csr", directory / "openssl.conf"
    san_names = ",".join(f"DNS:{name}" for name in (service, *extra_dns))
    _write(config, "[req]\ndistinguished_name=dn\n[dn]\n"
                   "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                   "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                   f"extendedKeyUsage=serverAuth\nsubjectAltName={san_names}\n")
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
    create_fixture_tls(lab, kubelet_tls, f"{lab.cluster}-control-plane",
                       extra_dns=(f"{lab.cluster}-worker",))
    text = config.read_text()
    mount_anchor = "  extraMounts:\n  kubeadmConfigPatches:\n"
    if text.count(mount_anchor) != 1:
        lab.block("Metrics Server supplement could not locate the Kind mount section")
    mount = (f"  - hostPath: {json.dumps(str(kubelet_tls))}\n"
             f"    containerPath: {KUBELET_CERT_DIR}\n    readOnly: true\n")
    text = text.replace(mount_anchor, "  extraMounts:\n" + mount + "  kubeadmConfigPatches:\n", 1)
    anchor = "  kubeadmConfigPatches:\n- role: worker"
    patch = ("  - |\n"
             "    apiVersion: kubelet.config.k8s.io/v1beta1\n"
             "    kind: KubeletConfiguration\n"
             "    serverTLSBootstrap: false\n"
             f"    tlsCertFile: {KUBELET_CERT_DIR}/tls.crt\n"
             f"    tlsPrivateKeyFile: {KUBELET_CERT_DIR}/tls.key\n")
    if text.count(anchor) != 1:
        lab.block("Metrics Server supplement could not place the control-plane Kubelet patch")
    text = text.replace(anchor, "  kubeadmConfigPatches:\n" + patch + "- role: worker", 1)
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
    node_names = (f"{lab.cluster}-control-plane", f"{lab.cluster}-worker")
    host_aliases = []
    for node in node_names:
        node_obj = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)
        ipv4 = next(address["address"] for address in node_obj["status"]["addresses"]
                    if address["type"] == "InternalIP" and ":" not in address["address"])
        host_aliases.append({"ip": ipv4, "hostnames": [node]})

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
        "hostAliases": host_aliases,
        "nodeSelector": {"node-role.kubernetes.io/control-plane": ""},
        "tolerations": [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists",
                         "effect": "NoSchedule"}],
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
