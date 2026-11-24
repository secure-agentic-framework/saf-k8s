"""Validate kube-apiserver backend trust in the harness-owned Kind cluster."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

PKI = "/etc/kubernetes/pki"
MOUNT = PKI + "/saf-backend-tls"
MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
STAGED_MANIFEST = "/etc/kubernetes/manifests/.saf-backend-tls.yaml"
UNKNOWN_AUTHORITY = "x509: certificate signed by unknown authority"
MARKER = "saf-backend-tls-marker"


def _run(args, *, timeout=30, input_text=None, env=None):
    return subprocess.run(list(map(str, args)), input=input_text, text=True,
                          capture_output=True, timeout=timeout, env=env)


def _required(lab, *args):
    result = _run(["openssl", *args])
    if result.returncode:
        lab.block(f"Could not prepare synthetic TLS material ({args[0]})")
    return result.stdout


def _make_ca(lab, directory: Path, label: str):
    key = directory / f"{label}-ca.key"
    cert = directory / f"{label}-ca.crt"
    config = directory / f"{label}-ca.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\n[dn]\n[ca_ext]\n"
        "basicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
    )
    _required(lab, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "5",
              "-sha256", "-config", config, "-extensions", "ca_ext", "-subj",
              f"/CN=SAF Disposable {label} CA", "-keyout", key, "-out", cert)
    key.chmod(0o600)
    return key, cert


def _make_leaf(lab, directory: Path, label: str, ca_key: Path, ca_cert: Path,
               *, dns=(), ips=(), client=False):
    key = directory / f"{label}.key"
    csr = directory / f"{label}.csr"
    cert = directory / f"{label}.crt"
    ext = directory / f"{label}.ext"
    _required(lab, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
              "-subj", f"/CN=SAF Disposable {label}", "-keyout", key, "-out", csr)
    key.chmod(0o600)
    sans = [*(f"DNS:{name}" for name in dns), *(f"IP:{name}" for name in ips)]
    usage = "clientAuth" if client else "serverAuth"
    ext.write_text(
        "[leaf]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage={usage}\n"
        + (f"subjectAltName={','.join(sans)}\n" if sans else "")
    )
    _required(lab, "x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
              "-set_serial", str(int(time.time() * 1000) % 2_000_000_000 + 1),
              "-sha256", "-days", "2", "-extfile", ext, "-extensions", "leaf",
              "-out", cert)
    return cert, key


def _fingerprint(lab, cert: Path):
    out = _required(lab, "x509", "-in", cert, "-noout", "-fingerprint", "-sha256",
                    "-subject", "-serial", "-dates", "-ext", "subjectAltName")
    normalized = out.replace("sha256 Fingerprint", "sha256 fingerprint")
    match = re.search(r"fingerprint=([0-9a-f:]+)", normalized, re.IGNORECASE)
    if not match:
        lab.block(f"No public certificate fingerprint was produced for {cert.name}")
    pem = cert.read_bytes()
    return {
        "sha256_fingerprint": match.group(1).lower(),
        "pem_sha256": hashlib.sha256(pem).hexdigest(),
        "details": normalized.strip(),
    }


def _node(lab, *args, **kwargs):
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", *args, **kwargs)


def _api(lab, endpoint):
    return lab.kubectl("get", f"--raw={endpoint}", timeout=12, allow_failure=True)


def _running_api(lab):
    return set(_node(lab, "crictl", "ps", "--name", "kube-apiserver", "-q").stdout.split())


def _api_ids(lab):
    return set(_node(lab, "crictl", "ps", "-a", "--name", "kube-apiserver", "-q").stdout.split())


def _wait_new_ready(lab, previous):
    end = time.monotonic() + 100
    while time.monotonic() < end:
        current = _running_api(lab) - previous
        if current:
            ready = _api(lab, "/readyz")
            if ready.returncode == 0 and ready.stdout.strip() == "ok":
                return
        time.sleep(1)
    lab.block("The replacement API server did not become ready")


def _with_flag(original, name, value):
    flag = f"--{name}="
    old = re.compile(rf"(?m)^([ \t]+-[ \t]+){re.escape(flag)}[^\n]+$")
    rendered, count = old.subn(lambda match: match[1] + flag + value, original)
    if count == 0:
        initial = re.search(r"(?m)^([ \t]+- kube-apiserver)$", original)
        if initial is None:
            raise ValueError("The owned static manifest has no apiserver argument list")
        indentation = initial[1].split("-")[0]
        rendered = original[:initial.end()] + f"\n{indentation}- {flag}{value}" + original[initial.end():]
    elif count != 1:
        raise ValueError("The owned static manifest has duplicate trust arguments")
    return rendered


def _write_manifest(lab, content):
    # Force the case-owned kubelet to ingest the new source after restart and
    # stop the previous container so it cannot answer either route probe.
    _node(lab, "systemctl", "stop", "kubelet", timeout=30)
    try:
        lab.command("docker", "exec", "-i", f"{lab.cluster}-control-plane", "sh", "-ceu",
                    'cat > "$1"; chmod 600 "$1"; mv -f "$1" "$2"',
                    "sh", STAGED_MANIFEST, MANIFEST, payload=content)
        for container in sorted(_running_api(lab)):
            _node(lab, "crictl", "stop", "--timeout", "5", container, timeout=20)
    finally:
        _node(lab, "systemctl", "start", "kubelet", timeout=30)


@contextmanager
def _change_trust(lab, baseline, name):
    previous = _api_ids(lab)
    try:
        _write_manifest(lab, _with_flag(baseline, name, MOUNT + "/unrelated-ca.crt"))
        yield previous
    finally:
        previous = _api_ids(lab)
        _write_manifest(lab, baseline)
        _wait_new_ready(lab, previous)


def _endpoint_protocol(lab, address, port, ca, *, client=False):
    options = ["timeout", "6", "openssl", "s_client", "-brief", "-verify_return_error",
               "-connect", f"{address}:{port}", "-verify_ip", address, "-CAfile", ca]
    if client:
        options += ["-cert", PKI + "/apiserver-etcd-client.crt", "-key", PKI + "/apiserver-etcd-client.key"]
    result = _node(lab, *options, allow_failure=True, timeout=9)
    transcript = result.stderr + result.stdout
    protocol = re.search(r"Protocol version:\s*(TLSv[0-9.]+)", transcript)
    return {"protocol": protocol[1] if protocol else None,
            "verified_endpoint": "Verification: OK" in transcript}


def _etcd_live(lab):
    instances = _node(lab, "crictl", "ps", "--name", "etcd", "-q").stdout.split()
    if len(instances) != 1:
        return False
    result = _node(lab, "crictl", "exec", instances[0], "etcdctl",
                   "--endpoints=https://127.0.0.1:2379", "--dial-timeout=3s", "--command-timeout=5s",
                   "--cacert=" + PKI + "/etcd/ca.crt",
                   "--cert=" + PKI + "/etcd/healthcheck-client.crt",
                   "--key=" + PKI + "/etcd/healthcheck-client.key",
                   "endpoint", "health", allow_failure=True, timeout=10)
    return result.returncode == 0 and "is healthy" in result.stdout + result.stderr


def _etcd_certificate_refusal(lab, previous):
    end = time.monotonic() + 75
    while time.monotonic() < end:
        for candidate in sorted(_api_ids(lab) - previous):
            logs = _node(lab, "crictl", "logs", "--tail=50", candidate, allow_failure=True, timeout=10)
            matching = [line for line in (logs.stdout + "\n" + logs.stderr).splitlines()
                        if UNKNOWN_AUTHORITY in line and "127.0.0.1:2379" in line]
            if matching:
                return matching[0]
        time.sleep(1)
    return None


def _reads_marker(result):
    if result.returncode:
        return False
    response = json.loads(result.stdout)
    return response.get("metadata", {}).get("name") == MARKER and response.get("data", {}).get("marker") == "owned"


def run(lab):
    node = f"{lab.cluster}-control-plane"
    endpoint = lab.kubectl("get", "node", node,
                           '-o=jsonpath={.status.addresses[?(@.type=="InternalIP")].address}').stdout.strip()
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", endpoint):
        lab.block("The owned node does not expose the fixture IPv4 address")
    root = lab.kubeconfig.parent / "backend-tls"
    root.mkdir(mode=0o700)
    signing_key, ca = _make_ca(lab, root, "kubelet")
    _, unrelated = _make_ca(lab, root, "unrelated")
    serving, serving_key = _make_leaf(lab, root, "kubelet-serving", signing_key, ca,
                                      dns=(node,), ips=(endpoint,))
    signing_key.unlink()
    (root / "unrelated-ca.key").unlink()
    _node(lab, "mkdir", "-m", "700", MOUNT)
    for material in (ca, unrelated, serving, serving_key):
        lab.command("docker", "cp", str(material), f"{node}:{MOUNT}/{material.name}")
    _node(lab, "sh", "-ceu",
          'f=/var/lib/kubelet/config.yaml; sed -i "/^tlsCertFile:/d; /^tlsPrivateKeyFile:/d" "$f"; '
          'printf "\\ntlsCertFile: %s\\ntlsPrivateKeyFile: %s\\n" "$1" "$2" >> "$f"; systemctl restart kubelet',
          "sh", MOUNT + "/" + serving.name, MOUNT + "/" + serving_key.name, timeout=35)

    default = _node(lab, "cat", MANIFEST).stdout
    baseline = _with_flag(default, "kubelet-certificate-authority", MOUNT + "/" + ca.name)
    previous = _api_ids(lab)
    _write_manifest(lab, baseline)
    _wait_new_ready(lab, previous)

    health_path = f"/api/v1/nodes/{node}/proxy/healthz"
    health = _api(lab, health_path)
    kubelet_tls = _endpoint_protocol(lab, endpoint, 10250, MOUNT + "/" + ca.name)
    lab.check("positive", "The API server reaches the named kubelet health endpoint with its intended CA",
              health.returncode == 0 and health.stdout.strip() == "ok" and kubelet_tls["verified_endpoint"],
              {"trusted_proxy_operation": health.returncode == 0 and health.stdout.strip() == "ok",
               "verified_endpoint": kubelet_tls["verified_endpoint"]})
    with _change_trust(lab, baseline, "kubelet-certificate-authority") as previous:
        _wait_new_ready(lab, previous)
        refusal = _api(lab, health_path)
    native_kubelet = refusal.returncode != 0 and UNKNOWN_AUTHORITY in refusal.stderr
    lab.check("red", "The same API server proxy operation returns native X.509 refusal with an unrelated CA",
              native_kubelet, {"native_route_certificate_refusal": native_kubelet})
    restored_health = _api(lab, health_path)
    restored_kubelet = restored_health.returncode == 0 and restored_health.stdout.strip() == "ok"
    lab.check("green", "Restoring the selected kubelet CA restores the identical operation",
              restored_kubelet, {"proxy_route_recovered": restored_kubelet})

    marker_path = f"/api/v1/namespaces/saf-test/configmaps/{MARKER}"
    lab.kubectl("create", "configmap", MARKER, "--from-literal=marker=owned")
    original_storage = _reads_marker(_api(lab, marker_path))
    etcd_tls = _endpoint_protocol(lab, "127.0.0.1", 2379, PKI + "/etcd/ca.crt", client=True)
    lab.check("positive", "The API server reads the exact ConfigMap with a live authenticated etcd backend",
              original_storage and etcd_tls["verified_endpoint"] and _etcd_live(lab),
              {"initial_marker_read": original_storage, "verified_endpoint": etcd_tls["verified_endpoint"]})

    with _change_trust(lab, baseline, "etcd-cafile") as previous:
        native_etcd_log = _etcd_certificate_refusal(lab, previous)
        negative = _api(lab, marker_path)
        healthy_etcd = _etcd_live(lab)
    native_etcd = native_etcd_log is not None and negative.returncode != 0
    lab.check("red", "The API server rejects the healthy etcd endpoint with wrong CA and the same storage read fails",
              native_etcd and healthy_etcd, {"native_etcd_certificate_refusal": native_etcd,
                                            "owned_etcd_stays_healthy": healthy_etcd})
    storage_recovered = _reads_marker(_api(lab, marker_path))
    lab.check("green", "Restoring the etcd CA restores the identical storage read",
              storage_recovered, {"storage_read_recovered": storage_recovered})
    (lab.evidence / "backend-tls-observations.json").write_text(json.dumps({
        "kubelet": {"trusted_leaf": _fingerprint(lab, serving), "direct_tls_probe": kubelet_tls,
                    "native_refusal": refusal.stderr.strip(), "restored": restored_kubelet},
        "etcd": {"direct_tls_probe": etcd_tls, "healthy_during_refusal": healthy_etcd,
                 "native_apiserver_log": native_etcd_log, "storage_read_status": negative.stderr.strip(),
                 "restored": storage_recovered},
    }, indent=2) + "\n")
