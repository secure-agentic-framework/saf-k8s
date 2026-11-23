"""SAF-K8S-0502-005 synthetic in-cluster protocol TLS fixture.

Implements the reference/lab.py case contract: run(lab). This module does not
create a Kind cluster; the supervisor's lab owns cluster lifecycle.
"""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time


CONTROL_ID = "SAF-K8S-0502-005"
NAMESPACE = "saf-0502-005"
PORTS = {"plain": 8080, "tls": 8443}
IMAGE = ("docker.io/library/python:3.13.7-alpine3.22@sha256:"
         "9ba6d8cbebf0fb6546ae71f2a1c14f6ffd2fdab83af7fa5669734ef30ad48844")
NODE_IMAGE = ("kindest/node:v1.36.1@sha256:"
              "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5")
APP = Path(__file__).with_name("app.py")
MARKERS = {
    "store": "saf-0502-005-synthetic-dataset-marker",
    "registry": "saf-0502-005-synthetic-model-marker",
}
HOSTS = {name: "%s.%s.svc.cluster.local" % (name, NAMESPACE) for name in MARKERS}
SCOPE = (
    "One disposable stock Kind v0.32.0 cluster with Kubernetes v1.36.1 and kindnet; "
    "case-owned synthetic data-store and model-registry/inference Services, one client, "
    "and temporary CA/leaf certificates. Each endpoint serves the same fixed marker on "
    "HTTP/8080 and TLS/8443 before enforcement. A client egress NetworkPolicy then permits "
    "DNS and case endpoint TCP/8443 only. The case checks plaintext baseline retrieval, "
    "plaintext-port rejection after policy, trusted TLS with expected service DNS identity, "
    "wrong-name rejection, untrusted-CA rejection, and continued marker retrieval over TLS. "
    "This tests application TLS verification and port-level egress restriction on these "
    "synthetic paths only. It does not prove CNI transparent encryption, storage or registry "
    "vendor settings, production workload coverage, RDMA, GPU/NCCL traffic, performance, "
    "or encryption of every data path."
)


class ProbeAmbiguous(Exception):
    """A failure was not the expected protocol or policy result."""


def _run_openssl(*args):
    try:
        result = subprocess.run(["openssl", *args], capture_output=True, text=True,
                                check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("openssl command unavailable or timed out") from error
    if result.returncode:
        # Keep command output out of logs; it may contain generated paths.
        raise RuntimeError("synthetic certificate generation failed")


def _make_ca(directory, name):
    key = directory / (name + "-ca.key")
    cert = directory / (name + "-ca.crt")
    _run_openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                 "-keyout", str(key), "-out", str(cert), "-subj", "/CN=%s-synthetic-ca" % name,
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-addext", "subjectKeyIdentifier=hash")
    key.chmod(0o600)
    return key, cert


def _make_leaf(directory, ca, name, dns_name):
    ca_key, ca_cert = ca
    key = directory / (name + ".key")
    csr = directory / (name + ".csr")
    cert = directory / (name + ".crt")
    ext = directory / (name + ".ext")
    ext.write_text("subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n"
                   "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                   "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n"
                   % dns_name)
    _run_openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                 "-out", str(csr), "-subj", "/CN=%s" % dns_name)
    _run_openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey",
                 str(ca_key), "-CAcreateserial", "-days", "2", "-extfile", str(ext),
                 "-out", str(cert))
    key.chmod(0o600)
    return key, cert


def _apply(lab, directory, name, resource):
    path = directory / (name + ".json")
    path.write_text(json.dumps(resource, sort_keys=True))
    if resource["kind"] != "Secret":
        lab.kubectl("-n", NAMESPACE, "apply", "-f", str(path))
        return
    path.chmod(0o600)
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "-n", NAMESPACE, "--request-timeout=20s",
               "create", "-f", str(path), "-o", "name"]
    try:
        result = subprocess.run(command, capture_output=True, env=lab.env, timeout=25)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("Synthetic TLS Secret could not be provisioned")
    finally:
        path.unlink(missing_ok=True)
    if result.returncode:
        lab.block("Synthetic TLS Secret API request failed")


def _labels(role):
    return {"saf-k8s.example/control": "0502-005", "saf-k8s.example/role": role}


def _pod(name, role, command, *, tls_secret=None, client=False):
    mounts = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "fixture", "configMap": {"name": "fixture-code"}}]
    if tls_secret:
        mounts.append({"name": "tls", "mountPath": "/tls", "readOnly": True})
        volumes.append({"name": "tls", "secret": {"secretName": tls_secret}})
    if client:
        mounts.append({"name": "cas", "mountPath": "/cas", "readOnly": True})
        volumes.append({"name": "cas", "configMap": {"name": "fixture-cas"}})
    container = {
        "name": name, "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": command,
        "resources": {"requests": {"cpu": "5m", "memory": "24Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 65532,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumeMounts": mounts,
    }
    if not client:
        container["ports"] = [{"name": "plain", "containerPort": PORTS["plain"]},
                               {"name": "tls", "containerPort": PORTS["tls"]}]
        container["readinessProbe"] = {"httpGet": {"path": "/marker", "port": "plain"},
                                       "periodSeconds": 2, "failureThreshold": 15}
        container["livenessProbe"] = {"httpGet": {"path": "/marker", "port": "plain"},
                                      "periodSeconds": 10, "failureThreshold": 3}
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels(role)},
        "spec": {"restartPolicy": "Always" if not client else "Never",
                 "automountServiceAccountToken": False,
                 "terminationGracePeriodSeconds": 1,
                 "containers": [container], "volumes": volumes},
    }


def _service(name):
    return {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {"type": "ClusterIP", "selector": _labels(name),
                 "ports": [{"name": "plain", "protocol": "TCP", "port": 8080,
                            "targetPort": "plain"},
                           {"name": "tls", "protocol": "TCP", "port": 8443,
                            "targetPort": "tls"}]},
    }


def _tls_secret(name, leaf):
    key, cert = leaf
    return {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "type": "kubernetes.io/tls",
        "data": {"tls.crt": base64.b64encode(cert.read_bytes()).decode("ascii"),
                 "tls.key": base64.b64encode(key.read_bytes()).decode("ascii")},
    }


def _wait_ready(lab, name):
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/" + name,
                "--timeout=90s", timeout=100)


def _probe(lab, mode, host, *, expected_name="", ca=""):
    args = ["python3", "/fixture/app.py", "probe", "--mode", mode,
            "--connect-host", host]
    if mode == "tls":
        args += ["--expected-name", expected_name, "--ca-file", ca]
    result = lab.kubectl("-n", NAMESPACE, "exec", "pod/client", "--", *args,
                         allow_failure=True, timeout=15)
    if result.returncode:
        raise ProbeAmbiguous("client process did not return a classified observation")
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as error:
        raise ProbeAmbiguous("client emitted no parseable observation") from error


def _repeat(lab, mode, host, expected, *, expected_name="", ca="", attempts=3):
    seen = []
    for _ in range(attempts):
        seen.append(_probe(lab, mode, host, expected_name=expected_name, ca=ca))
        if seen[-1] != expected:
            break
        time.sleep(0.2)
    matched = len(seen) == attempts and all(item == expected for item in seen)
    return matched, {"host": host, "mode": mode, "expected": expected,
                     "observations": seen, "three_consecutive": matched}


def _policy():
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "tls-only-egress", "namespace": NAMESPACE},
        "spec": {
            "podSelector": {"matchLabels": _labels("client")},
            "policyTypes": ["Egress"],
            "egress": [
                {"to": [{"namespaceSelector": {"matchLabels": {
                    "kubernetes.io/metadata.name": "kube-system"}},
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                 "ports": [{"protocol": "UDP", "port": 53},
                           {"protocol": "TCP", "port": 53}]},
                {"to": [{"podSelector": {"matchLabels": _labels(name)}}
                        for name in MARKERS],
                 "ports": [{"protocol": "TCP", "port": PORTS["tls"]}]},
            ],
        },
    }


def _check_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block("Expected kind v0.32.0, got %r" % kind_version)
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server_version = version.get("serverVersion", {}).get("gitVersion")
    if server_version != "v1.36.1":
        lab.block("Expected Kubernetes v1.36.1, got %r" % server_version)
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    lab.check("positive", "Kind/Kubernetes versions and kindnet match the reviewed fixture",
              True, {"kind": kind_version, "kubernetes": server_version,
                     "cni": "kube-system/kindnet"})


def run(lab):
    _check_platform(lab)
    lab.kubectl("create", "namespace", NAMESPACE)
    with tempfile.TemporaryDirectory(prefix="saf-0502-005-") as temporary:
        directory = Path(temporary)
        store_ca = _make_ca(directory, "store")
        registry_ca = _make_ca(directory, "registry")
        unknown_ca = _make_ca(directory, "untrusted")
        store_leaf = _make_leaf(directory, store_ca, "store-leaf", HOSTS["store"])
        registry_leaf = _make_leaf(directory, registry_ca, "registry-leaf", HOSTS["registry"])
        trusted_bundle = directory / "trusted-ca.pem"
        trusted_bundle.write_bytes(store_ca[1].read_bytes() + registry_ca[1].read_bytes())
        untrusted_bundle = directory / "untrusted-ca.pem"
        untrusted_bundle.write_bytes(unknown_ca[1].read_bytes())

        configmap = {"apiVersion": "v1", "kind": "ConfigMap",
                     "metadata": {"name": "fixture-code", "namespace": NAMESPACE},
                     "data": {"app.py": APP.read_text()}}
        cas = {"apiVersion": "v1", "kind": "ConfigMap",
               "metadata": {"name": "fixture-cas", "namespace": NAMESPACE},
               "data": {"trusted-ca.pem": trusted_bundle.read_text(),
                        "untrusted-ca.pem": untrusted_bundle.read_text()}}
        for name, resource in (
            ("code", configmap), ("cas", cas),
            ("store-secret", _tls_secret("store-tls", store_leaf)),
            ("registry-secret", _tls_secret("registry-tls", registry_leaf)),
        ):
            _apply(lab, directory, name, resource)
        for name, secret in (("store", "store-tls"), ("registry", "registry-tls")):
            _apply(lab, directory, name + "-pod",
                   _pod(name, name, ["python3", "/fixture/app.py", "serve",
                                     "--marker", MARKERS[name], "--cert", "/tls/tls.crt",
                                     "--key", "/tls/tls.key"], tls_secret=secret))
            _apply(lab, directory, name + "-service", _service(name))
        _apply(lab, directory, "client",
               _pod("client", "client", ["python3", "-c", "import time; time.sleep(3600)"],
                    client=True))
        for name in MARKERS:
            _wait_ready(lab, name)
        _wait_ready(lab, "client")

        # Red baseline: the same fixed synthetic marker is reachable over plaintext.
        for name, marker in MARKERS.items():
            expected = {"outcome": "marker", "marker": marker}
            matched, receipt = _repeat(lab, "plain", HOSTS[name], expected)
            lab.check("red", "No-policy plaintext baseline retrieves %s marker" % name,
                      matched, receipt)

        policy = _policy()
        _apply(lab, directory, "policy", policy)
        actual = json.loads(lab.kubectl("-n", NAMESPACE, "get", "networkpolicy",
                                        policy["metadata"]["name"], "-o", "json").stdout)
        if actual.get("spec") != policy["spec"]:
            lab.block("Applied egress policy differs from the reviewed TCP port boundary")

        # NetworkPolicy programming is asynchronous. Wait for the two exact
        # previously successful paths to converge before recording repeated probes.
        for name in MARKERS:
            deadline = time.monotonic() + 30
            while True:
                outcome = _probe(lab, "plain", HOSTS[name])["outcome"]
                if outcome == "timeout":
                    break
                if outcome != "marker" or time.monotonic() >= deadline:
                    lab.block(f"Plaintext probe for {name} did not reach the expected policy outcome")
                time.sleep(0.5)

        for name in MARKERS:
            expected = {"outcome": "timeout"}
            matched, receipt = _repeat(lab, "plain", HOSTS[name], expected)
            lab.check("green", "Policy blocks %s plaintext port while DNS remains permitted" % name,
                      matched, receipt)

        # Trusted TLS is the permitted application transport for both endpoints.
        for name, marker in MARKERS.items():
            expected = {"outcome": "marker", "marker": marker}
            matched, receipt = _repeat(lab, "tls", HOSTS[name], expected,
                                       expected_name=HOSTS[name], ca="/cas/trusted-ca.pem")
            lab.check("positive", "Trusted TLS preserves %s marker retrieval" % name,
                      matched, receipt)

        cases = (
            ("wrong-name", "store", "wrong-name.%s.svc.cluster.local" % NAMESPACE,
             "/cas/trusted-ca.pem",
             {"outcome": "certificate_error", "reason": "hostname"}),
            ("untrusted-ca", "registry", HOSTS["registry"], "/cas/untrusted-ca.pem",
             {"outcome": "certificate_error", "reason": "trust"}),
        )
        for label, endpoint, expected_name, ca_path, expected in cases:
            matched, receipt = _repeat(lab, "tls", HOSTS[endpoint], expected,
                                       expected_name=expected_name, ca=ca_path)
            lab.check("negative", "%s fails certificate verification" % label,
                      matched, receipt)

        # Re-probe the permitted path after the negative cases to rule out a
        # client/server failure being mistaken for certificate rejection.
        for name, marker in MARKERS.items():
            matched, receipt = _repeat(
                lab, "tls", HOSTS[name], {"outcome": "marker", "marker": marker},
                expected_name=HOSTS[name], ca="/cas/trusted-ca.pem")
            lab.check("positive", "Permitted TLS path remains healthy after negative probes: %s" % name,
                      matched, receipt)
