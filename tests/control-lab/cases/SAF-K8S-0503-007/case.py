"""Exercise a local Traefik TLS boundary on an isolated kind cluster."""
from hashlib import sha256
import json
from pathlib import Path
import ssl
import socket
import subprocess
import tempfile
import time


CONTROL_ID = "SAF-K8S-0503-007"
CHART_VERSION = "42.4.1"
TRAEFIK_VERSION = "v3.7.19"
TRAEFIK_IMAGE = (
    "ghcr.io/traefik/traefik@sha256:"
    "a6c0194dda77bcb804824580f36fa7edc56e315b1acfe933366c8b52844a78a4"
)
GATEWAY_API_VERSION = "v1.6.3"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-0503-007"
APP = "synthetic-ingress-app"
HOSTNAME = "app.saf.test"
MARKER = "SAF-K8S-0503-007 harmless ingress marker 54a1"
TLS12_CIPHERS = {
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
}
TLS12_OPENSSL_NAMES = {
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
}
HTTP_NODE_PORT = 30080
HTTPS_NODE_PORT = 30443
UNAPPROVED_TLS12_CIPHER = "ECDHE-RSA-CHACHA20-POLY1305"
SCOPE = (
    "One disposable kind cluster running Kubernetes v1.36.1, one Traefik Proxy "
    "Gateway API controller (chart 42.4.1; image v3.7.19 pinned by the GHCR "
    "manifest digest), one synthetic Python HTTP application, and one Gateway. "
    "Two dedicated host-loopback ports map to the fixture's NodePorts. "
    "The case first routes a fixed GET over plaintext HTTP with no TLS listener, "
    "then replaces that listener with HTTPS termination using a local CA-signed "
    "certificate, minimum TLS 1.2, and a small TLS 1.2 cipher allowlist. It probes "
    "trusted and untrusted CAs, the correct and incorrect client hostname, accepted "
    "TLS versions, the exact response marker, and unmatched host/path behavior. "
    "No internet target, public address, production resource, attack traffic, "
    "WAF, application authorization, cloud load balancer, or certificate issuer "
    "is involved."
)


def kubectl(lab, *args, timeout=45, allow_failure=False, payload=None):
    return lab.kubectl(*args, timeout=timeout, allow_failure=allow_failure,
                       payload=payload)


def make_app():
    source = (
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        f"MARKER = {MARKER!r}.encode()\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        " def do_GET(self):\n"
        "  body = MARKER if self.path == '/marker' else b'not found'\n"
        "  self.send_response(200 if self.path == '/marker' else 404)\n"
        "  self.send_header('Content-Length', str(len(body)))\n"
        "  self.end_headers()\n"
        "  self.wfile.write(body)\n"
        " def log_message(self, fmt, *args): pass\n"
        "HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()\n"
    )
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": APP, "namespace": NAMESPACE,
                     "labels": {"app": APP}},
        "spec": {"replicas": 1,
                 "selector": {"matchLabels": {"app": APP}},
                 "template": {
                     "metadata": {"labels": {"app": APP}},
                     "spec": {
                         "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True,
                                             "runAsUser": 65532,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{
                             "name": "app", "image": PYTHON_IMAGE,
                             "imagePullPolicy": "IfNotPresent",
                             "command": ["python", "-u", "-c", source],
                             "ports": [{"name": "http", "containerPort": 8080}],
                             "readinessProbe": {"tcpSocket": {"port": 8080},
                                                "periodSeconds": 2,
                                                "failureThreshold": 30},
                             "resources": {
                                 "requests": {"cpu": "10m", "memory": "64Mi"},
                                 "limits": {"cpu": "200m", "memory": "128Mi"}},
                             "securityContext": {
                                 "allowPrivilegeEscalation": False,
                                 "capabilities": {"drop": ["ALL"]},
                                 "readOnlyRootFilesystem": True}}]}}}
    }


def make_gateway(listeners):
    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {"name": "fixture-gateway", "namespace": NAMESPACE},
        "spec": {"gatewayClassName": "fixture-traefik",
                 "listeners": listeners},
    }


def route(listener):
    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {"name": "fixture-route", "namespace": NAMESPACE},
        "spec": {
            "parentRefs": [{"name": "fixture-gateway", "sectionName": listener}],
            "hostnames": [HOSTNAME],
            "rules": [{
                "matches": [{"path": {"type": "Exact", "value": "/marker"}}],
                "backendRefs": [{"name": APP, "port": 8080}],
            }],
        },
    }


def issue_certificates(lab, directory):
    def openssl(*args):
        lab.command("openssl", *args, timeout=30)

    ca_key, ca_cert = directory / "fixture-ca.key", directory / "fixture-ca.crt"
    wrong_ca_key, wrong_ca_cert = directory / "wrong-ca.key", directory / "wrong-ca.crt"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=SAF local fixture CA", "-addext",
            "basicConstraints=critical,CA:TRUE", "-addext",
            "keyUsage=critical,keyCertSign,cRLSign", "-addext",
            "subjectKeyIdentifier=hash", "-keyout", str(ca_key),
            "-out", str(ca_cert))
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=SAF unrelated fixture CA", "-addext",
            "basicConstraints=critical,CA:TRUE", "-addext",
            "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(wrong_ca_key),
            "-out", str(wrong_ca_cert))
    key, csr, cert, ext = (directory / name for name in
                           ("server.key", "server.csr", "server.crt", "server.ext"))
    ext.write_text("basicConstraints=critical,CA:FALSE\n"
                   "keyUsage=critical,digitalSignature,keyEncipherment\n"
                   "extendedKeyUsage=serverAuth\n"
                   "authorityKeyIdentifier=keyid\n"
                   "subjectKeyIdentifier=hash\n"
                   f"subjectAltName=DNS:{HOSTNAME}\n")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj",
            f"/CN={HOSTNAME}", "-keyout", str(key), "-out", str(csr))
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "2", "-sha256",
            "-extfile", str(ext), "-out", str(cert))
    return {"ca": ca_cert, "wrong_ca": wrong_ca_cert,
            "key": key, "cert": cert}


def apply(lab, resource):
    namespace = resource["metadata"].get("namespace")
    scope = ("-n", namespace) if namespace else ()
    kubectl(lab, *scope, "apply", "-f", "-", payload=json.dumps(resource))


def wait_conditions(lab, kind, name, conditions, namespace=NAMESPACE, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = kubectl(lab, "-n", namespace, "get", kind, name, "-o", "json")
        obj = json.loads(result.stdout)
        status = obj.get("status", {})
        condition_rows = list(status.get("conditions", []))
        for parent in status.get("parents", []):
            condition_rows.extend(parent.get("conditions", []))
        observed = {c.get("type"): c.get("status") for c in condition_rows}
        if all(observed.get(condition) == "True" for condition in conditions):
            generation = obj["metadata"]["generation"]
            fresh = {row["type"] for row in condition_rows
                     if row.get("observedGeneration") == generation}
            if fresh.issuperset(conditions):
                return observed
        time.sleep(2)
    kubectl(lab, "-n", "traefik", "logs", "deployment/traefik", "--tail=80",
            allow_failure=True)
    lab.block(f"{kind}/{name} did not reach conditions {conditions}; see controller logs")


def mapped_port(lab, node_port):
    mapping = lab.command("docker", "port", f"{lab.cluster}-control-plane",
                          f"{node_port}/tcp").stdout.strip()
    address, _, port = mapping.rpartition(":")
    if address != "127.0.0.1" or not port.isdigit():
        lab.block(f"Expected one loopback mapping for fixture port {node_port}")
    return int(port)


def request(host_header, *, port, server_name=None, ca_file=None, tls_version=None,
            cipher=None, path="/marker"):
    if ca_file is None:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.sendall((f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                          "Connection: close\r\n\r\n").encode("ascii"))
            raw = b""
            while len(raw) < 8192:
                part = conn.recv(2048)
                if not part:
                    break
                raw += part
        head, _, body = raw.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        return {"status": status, "body": body.decode("utf-8", "replace"),
                "protocol": "HTTP"}

    context = ssl.create_default_context(cafile=str(ca_file))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if tls_version:
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        if tls_version == ssl.TLSVersion.TLSv1_1:
            context.set_ciphers("ALL:@SECLEVEL=0")
    if cipher:
        context.set_ciphers(cipher)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=server_name or HOSTNAME) as conn:
            conn.settimeout(5)
            conn.sendall((f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                          "Connection: close\r\n\r\n").encode("ascii"))
            response = conn.makefile("rb")
            first = response.readline(256).decode("ascii", "replace").strip()
            fields = first.split(" ", 2)
            status = int(fields[1])
            headers = {}
            while True:
                line = response.readline(2048)
                if line in (b"\r\n", b"", b"\n"):
                    break
                if b":" in line:
                    key, value = line.split(b":", 1)
                    headers[key.strip().lower()] = value.strip()
            body = response.read(int(headers.get(b"content-length", b"0")))
            cipher = conn.cipher()[0]
            return {"status": status, "body": body.decode("utf-8", "replace"),
                    "protocol": conn.version(),
                    "cipher": TLS12_OPENSSL_NAMES.get(cipher, cipher)}


def wait_for_response(probe, status, body_matches, timeout=20):
    """Allow the data plane to apply configuration acknowledged by the controller."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            response = probe()
        except OSError as error:
            response = {"error": str(error)}
        matched = response.get("status") == status and body_matches(response.get("body"))
        if matched or time.monotonic() >= deadline:
            return response
        time.sleep(0.5)


def run(lab):
    if not ssl.HAS_TLSv1_3:
        lab.block("Use Python linked against a TLS 1.3-capable SSL library for this case")
    http_port = mapped_port(lab, HTTP_NODE_PORT)
    https_port = mapped_port(lab, HTTPS_NODE_PORT)
    node_version = json.loads(kubectl(lab, "version", "-o", "json").stdout)[
        "serverVersion"]["gitVersion"]
    if node_version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {node_version}")
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected kind v0.32.0, got {kind_version}")

    lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "apply", "-f",
        f"https://github.com/kubernetes-sigs/gateway-api/releases/download/"
        f"{GATEWAY_API_VERSION}/standard-install.yaml", timeout=120)
    lab.command("helm", "upgrade", "--install", "traefik", "traefik",
                "--repo", "https://traefik.github.io/charts",
                "--version", CHART_VERSION, "--namespace", "traefik",
                "--create-namespace", "--kubeconfig", str(lab.kubeconfig),
                "--kube-context", f"kind-{lab.cluster}",
                "--values", str(Path(__file__).with_name("traefik-values.yaml")),
                "--wait", "--timeout", "5m", timeout=320)
    kubectl(lab, "-n", "traefik", "rollout", "status", "deployment/traefik",
            "--timeout=240s", timeout=250)
    controller = json.loads(kubectl(lab, "-n", "traefik", "get", "deployment/traefik",
                                    "-o", "json").stdout)
    images = [container["image"] for container in
              controller["spec"]["template"]["spec"]["containers"]]
    if TRAEFIK_IMAGE not in images:
        lab.block(f"Traefik workload does not use the reviewed digest: {images}")
    controller_pods = json.loads(kubectl(
        lab, "-n", "traefik", "get", "pods", "-l", "app.kubernetes.io/name=traefik",
        "-o", "json").stdout).get("items", [])
    image_ids = [status.get("imageID", "") for pod in controller_pods
                 for status in pod.get("status", {}).get("containerStatuses", [])]
    if not image_ids or not all("sha256:" in image_id for image_id in image_ids):
        lab.block(f"Traefik runtime image IDs did not expose immutable digests: {image_ids}")
    lab.check("positive", "Supported controller chart/image are pinned and ready", True,
              {"kind": kind_version, "kubernetes": node_version,
               "helm_chart": CHART_VERSION, "controller_image": images,
               "runtime_image_ids": image_ids,
               "gateway_api_crds": GATEWAY_API_VERSION})

    kubectl(lab, "create", "namespace", NAMESPACE)
    app = make_app()
    apply(lab, app)
    apply(lab, {"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": APP, "namespace": NAMESPACE},
                "spec": {"selector": {"app": APP},
                         "ports": [{"name": "http", "port": 8080,
                                    "targetPort": 8080}]}})
    kubectl(lab, "-n", NAMESPACE, "rollout", "status", f"deployment/{APP}",
            "--timeout=120s", timeout=130)
    app_obj = json.loads(kubectl(lab, "-n", NAMESPACE, "get", f"deployment/{APP}",
                                 "-o", "json").stdout)
    app_images = [c["image"] for c in
                  app_obj["spec"]["template"]["spec"]["containers"]]
    if app_images != [PYTHON_IMAGE]:
        lab.block(f"Synthetic app image is not pinned: {app_images}")

    apply(lab, {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass",
                "metadata": {"name": "fixture-traefik"},
                "spec": {"controllerName": "traefik.io/gateway-controller"}})
    apply(lab, make_gateway([{
        "name": "http", "hostname": HOSTNAME, "port": 8000, "protocol": "HTTP",
        "allowedRoutes": {"namespaces": {"from": "Same"}},
    }]))
    apply(lab, route("http"))
    wait_conditions(lab, "gateway", "fixture-gateway", ["Accepted", "Programmed"])
    wait_conditions(lab, "httproute", "fixture-route", ["Accepted", "ResolvedRefs"])

    baseline = wait_for_response(lambda: request(HOSTNAME, port=http_port),
                                 200, lambda body: body == MARKER)
    lab.check("red", "Without a TLS listener the owned route serves the marker over HTTP",
              baseline.get("status") == 200 and baseline.get("body") == MARKER,
              baseline)

    with tempfile.TemporaryDirectory(prefix="saf-0503-007-") as temporary:
        directory = Path(temporary)
        certs = issue_certificates(lab, directory)
        kubectl(lab, "-n", NAMESPACE, "create", "secret", "tls", "fixture-tls",
                "--cert", str(certs["cert"]), "--key", str(certs["key"]))
        kubectl(lab, "-n", "traefik", "create", "secret", "tls", "fixture-default-tls",
                "--cert", str(certs["cert"]), "--key", str(certs["key"]))
        apply(lab, {"apiVersion": "traefik.io/v1alpha1", "kind": "TLSStore",
                    "metadata": {"name": "default", "namespace": "traefik"},
                    "spec": {"defaultCertificate": {
                        "secretName": "fixture-default-tls"}}})
        apply(lab, make_gateway([{
            "name": "https", "hostname": HOSTNAME, "port": 8443,
            "protocol": "HTTPS", "tls": {"mode": "Terminate",
                                            "certificateRefs": [{"kind": "Secret",
                                                                  "name": "fixture-tls"}]},
            "allowedRoutes": {"namespaces": {"from": "Same"}},
        }]))
        apply(lab, route("https"))
        wait_conditions(lab, "gateway", "fixture-gateway", ["Accepted", "Programmed"])
        wait_conditions(lab, "httproute", "fixture-route", ["Accepted", "ResolvedRefs"])

        cleartext_after = wait_for_response(
            lambda: request(HOSTNAME, port=http_port), 404,
            lambda body: body != MARKER)
        lab.check("green", "After TLS configuration the plaintext listener does not serve the route",
                  cleartext_after.get("status") == 404 and cleartext_after.get("body") != MARKER,
                  cleartext_after)

        accepted_protocols = []
        protocol_text = {
            ssl.TLSVersion.TLSv1_2: "TLSv1.2",
            ssl.TLSVersion.TLSv1_3: "TLSv1.3",
        }
        for tls_version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            result = wait_for_response(
                lambda: request(HOSTNAME, port=https_port, ca_file=certs["ca"],
                                tls_version=tls_version),
                200, lambda body: body == MARKER)
            if (result.get("status") == 200 and result.get("body") == MARKER
                    and result.get("protocol") == protocol_text[tls_version]
                    and (tls_version != ssl.TLSVersion.TLSv1_2
                         or result.get("cipher") in TLS12_CIPHERS)):
                accepted_protocols.append(result)
            else:
                lab.check("green", f"TLS protocol {tls_version.name} accepted with trusted identity",
                          False, result)
        lab.check("positive", "Trusted CA, matching hostname, accepted protocol, and marker succeed",
                  len(accepted_protocols) == 2, accepted_protocols)

        try:
            weak_protocol = request(HOSTNAME, port=https_port, ca_file=certs["ca"],
                                    tls_version=ssl.TLSVersion.TLSv1_1)
            weak_protocol_outcome = {"unexpected_success": weak_protocol}
            weak_protocol_rejected = False
        except ssl.SSLError as error:
            reason = getattr(error, "reason", "") or type(error).__name__
            weak_protocol_outcome = {"client_error": type(error).__name__,
                                     "reason": reason}
            weak_protocol_rejected = "PROTOCOL_VERSION" in reason.upper()
        lab.check("green", "TLS 1.1 is rejected by the configured TLS 1.2 minimum",
                  weak_protocol_rejected, weak_protocol_outcome)

        try:
            response = request(HOSTNAME, port=https_port, ca_file=certs["ca"],
                               tls_version=ssl.TLSVersion.TLSv1_2,
                               cipher=UNAPPROVED_TLS12_CIPHER)
            unapproved = {"unexpected_success": response}
        except ssl.SSLError as error:
            unapproved = {"reason": error.reason}
        lab.check("green", "The owned endpoint rejects an unapproved TLS 1.2 cipher",
                  "HANDSHAKE_FAILURE" in (unapproved.get("reason") or ""), unapproved)

        untrusted = None
        try:
            untrusted = request(HOSTNAME, port=https_port, ca_file=certs["wrong_ca"])
            untrusted_outcome = {"status": untrusted.get("status"),
                                 "unexpected_tls_success": True}
            untrusted_rejected = False
        except ssl.SSLCertVerificationError as error:
            untrusted_outcome = {"verification_error": type(error).__name__,
                                 "verify_code": error.verify_code}
            untrusted_rejected = True
        lab.check("green", "A client that does not trust the fixture CA rejects the server",
                  untrusted_rejected and untrusted_outcome.get("verify_code") != 62,
                  untrusted_outcome)

        wrong_host = None
        try:
            wrong_host = request("wrong.saf.test", port=https_port, server_name="wrong.saf.test",
                                 ca_file=certs["ca"])
            wrong_host_outcome = {"status": wrong_host.get("status"),
                                  "unexpected_tls_success": True}
            wrong_host_rejected = False
        except ssl.SSLCertVerificationError as error:
            wrong_host_outcome = {"verification_error": type(error).__name__,
                                  "verify_code": error.verify_code}
            wrong_host_rejected = True
        lab.check("green", "A trusted certificate for a different hostname is rejected",
                  wrong_host_rejected and wrong_host_outcome.get("verify_code") == 62,
                  wrong_host_outcome)

        wrong_http_host = request("wrong.saf.test", port=https_port, ca_file=certs["ca"])
        lab.check("green", "A correct TLS identity with an unmatched HTTP Host does not route",
                  wrong_http_host.get("status") == 404
                  and wrong_http_host.get("body") != MARKER, wrong_http_host)
        wrong_path = request(HOSTNAME, port=https_port, ca_file=certs["ca"], path="/unmatched")
        lab.check("green", "An unmatched path does not reach the application marker",
                  wrong_path.get("status") == 404
                  and wrong_path.get("body") != MARKER, wrong_path)
