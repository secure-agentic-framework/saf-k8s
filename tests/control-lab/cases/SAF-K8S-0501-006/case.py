"""Prove one cross-cluster TLS and exact-client-identity boundary."""
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
NODE_PORT = 31443
HOSTNAME = "server.saf.test"
ALLOWED_IDENTITY = "spiffe://saf-k8s.test/workload/client-allowed"
WRONG_IDENTITY = "spiffe://saf-k8s.test/workload/client-wrong"
TIMEOUT = 8
SCOPE = (
    "Two independently named disposable Kubernetes v1.36.1 kind clusters on one "
    "case-owned local Docker bridge, with one synthetic Python client Pod in the "
    "runner-owned cluster and one synthetic Python TLS server Pod in a case-owned "
    "cluster. A NodePort request demonstrates baseline unauthenticated access, then "
    "server-authenticated TLS and mandatory mTLS trust plus exact URI SAN allowlisting. "
    "The client uses standard CA and hostname verification. Receipts contain only fixed "
    "phase labels, TLS outcome/status, and allow/deny identity labels; request and "
    "response bodies, certificate contents, and keys are not retained. This does not "
    "install MCS, a mesh, or production flow collection."
)


SERVER_PROGRAM = r'''import json, os, socket, ssl, threading

HOST = "0.0.0.0"
ALLOWED = "spiffe://saf-k8s.test/workload/client-allowed"

def receipt(**fields):
    print(json.dumps(fields, sort_keys=True, separators=(",", ":")), flush=True)

def serve(conn, require_client):
    try:
        conn.settimeout(5)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 4096:
            part = conn.recv(min(1024, 4096 - len(raw)))
            if not part:
                break
            raw += part
        head = raw.split(b"\r\n\r\n", 1)[0].decode("ascii", "replace")
        lines = head.split("\r\n")
        request_ok = bool(lines and lines[0] == "GET /health HTTP/1.1")
        headers = {}
        for line in lines[1:32]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        phase = headers.get("x-saf-phase", "invalid")
        if phase not in {"baseline-anonymous", "baseline-authorized", "post-absent",
                         "post-wrong-peer", "post-authorized"}:
            phase = "invalid"
        peer = conn.getpeercert() or {}
        identity = "none"
        for kind, value in peer.get("subjectAltName", ()):
            if kind == "URI":
                identity = value if value in {ALLOWED, "spiffe://saf-k8s.test/workload/client-wrong"} else "other"
                break
        allowed = request_ok and (not require_client or identity == ALLOWED)
        status = 200 if allowed else 403
        body = b"ok"
        conn.sendall((f"HTTP/1.1 {status} {'OK' if status == 200 else 'Forbidden'}\r\n"
                      f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("ascii") + body)
        receipt(event="request", phase=phase, identity=identity,
                decision="allow" if allowed else "deny", status=status)
    except (OSError, UnicodeError):
        receipt(event="request_error", phase="invalid")
    finally:
        try:
            conn.close()
        except OSError:
            pass

def accept_loop(port, context, require_client):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, port))
    listener.listen(16)
    while True:
        raw, _ = listener.accept()
        raw.settimeout(5)
        try:
            secure = context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as error:
            raw.close()
            if require_client and getattr(error, "reason", None) == "PEER_DID_NOT_RETURN_A_CERTIFICATE":
                receipt(event="tls_rejected", phase="post-absent")
            continue
        threading.Thread(target=serve, args=(secure, require_client), daemon=True).start()

require_client = os.environ.get("REQUIRE_CLIENT_CERT") == "true"
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain("/tls/server.crt", "/tls/server.key")
context.load_verify_locations(cafile="/trust/ca.crt")
context.verify_mode = ssl.CERT_REQUIRED if require_client else ssl.CERT_OPTIONAL
accept_loop(8443, context, require_client)
'''


CLIENT_PROGRAM = r'''import argparse, json, socket, ssl

parser = argparse.ArgumentParser()
parser.add_argument("--address", required=True)
parser.add_argument("--server-name", default="server.saf.test")
parser.add_argument("--phase", required=True)
parser.add_argument("--port", required=True, type=int)
parser.add_argument("--identity", choices=("allowed", "wrong"))
args = parser.parse_args()
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="/trust/ca.crt")
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
if args.identity:
    prefix = "/clients/" + args.identity
    context.load_cert_chain(prefix + "/tls.crt", prefix + "/tls.key")
result = {"phase": args.phase, "hostname_verification": "required",
          "identity": args.identity or "absent"}
try:
    raw = socket.create_connection((args.address, args.port), timeout=6)
    with context.wrap_socket(raw, server_hostname=args.server_name) as secure:
        secure.sendall(("GET /health HTTP/1.1\r\n"
                        f"Host: {args.server_name}\r\nX-SAF-Phase: {args.phase}\r\n"
                        "Connection: close\r\n\r\n").encode("ascii"))
        first_line = secure.makefile("rb").readline(128).decode("ascii", "replace").rstrip("\r\n")
        parts = first_line.split(" ", 2)
        result.update(outcome="http", status=int(parts[1]) if len(parts) > 1 else 0,
                      tls=secure.version())
except ssl.SSLCertVerificationError as error:
    result.update(outcome="server_certificate_rejected", verify_code=error.verify_code)
except ssl.SSLError as error:
    result.update(outcome="tls_rejected", reason=(error.reason or type(error).__name__)[:64])
except (OSError, ValueError) as error:
    result.update(outcome="transport_error", reason=type(error).__name__)
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''


def kubectl(lab, kubeconfig, cluster, *args, timeout=TIMEOUT, allow_failure=False, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        "--namespace", NAMESPACE, f"--request-timeout={timeout - 1}s", *args,
        timeout=timeout, allow_failure=allow_failure, payload=payload,
    )


def issue_certificates(root):
    ca_key, ca_cert = root / "ca.key", root / "ca.crt"
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", "/CN=SAF-K8S-0501-006-test-CA", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash", "-keyout", str(ca_key),
         "-out", str(ca_cert)],
    ]
    def execute(args):
        try:
            result = subprocess.run(args, capture_output=True, timeout=20, text=True, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError(type(error).__name__) from error
        if result.returncode:
            raise RuntimeError(args[0])
    for command in commands:
        execute(command)
    for name, subject, extension in (
        ("server", "/CN=server.saf.test", "subjectAltName=DNS:server.saf.test\nextendedKeyUsage=serverAuth\n"),
        ("allowed", "/CN=authorized-synthetic-client", f"subjectAltName=URI:{ALLOWED_IDENTITY}\nextendedKeyUsage=clientAuth\n"),
        ("wrong", "/CN=other-synthetic-client", f"subjectAltName=URI:{WRONG_IDENTITY}\nextendedKeyUsage=clientAuth\n"),
    ):
        key, csr, cert, ext = (root / f"{name}.{suffix}" for suffix in ("key", "csr", "crt", "ext"))
        ext.write_text("basicConstraints=critical,CA:FALSE\n"
                       "keyUsage=critical,digitalSignature,keyEncipherment\n"
                       "authorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n" + extension)
        execute(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", subject,
                 "-keyout", str(key), "-out", str(csr)])
        execute(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
                 "-CAkey", str(ca_key), "-CAcreateserial", "-days", "2", "-sha256",
                 "-extfile", str(ext), "-out", str(cert)])


def network_json(lab, node):
    result = lab.command("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", node)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block(f"Could not inspect the owned kind node {node}")


@contextmanager
def shared_network(lab, peer_cluster):
    """Attach only the two case node containers to a temporary Docker bridge."""
    name = f"saf-xcluster-{uuid.uuid4().hex[:12]}"
    primary_node = f"{lab.cluster}-control-plane"
    peer_node = f"{peer_cluster}-control-plane"
    attached = []
    created_network = False
    try:
        lab.command("docker", "network", "create", "--driver", "bridge", "--internal", name)
        created_network = True
        for node in (primary_node, peer_node):
            lab.command("docker", "network", "connect", name, node)
            attached.append(node)
        details = network_json(lab, peer_node)
        network = details.get(name, {})
        address = network.get("IPAddress", "")
        if not address:
            lab.block("The second owned kind node has no address on the case bridge")
        yield name, address
    finally:
        errors = []
        for node in reversed(attached):
            result = lab.command("docker", "network", "disconnect", name, node,
                                allow_failure=True)
            if result.returncode:
                errors.append(node)
        if created_network:
            result = lab.command("docker", "network", "rm", name, allow_failure=True)
            if result.returncode:
                errors.append(name)
        if errors:
            lab.block("Could not remove case-owned Docker network resources")


@contextmanager
def peer_cluster(lab, root):
    cluster = f"{lab.cluster}-peer"
    kubeconfig = root / "peer-kubeconfig"
    config = root / "peer-kind.yaml"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Refusing to reuse the independently named peer cluster")
    config.write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n")
    created = False
    try:
        created = True
        lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                    "--config", str(config), "--kubeconfig", str(kubeconfig),
                    "--wait", "90s", timeout=480)
        yield cluster, kubeconfig
    finally:
        if created:
            result = lab.command("kind", "delete", "cluster", "--name", cluster,
                                 "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True)
            if result.returncode or cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
                lab.block("Could not confirm deletion of the case-owned peer cluster")


def apply(lab, kubeconfig, cluster, manifest):
    kubectl(lab, kubeconfig, cluster, "apply", "-f", "-", payload=json.dumps(manifest))


def wait_pod(lab, kubeconfig, cluster, name):
    kubectl(lab, kubeconfig, cluster, "wait", "--for=condition=Ready", f"pod/{name}",
            "--timeout=90s", timeout=100)


def create_cert_secrets(lab, kubeconfig, cluster, root, *, server):
    if server:
        kubectl(lab, kubeconfig, cluster, "create", "secret", "generic", "tls-server",
                f"--from-file=server.crt={root / 'server.crt'}",
                f"--from-file=server.key={root / 'server.key'}")
        kubectl(lab, kubeconfig, cluster, "create", "configmap", "client-ca",
                f"--from-file=ca.crt={root / 'ca.crt'}")
    else:
        for name in ("allowed", "wrong"):
            kubectl(lab, kubeconfig, cluster, "create", "secret", "generic", f"client-{name}",
                    f"--from-file=tls.crt={root / f'{name}.crt'}",
                    f"--from-file=tls.key={root / f'{name}.key'}")
        kubectl(lab, kubeconfig, cluster, "create", "configmap", "server-ca",
                f"--from-file=ca.crt={root / 'ca.crt'}")


def workload_manifests():
    server = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "tls-server-program", "namespace": NAMESPACE},
        "data": {"server.py": SERVER_PROGRAM},
    }
    server_pod = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "synthetic-tls-server", "namespace": NAMESPACE},
        "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                 "selector": {"matchLabels": {"app": "synthetic-tls-server"}},
                 "template": {"metadata": {"labels": {"app": "synthetic-tls-server",
                                                      "saf-peer-policy": "optional"}},
                              "spec": {"automountServiceAccountToken": False,
                                       "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                                           "seccompProfile": {"type": "RuntimeDefault"}},
                                       "containers": [{"name": "server", "image": PYTHON_IMAGE,
                                                       "command": ["python", "/app/server.py"],
                                                       "ports": [{"containerPort": 8443}],
                                                       "readinessProbe": {"tcpSocket": {"port": 8443}},
                                                       "volumeMounts": [
                                                           {"name": "program", "mountPath": "/app", "readOnly": True},
                                                           {"name": "server-cert", "mountPath": "/tls", "readOnly": True},
                                                           {"name": "client-ca", "mountPath": "/trust", "readOnly": True}],
                                                       "securityContext": {"allowPrivilegeEscalation": False,
                                                                           "readOnlyRootFilesystem": True,
                                                                           "capabilities": {"drop": ["ALL"]}}}],
                                       "volumes": [{"name": "program", "configMap": {"name": "tls-server-program"}},
                                                   {"name": "server-cert", "secret": {"secretName": "tls-server"}},
                                                   {"name": "client-ca", "configMap": {"name": "client-ca"}}]}}},
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "synthetic-tls-server", "namespace": NAMESPACE},
        "spec": {"type": "NodePort", "selector": {"app": "synthetic-tls-server"},
                 "ports": [{"name": "tls", "port": 8443, "targetPort": 8443, "nodePort": NODE_PORT}]},
    }
    client = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "tls-client-program", "namespace": NAMESPACE},
        "data": {"client.py": CLIENT_PROGRAM},
    }
    client_pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "synthetic-tls-client", "namespace": NAMESPACE,
                     "labels": {"app": "synthetic-tls-client"}},
        "spec": {"automountServiceAccountToken": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "client", "image": PYTHON_IMAGE,
                                 "command": ["python", "-c", "import time; time.sleep(3600)"],
                                 "volumeMounts": [
                                     {"name": "program", "mountPath": "/app", "readOnly": True},
                                     {"name": "server-ca", "mountPath": "/trust", "readOnly": True},
                                     {"name": "allowed", "mountPath": "/clients/allowed", "readOnly": True},
                                     {"name": "wrong", "mountPath": "/clients/wrong", "readOnly": True}],
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                     "readOnlyRootFilesystem": True,
                                                     "capabilities": {"drop": ["ALL"]}}}],
                 "volumes": [{"name": "program", "configMap": {"name": "tls-client-program"}},
                             {"name": "server-ca", "configMap": {"name": "server-ca"}},
                             {"name": "allowed", "secret": {"secretName": "client-allowed"}},
                             {"name": "wrong", "secret": {"secretName": "client-wrong"}}]},
    }
    return server, server_pod, service, client, client_pod


def run_probe(lab, kubeconfig, cluster, address, phase, port, identity=None,
              server_name=HOSTNAME):
    args = ["exec", "pod/synthetic-tls-client", "--", "python", "/app/client.py",
            "--address", address, "--server-name", server_name, "--phase", phase,
            "--port", str(port)]
    if identity:
        args.extend(("--identity", identity))
    deadline = time.monotonic() + 30
    while True:
        result = kubectl(lab, kubeconfig, cluster, *args, timeout=20)
        try:
            receipt = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            lab.block("The synthetic client returned no bounded JSON flow receipt")
        if not isinstance(receipt, dict) or len(receipt) > 7:
            lab.block("The synthetic client receipt exceeded its fixed field bound")
        if receipt.get("outcome") != "transport_error" or time.monotonic() >= deadline:
            return receipt
        time.sleep(0.5)


def wait_server(lab, kubeconfig, cluster):
    kubectl(lab, kubeconfig, cluster, "rollout", "status",
            "deployment/synthetic-tls-server", "--timeout=90s", timeout=100)


def server_receipts(lab, kubeconfig, cluster, mode):
    result = kubectl(lab, kubeconfig, cluster, "logs", "-l",
                     f"app=synthetic-tls-server,saf-peer-policy={mode}",
                     "--tail=20", timeout=20)
    rows = []
    for line in result.stdout.splitlines()[-20:]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and len(item) <= 5:
            rows.append(item)
    return rows


def run(lab):
    with tempfile.TemporaryDirectory(prefix="saf-0501-006-") as temporary:
        root = Path(temporary)
        try:
            issue_certificates(root)
        except RuntimeError as error:
            lab.block(f"Could not create case-only certificates ({error})")

        peer = f"{lab.cluster}-peer"
        with peer_cluster(lab, root) as (peer, peer_kubeconfig):
            with shared_network(lab, peer) as (_, server_address):
                kubectl(lab, peer_kubeconfig, peer, "create", "namespace", NAMESPACE)
                create_cert_secrets(lab, peer_kubeconfig, peer, root, server=True)
                create_cert_secrets(lab, lab.kubeconfig, lab.cluster, root, server=False)
                server_cm, server_deployment, service, client_cm, client_pod = workload_manifests()
                apply(lab, peer_kubeconfig, peer, server_cm)
                apply(lab, peer_kubeconfig, peer, server_deployment)
                apply(lab, peer_kubeconfig, peer, service)
                apply(lab, lab.kubeconfig, lab.cluster, client_cm)
                apply(lab, lab.kubeconfig, lab.cluster, client_pod)
                wait_server(lab, peer_kubeconfig, peer)
                wait_pod(lab, lab.kubeconfig, lab.cluster, "synthetic-tls-client")

                anonymous = run_probe(lab, lab.kubeconfig, lab.cluster, server_address,
                                      "baseline-anonymous", NODE_PORT)
                lab.check("red", "Before peer authentication, a normal request without a client certificate reaches the synthetic service",
                          anonymous.get("outcome") == "http" and anonymous.get("status") == 200,
                          anonymous)
                baseline_allowed = run_probe(lab, lab.kubeconfig, lab.cluster, server_address,
                                             "baseline-authorized", NODE_PORT, "allowed")
                lab.check("positive", "The exact authorized synthetic client works over standard verified server TLS at baseline",
                          baseline_allowed.get("outcome") == "http"
                          and baseline_allowed.get("status") == 200
                          and baseline_allowed.get("tls") in {"TLSv1.2", "TLSv1.3"},
                          baseline_allowed)
                wrong_name = run_probe(lab, lab.kubeconfig, lab.cluster, server_address,
                                       "baseline-authorized", NODE_PORT, "allowed", "wrong.saf.test")
                lab.check("green", "The same trusted server certificate is rejected for a wrong DNS hostname",
                          wrong_name.get("outcome") == "server_certificate_rejected" and wrong_name.get("verify_code") == 62,
                          wrong_name)

                baseline_rows = server_receipts(lab, peer_kubeconfig, peer, "optional")
                patch = {"spec": {"template": {
                    "metadata": {"labels": {"saf-peer-policy": "required"}},
                    "spec": {"containers": [{"name": "server", "env": [
                        {"name": "REQUIRE_CLIENT_CERT", "value": "true"},
                    ]}]},
                }}}
                kubectl(lab, peer_kubeconfig, peer, "patch", "deployment", "synthetic-tls-server",
                        "--type=strategic", "-p", json.dumps(patch), timeout=25)
                wait_server(lab, peer_kubeconfig, peer)
                old = kubectl(lab, peer_kubeconfig, peer, "get", "pods", "-l",
                              "app=synthetic-tls-server,saf-peer-policy=optional", "-o", "name")
                if old.stdout.strip():
                    lab.block("The baseline Pod remained after switching to mandatory mTLS")

                absent = run_probe(lab, lab.kubeconfig, lab.cluster, server_address,
                                   "post-absent", NODE_PORT)
                lab.check("green", "After policy, a client with no certificate fails mandatory mTLS before an HTTP request",
                          absent.get("outcome") == "tls_rejected", absent)
                wrong_peer = run_probe(lab, lab.kubeconfig, lab.cluster, server_address,
                                       "post-wrong-peer", NODE_PORT, "wrong")
                lab.check("green", "A CA-authenticated but unallowlisted client receives an application 403",
                          wrong_peer.get("outcome") == "http" and wrong_peer.get("status") == 403,
                          wrong_peer)
                allowed = run_probe(lab, lab.kubeconfig, lab.cluster, server_address,
                                    "post-authorized", NODE_PORT, "allowed")
                lab.check("positive", "The same exact authorized client remains usable after mTLS and identity policy",
                          allowed.get("outcome") == "http" and allowed.get("status") == 200,
                          allowed)

                expected = {
                    ("baseline-anonymous", "none", "allow", 200),
                    ("baseline-authorized", ALLOWED_IDENTITY, "allow", 200),
                    ("post-wrong-peer", WRONG_IDENTITY, "deny", 403),
                    ("post-authorized", ALLOWED_IDENTITY, "allow", 200),
                }
                receipts = []
                observed = set()
                rejected = 0
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    receipts = baseline_rows + server_receipts(lab, peer_kubeconfig, peer, "required")
                    observed = {(r.get("phase"), r.get("identity"), r.get("decision"), r.get("status"))
                                for r in receipts if r.get("event") == "request"}
                    rejected = sum(r.get("event") == "tls_rejected"
                                   and r.get("phase") == "post-absent" for r in receipts)
                    if expected.issubset(observed) and rejected >= 1:
                        break
                    time.sleep(0.1)
                summary = {"request_receipts": len(observed & expected), "expected_requests": len(expected),
                           "tls_rejections": rejected, "receipt_fields": "phase,identity,decision,status,event"}
                lab.check("green", "Server-side bounded receipts distinguish absent certificate, authenticated wrong peer, and allowed peer",
                          expected.issubset(observed) and rejected >= 1, summary)
