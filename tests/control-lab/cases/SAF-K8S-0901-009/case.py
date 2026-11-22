"""Exercise peer authentication for a harmless two-worker training marker."""

import json
import os
from pathlib import Path
import subprocess


HERE = Path(__file__).resolve().parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-0901-009-fixture"
NODE_LABEL = "saf-0901-009.example/worker"
SERVER_ID = "spiffe://saf.example.test/worker/server"
CLIENT_ID = "spiffe://saf.example.test/worker/client-a"
UNTRUSTED_ID = "spiffe://saf.example.test/worker/untrusted"
SERVER_DNS = "saf-peer.saf-0901-009.test"
MARKER = "SAF-K8S-0901-009 synthetic gradient marker 51c8d2"
SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster with one control-plane node and two "
    "worker nodes. A case-owned Python fixture runs on the two distinct worker nodes and "
    "exchanges one exact, harmless synthetic marker. The same server pod exposes a TLS "
    "server-auth-only comparator and an mTLS listener requiring a CA-trusted client "
    "certificate. The client verifies the server CA and DNS identity; the server checks "
    "the authorized client certificate URI identity before accepting the marker. Missing "
    "and separately untrusted client certificates are rejected, as is a trusted certificate for a different identity. Per-run CA and leaf keys "
    "are generated locally, mounted only as disposable Kubernetes Secrets, and excluded "
    "from evidence. No real training data, framework operator, external endpoint, feed, "
    "or target is used. This does not establish PyTorchJob/MPIJob/TFJob integration, "
    "certificate issuance/rotation/revocation, production identity authorization, or "
    "NetworkPolicy enforcement by a production CNI."
)


def _kubectl(lab, *args, timeout=45, allow_failure=False, **kwargs):
    return lab.kubectl(*args, timeout=timeout, allow_failure=allow_failure, **kwargs)


def _openssl(args, *, timeout=30):
    try:
        result = subprocess.run(
            ["openssl", *args], capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("local fixture certificate operation failed") from None
    if result.returncode:
        raise RuntimeError("local fixture certificate operation failed")
    return result.stdout.strip()


def _make_ca(material: Path, name: str) -> tuple[Path, Path]:
    key, cert = material / f"{name}.key", material / f"{name}.crt"
    _openssl([
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", f"/CN={name}.saf.example.test",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
        "-keyout", str(key), "-out", str(cert),
    ])
    key.chmod(0o600)
    cert.chmod(0o600)
    return key, cert


def _make_leaf(material: Path, name: str, ca_key: Path, ca_cert: Path,
               *, identity: str, server: bool = False) -> tuple[Path, Path]:
    key = material / f"{name}.key"
    csr = material / f"{name}.csr"
    cert = material / f"{name}.crt"
    ext = material / f"{name}.ext"
    _openssl([
        "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-subj", f"/CN={name}.saf.example.test", "-keyout", str(key),
        "-out", str(csr),
    ])
    usage = "serverAuth" if server else "clientAuth"
    san = f"DNS:{SERVER_DNS},URI:{identity}" if server else f"URI:{identity}"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
        f"extendedKeyUsage={usage}\nsubjectAltName={san}\n",
        encoding="ascii",
    )
    _openssl([
        "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
        "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
        "-sha256", "-extfile", str(ext), "-out", str(cert),
    ])
    key.chmod(0o600)
    cert.chmod(0o600)
    for path in (csr, ext):
        path.unlink(missing_ok=True)
    return key, cert


def _create_secret_from_files(lab, name: str, files: list[tuple[str, Path]]) -> None:
    args = ["-n", NAMESPACE, "create", "secret", "generic", name]
    args.extend(f"--from-file={key}={path}" for key, path in files)
    args.extend(["-o", "name"])
    _kubectl(lab, *args)


def _wait_pod(lab, name: str) -> dict:
    _kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready",
             f"pod/{name}", "--timeout=150s", timeout=160)
    return json.loads(_kubectl(lab, "-n", NAMESPACE, "get", "pod", name, "-o", "json").stdout)


def _probe(lab, mode: str) -> dict:
    result = _kubectl(
        lab, "-n", NAMESPACE, "exec", "client-worker", "--",
        "python", "/fixture/worker.py", "probe", mode, timeout=25,
    )
    try:
        observed = json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("The synthetic TLS client returned no structured result")
    return observed


def _server_events(lab) -> list[dict]:
    raw = _kubectl(lab, "-n", NAMESPACE, "logs", "server-worker", timeout=25).stdout
    records = []
    for line in raw.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("event") in {"accepted", "rejected", "tls_rejected"}:
            records.append(record)
    safe_raw = "\n".join(json.dumps(item, sort_keys=True) for item in records) + "\n"
    (lab.evidence / "peer-events.raw.jsonl").write_text(safe_raw, encoding="utf-8")
    return records


def _worker_pod(name: str, role: str, command: list[str], secret_mounts: list[dict]) -> dict:
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"app": "saf-0901-009", "role": role}},
        "spec": {
            "nodeSelector": {NODE_LABEL: role},
            "automountServiceAccountToken": False,
            "restartPolicy": "Always",
            "securityContext": {
                "runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                "fsGroup": 65532,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": role, "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": command,
                "ports": ([{"name": "baseline", "containerPort": 8443},
                           {"name": "mtls", "containerPort": 8444}] if role == "server" else []),
                "readinessProbe": ({"tcpSocket": {"port": 8444}, "periodSeconds": 1,
                                    "failureThreshold": 60} if role == "server" else
                                   {"exec": {"command": ["python", "-c", "print('ready')"]},
                                    "periodSeconds": 2}),
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "96Mi"}},
                "securityContext": {
                    "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [
                    {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                    *secret_mounts,
                ],
            }],
            "volumes": [
                {"name": "fixture", "configMap": {"name": "worker-fixture"}},
                {"name": "server-material", "secret": {"secretName": "server-material",
                                                            "defaultMode": 0o440}},
                {"name": "client-material", "secret": {"secretName": "client-material",
                                                            "defaultMode": 0o440}},
                {"name": "untrusted-material", "secret": {"secretName": "untrusted-material",
                                                               "defaultMode": 0o440}},
                {"name": "unauthorized-material", "secret": {"secretName": "unauthorized-material",
                                                                  "defaultMode": 0o440}},
            ],
        },
    }


def _security_objects() -> list[dict]:
    app = {"app": "saf-0901-009"}
    client = {"podSelector": {"matchLabels": {**app, "role": "client"}}}
    server = {"podSelector": {"matchLabels": {**app, "role": "server"}}}
    ports = [{"protocol": "TCP", "port": 8443}, {"protocol": "TCP", "port": 8444}]
    return [{
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "peer-only-fixture", "namespace": NAMESPACE},
        "spec": {"podSelector": {"matchLabels": app}, "policyTypes": ["Ingress", "Egress"],
                 "ingress": [{"from": [client], "ports": ports}],
                 "egress": [{"to": [server], "ports": ports}]},
    }]


def run(lab):
    material = lab.kubeconfig.parent / "0901-009-private-material"
    material.mkdir(mode=0o700)
    os.chmod(material, 0o700)
    ca_key = untrusted_key = None
    private_paths: list[Path] = []
    try:
        ca_key, ca_cert = _make_ca(material, "authorized-ca")
        untrusted_key, untrusted_ca = _make_ca(material, "untrusted-ca")
        server_key, server_cert = _make_leaf(
            material, "server", ca_key, ca_cert, identity=SERVER_ID, server=True,
        )
        client_key, client_cert = _make_leaf(
            material, "client", ca_key, ca_cert, identity=CLIENT_ID,
        )
        untrusted_client_key, untrusted_client_cert = _make_leaf(
            material, "untrusted-client", untrusted_key, untrusted_ca,
            identity=UNTRUSTED_ID,
        )
        unauthorized_key, unauthorized_cert = _make_leaf(
            material, "unauthorized-client", ca_key, ca_cert,
            identity=UNTRUSTED_ID,
        )
        private_paths = [ca_key, untrusted_key, server_key, client_key,
                         untrusted_client_key, unauthorized_key]

        _kubectl(lab, "create", "namespace", NAMESPACE)
        fixture = HERE / "worker.py"
        _kubectl(lab, "-n", NAMESPACE, "create", "configmap", "worker-fixture",
                 f"--from-file=worker.py={fixture}", "-o", "name")
        _create_secret_from_files(lab, "server-material", [
            ("server.crt", server_cert), ("server.key", server_key), ("ca.crt", ca_cert),
        ])
        _create_secret_from_files(lab, "client-material", [
            ("client.crt", client_cert), ("client.key", client_key), ("ca.crt", ca_cert),
        ])
        _create_secret_from_files(lab, "untrusted-material", [
            ("client.crt", untrusted_client_cert), ("client.key", untrusted_client_key),
            ("ca.crt", ca_cert),
        ])
        _create_secret_from_files(lab, "unauthorized-material", [
            ("client.crt", unauthorized_cert), ("client.key", unauthorized_key),
            ("ca.crt", ca_cert),
        ])
        for path in material.iterdir():
            if path.is_file() and path.suffix in {".key", ".srl"}:
                path.unlink(missing_ok=True)

        for obj in _security_objects():
            _kubectl(lab, "-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(obj))
        server_obj = _worker_pod(
            "server-worker", "server", ["python", "-u", "/fixture/worker.py", "serve"], [
                {"name": "server-material", "mountPath": "/certs/server", "readOnly": True},
            ],
        )
        server_obj["spec"]["containers"][0]["env"] = [
            {"name": "MARKER", "value": MARKER},
        ]
        _kubectl(lab, "-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(server_obj))
        server = _wait_pod(lab, "server-worker")
        server_node = server["spec"].get("nodeName", "")
        server_ip = server["status"].get("podIP", "")
        if not server_ip or not server_node:
            lab.block("The synthetic server did not receive a node and pod address")

        client_obj = _worker_pod(
            "client-worker", "client", ["python", "-u", "/fixture/worker.py", "idle"], [
                {"name": "client-material", "mountPath": "/certs/client", "readOnly": True},
                {"name": "untrusted-material", "mountPath": "/certs/untrusted", "readOnly": True},
                {"name": "unauthorized-material", "mountPath": "/certs/unauthorized", "readOnly": True},
            ],
        )
        client_obj["spec"]["containers"][0]["env"] = [
            {"name": "PEER_IP", "value": server_ip},
            {"name": "SERVER_DNS", "value": SERVER_DNS},
            {"name": "MARKER", "value": MARKER},
            {"name": "SERVER_ID", "value": SERVER_ID},
            {"name": "CLIENT_ID", "value": CLIENT_ID},
        ]
        _kubectl(lab, "-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(client_obj))
        client = _wait_pod(lab, "client-worker")
        client_node = client["spec"].get("nodeName", "")
        nodes = json.loads(_kubectl(lab, "get", "nodes", "-o", "json").stdout)
        versions = sorted({item["status"]["nodeInfo"]["kubeletVersion"]
                           for item in nodes.get("items", [])})
        lab.check(
            "positive", "The disposable cluster is Kubernetes v1.36.1 with two Kind workers",
            versions == ["v1.36.1"] and len(nodes.get("items", [])) == 3,
            {"kubelet_versions": versions, "node_count": len(nodes.get("items", []))},
        )
        lab.check(
            "positive", "Fixture workers are ready on two distinct Kind worker nodes",
            server_node != client_node and bool(server_node) and bool(client_node),
            {"distinct_nodes": server_node != client_node},
        )

        (lab.evidence / "peer-placement.raw.json").write_text(json.dumps({
            "server_node": server_node, "client_node": client_node,
            "distinct_nodes": server_node != client_node,
        }, indent=2) + "\n")
        baseline = _probe(lab, "baseline")
        if baseline.get("tls_established") is not True:
            lab.block(f"Server-authenticated comparator did not establish TLS: {baseline}")
        baseline_events = _server_events(lab)
        red_seen = any(item.get("listener") == "server-auth-only"
                       and item.get("client_uri") is None
                       and item.get("marker") == MARKER for item in baseline_events)
        lab.check(
            "red", "Without client authentication, the comparator accepts the exact marker from an unidentified peer",
            baseline.get("accepted") is True and baseline.get("client_identity") is None and red_seen,
            {"client_result": baseline, "server_observed_unidentified_peer": red_seen,
             "marker_exact": baseline.get("marker") == MARKER},
        )

        missing = _probe(lab, "missing")
        untrusted = _probe(lab, "untrusted")
        unauthorized = _probe(lab, "unauthorized")
        events = _server_events(lab)
        unauthorized_rejected_seen = any(
            item.get("event") == "rejected" and item.get("listener") == "mutual-tls"
            and item.get("client_uri") == UNTRUSTED_ID and item.get("marker") is None
            for item in events
        )
        handshake_rejections = {item.get("reason") for item in events
                                if item.get("event") == "tls_rejected"
                                and item.get("listener") == "mutual-tls"}
        rejected_by_tls = {"PEER_DID_NOT_RETURN_A_CERTIFICATE", "CERTIFICATE_VERIFY_FAILED"} <= handshake_rejections
        green = (rejected_by_tls and missing.get("tls_established") is False
                 and untrusted.get("tls_established") is False
                 and unauthorized.get("tls_established") is True
                 and unauthorized.get("accepted") is False
                 and unauthorized_rejected_seen
                 and not any(item.get("listener") == "mutual-tls"
                             and item.get("marker") == MARKER
                             and item.get("client_uri") in {None, UNTRUSTED_ID}
                             for item in events))
        lab.check(
            "green", "mTLS rejects missing and untrusted identities, and policy rejects a trusted but unauthorized worker identity",
            green,
            {"missing_identity": missing, "untrusted_identity": untrusted,
             "trusted_unauthorized_identity": unauthorized,
             "certificate_rejections_confirmed_on_server": rejected_by_tls,
             "trusted_unauthorized_rejected_without_marker": unauthorized_rejected_seen,
             "all_negative_outcomes_matched": green},
        )

        authorized = _probe(lab, "authorized")
        events = _server_events(lab)
        positive_seen = any(
            item.get("listener") == "mutual-tls" and item.get("client_uri") == CLIENT_ID
            and item.get("server_uri") == SERVER_ID and item.get("marker") == MARKER
            for item in events
        )
        positive = (authorized.get("accepted") is True
                    and authorized.get("tls_established") is True
                    and authorized.get("server_hostname_verified") is True
                    and authorized.get("server_certificate_uri_matches") is True
                    and authorized.get("server_identity") == SERVER_ID
                    and authorized.get("client_identity") == CLIENT_ID
                    and authorized.get("marker") == MARKER and positive_seen)
        lab.check(
            "positive", "Mutually authenticated workers exchange only the exact authorized synthetic marker",
            positive,
            {"client_result": authorized, "server_observed_both_identities_and_marker": positive_seen,
             "marker_sha256": __import__("hashlib").sha256(MARKER.encode()).hexdigest()},
        )
    finally:
        for path in private_paths:
            path.unlink(missing_ok=True)
        if ca_key is not None:
            ca_key.unlink(missing_ok=True)
        if untrusted_key is not None:
            untrusted_key.unlink(missing_ok=True)
        # Remove every remaining local certificate, CSR, serial, and extension file.
        for path in material.glob("*"):
            if path.is_file():
                path.unlink(missing_ok=True)
        material.rmdir()
