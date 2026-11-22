"""Compare plaintext and authenticated TLS for a synthetic worker marker."""
import json
from pathlib import Path
import subprocess
import tempfile
import time

from lab import NAMESPACE


HERE = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
WORKER_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
APP = "saf-0901-010"
SERVER = "gradient-sink"
CLIENT = "gradient-source"
MARKER = "SAF-SYNTH-GRADIENT-MARKER-0901-010"
SCOPE = (
    "Two case-owned Python mock workers on distinct nodes in one disposable Kubernetes v1.36.1 Kind cluster. "
    "The sender transmits one fixed synthetic marker over plaintext and then authenticated TLS 1.3 "
    "to the receiver. A bounded local relay in the sender observes only the sender's own plaintext and TLS TCP "
    "stream; no host or other workload traffic is collected. Evidence records exact receiver "
    "readback, negotiated TLS version, verified server name, and the sender-owned outbound TLS "
    "bytes. This demonstrates transport encryption for this Python fixture only. It does not "
    "exercise NCCL, MPI, TensorFlow gRPC, any training engine/provider/GPU, real gradients, "
    "mTLS client identity, certificate rotation, a production CNI/fabric, or cluster-wide "
    "enforcement."
)


def run_command(lab, *args, timeout=20):
    try:
        return lab.command(*args, timeout=timeout)
    except Exception as error:
        lab.block(f"Case-owned TLS fixture setup failed ({type(error).__name__})")


def create_certificates(lab, directory):
    ca_key = directory / "ca.key"
    ca_cert = directory / "ca.crt"
    server_key = directory / "server.key"
    server_csr = directory / "server.csr"
    server_cert = directory / "server.crt"
    ext = directory / "server.ext"
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", "/CN=SAF-K8S-0901-010 synthetic CA",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash",
         "-keyout", str(ca_key), "-out", str(ca_cert)],
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj",
         "/CN=gradient-sink.saf-test.svc", "-keyout", str(server_key),
         "-out", str(server_csr)],
    ]
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:gradient-sink.saf-test.svc.cluster.local\n",
        encoding="ascii",
    )
    commands.append([
        "openssl", "x509", "-req", "-in", str(server_csr), "-CA", str(ca_cert),
        "-CAkey", str(ca_key), "-CAcreateserial", "-days", "2", "-sha256",
        "-extfile", str(ext), "-out", str(server_cert),
    ])
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            lab.block(f"Could not create local synthetic TLS fixture ({type(error).__name__})")
        if result.returncode:
            # Suppress OpenSSL diagnostics to keep private key material out of retained evidence.
            lab.block("Could not create local synthetic TLS fixture certificate")
    return ca_cert, server_cert, server_key


def kubectl(lab, *args, timeout=30, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", NAMESPACE, f"--request-timeout={timeout - 5}s", *args,
        timeout=timeout, allow_failure=allow_failure,
    )


def run(lab):
    (lab.evidence / "case-scope.json").write_text(json.dumps({
        "control": "SAF-K8S-0901-010", "scope": SCOPE,
        "node_image": NODE_IMAGE, "worker_image": WORKER_IMAGE,
        "marker": MARKER, "real_feed_or_target_access": False,
        "training_engine_provider_or_gpu_claimed": False,
        "mtls_identity_control_tested": False,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="saf-0901-010-") as temp:
        ca_cert, server_cert, server_key = create_certificates(lab, Path(temp))

        run_command(lab, "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                    f"kind-{lab.cluster}", "-n", NAMESPACE, "create", "configmap",
                    f"{APP}-programs", f"--from-file=receiver.py={HERE / 'fixtures' / 'receiver.py'}",
                    f"--from-file=sender.py={HERE / 'fixtures' / 'sender.py'}", "-o", "name")
        run_command(lab, "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                    f"kind-{lab.cluster}", "-n", NAMESPACE, "create", "secret", "generic",
                    f"{APP}-server-tls", f"--from-file=ca.crt={ca_cert}",
                    f"--from-file=tls.crt={server_cert}", f"--from-file=tls.key={server_key}",
                    "-o", "name")

    labels = {"saf-k8s.example/control-0901-010": "synthetic-worker"}
    common_security = {
        "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
    }
    pod_security = {"runAsNonRoot": True, "runAsUser": 65532,
                    "seccompProfile": {"type": "RuntimeDefault"}}
    receiver = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": SERVER, "namespace": NAMESPACE, "labels": {**labels, "role": "receiver"}},
        "spec": {
            "restartPolicy": "Always", "automountServiceAccountToken": False,
            "securityContext": pod_security,
            "nodeSelector": {"saf-k8s.example/transport-worker": "receiver"},
            "tolerations": [{"key": "node-role.kubernetes.io/control-plane",
                             "operator": "Exists", "effect": "NoSchedule"}],
            "containers": [{"name": "receiver", "image": WORKER_IMAGE,
                "imagePullPolicy": "IfNotPresent", "command": ["python", "/case/receiver.py"],
                "ports": [{"containerPort": 9011}, {"containerPort": 9012}],
                "readinessProbe": {"tcpSocket": {"port": 9012}},
                "securityContext": common_security,
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "250m", "memory": "96Mi"}},
                "volumeMounts": [{"name": "programs", "mountPath": "/case", "readOnly": True},
                                 {"name": "server-tls", "mountPath": "/tls", "readOnly": True}]}],
            "volumes": [{"name": "programs", "configMap": {"name": f"{APP}-programs"}},
                        {"name": "server-tls", "secret": {"secretName": f"{APP}-server-tls"}}],
        },
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVER, "namespace": NAMESPACE, "labels": labels},
        "spec": {"selector": {**labels, "role": "receiver"}, "ports": [
            {"name": "plain-fixture", "port": 9011, "targetPort": 9011},
            {"name": "tls-fixture", "port": 9012, "targetPort": 9012}]},
    }
    sender = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": CLIENT, "namespace": NAMESPACE, "labels": labels},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
            "template": {"metadata": {"labels": {**labels, "role": "sender"}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": pod_security,
                    "nodeSelector": {"saf-k8s.example/transport-worker": "sender"},
                    "containers": [{"name": "sender", "image": WORKER_IMAGE,
                        "imagePullPolicy": "IfNotPresent", "command": ["python", "/case/sender.py"],
                        "env": [{"name": "SERVER_HOST", "value": f"{SERVER}.{NAMESPACE}.svc.cluster.local"},
                                {"name": "SERVER_NAME", "value": f"{SERVER}.{NAMESPACE}.svc.cluster.local"},
                                {"name": "MARKER", "value": MARKER}],
                        "securityContext": common_security,
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "250m", "memory": "96Mi"}},
                        "volumeMounts": [{"name": "programs", "mountPath": "/case", "readOnly": True},
                                         {"name": "trust", "mountPath": "/trust", "readOnly": True}]}],
                    "volumes": [{"name": "programs", "configMap": {"name": f"{APP}-programs"}},
                                {"name": "trust", "secret": {"secretName": f"{APP}-server-tls",
                                                                  "items": [{"key": "ca.crt", "path": "ca.crt"}]}}]}}},
    }
    for obj in (receiver, service):
        lab.create(obj)
    kubectl(lab, "wait", f"pod/{SERVER}", "--for=condition=Ready", "--timeout=90s", timeout=100)
    lab.create(sender)
    deadline = time.monotonic() + 105
    while time.monotonic() < deadline:
        status = json.loads(kubectl(lab, "get", f"job/{CLIENT}", "-o", "json").stdout)["status"]
        conditions = {item["type"]: item for item in status.get("conditions", [])
                      if item["status"] == "True"}
        if "Complete" in conditions:
            break
        failure = conditions.get("FailureTarget") or conditions.get("Failed")
        if failure:
            kubectl(lab, "logs", f"job/{CLIENT}", allow_failure=True)
            kubectl(lab, "logs", f"pod/{SERVER}", allow_failure=True)
            lab.block(f"Synthetic sender Job failed: {failure.get('reason', 'unknown reason')}")
        time.sleep(1)
    else:
        kubectl(lab, "logs", f"job/{CLIENT}", allow_failure=True)
        lab.block("Synthetic sender Job did not complete within 105 seconds")
    raw = kubectl(lab, "logs", f"job/{CLIENT}").stdout.strip()
    (lab.evidence / "sender.raw.json").write_text(raw + "\n", encoding="utf-8")
    try:
        observed = json.loads(raw)
    except json.JSONDecodeError:
        lab.block("The synthetic sender returned no JSON transport evidence")

    receiver_raw = kubectl(lab, "logs", f"pod/{SERVER}").stdout.strip().splitlines()
    (lab.evidence / "receiver.raw.jsonl").write_text("\n".join(receiver_raw) + "\n", encoding="utf-8")
    receiver_events = [json.loads(line) for line in receiver_raw if line.startswith("{")]
    by_mode = {event.get("mode"): event for event in receiver_events}
    plain = observed.get("plaintext", {})
    tls = observed.get("tls", {})
    red_ok = (plain.get("readback") == MARKER and plain.get("request_hex") ==
              (MARKER + "\n").encode().hex() and by_mode.get("plaintext", {}).get("readback") == MARKER
              and plain.get("relay_completed") is True and plain.get("relay_errors") == [])
    lab.check("red", "The plaintext counterfactual exposes the exact synthetic marker on its owned stream",
              red_ok, {"marker": plain.get("readback"), "owned_stream_hex": plain.get("request_hex"),
                       "receiver_readback": by_mode.get("plaintext", {}).get("readback")})

    tls_records = bytes.fromhex(tls.get("client_to_server_hex", "")) if tls.get("client_to_server_hex") else b""
    tls_server = by_mode.get("tls", {})
    green_ok = (tls.get("readback") == MARKER and tls.get("tls_version") == "TLSv1.3"
                and tls.get("relay_completed") is True and tls.get("relay_errors") == []
                and tls.get("owned_client_to_server_byte_count", 0) > 0
                and MARKER.encode() not in tls_records
                and tls_server.get("readback") == MARKER
                and tls_server.get("tls_version") == "TLSv1.3")
    lab.check("green", "The TLS 1.3 worker exchange reads back the marker while owned outbound bytes conceal it",
              green_ok, {"readback": tls.get("readback"), "tls_version": tls.get("tls_version"),
                         "owned_outbound_bytes_observed": bool(tls_records),
                         "marker_present_in_owned_bytes": MARKER.encode() in tls_records,
                         "receiver": tls_server})

    receiver_node = json.loads(kubectl(lab, "get", "pod", SERVER, "-o", "json").stdout)["spec"]["nodeName"]
    sender_pods = json.loads(kubectl(lab, "get", "pods", "-l", f"job-name={CLIENT}", "-o", "json").stdout)["items"]
    sender_nodes = {item["spec"].get("nodeName") for item in sender_pods}
    distinct_nodes = len(sender_nodes) == 1 and None not in sender_nodes and receiver_node not in sender_nodes
    (lab.evidence / "worker-placement.raw.json").write_text(json.dumps({
        "receiver_node": receiver_node, "sender_nodes": sorted(node for node in sender_nodes if node),
        "distinct_nodes": distinct_nodes,
    }, indent=2) + "\n")
    positive_ok = (distinct_nodes and tls.get("ca_validation") is True and tls.get("server_hostname_verified") is True
                   and f"{SERVER}.{NAMESPACE}.svc.cluster.local" in tls.get("peer_dns_names", [])
                   and tls_server.get("client_certificate_present") is False
                   and plain.get("readback") == MARKER and tls.get("readback") == MARKER)
    lab.check("positive", "The TLS server CA and DNS identity verify; client-certificate identity is a separate untested control",
              positive_ok, {"workers_on_distinct_nodes": distinct_nodes,
                            "sender_peer_authentication": "server certificate and DNS SAN verified",
                            "receiver_observed_client_certificate": tls_server.get("client_certificate_present"),
                            "mtls_identity_control_tested": False,
                            "plaintext_and_tls_readbacks_match": plain.get("readback") == tls.get("readback") == MARKER})
