"""Observe per-Pod tmpfs, container memory cgroups, and mock mTLS."""
import json
from pathlib import Path
import tempfile
import time


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
CONTROL_ID = "SAF-K8S-0902-004"
NAMESPACE = "saf-0902-004"
PORT = 8443
SERVER_NAME = "model-b"
SERVICE_DNS = "model-b.saf-0902-004.svc.cluster.local"
MARKERS = {
    "model-a": "SYNTH-SAF-0902-004-MODEL-A-4b7d",
    "model-b": "SYNTH-SAF-0902-004-MODEL-B-a291",
}
SCRATCH_NAME = "model-cache.marker"
SCRATCH_BYTES = 8 * 1024 * 1024
WORKLOAD = FIXTURES / "workload.py"
SCOPE = (
    "GPU-free disposable Kind fixture with two independent mock Pods: two per-Pod own-cgroup memory checks, "
    "distinct bounded tmpfs markers, bounded writer-versus-peer memory charge, synthetic missing-client-cert "
    "rejection, and one authenticated server/client TLS health request. It demonstrates Pod-scoped tmpfs and "
    "CPU/memory cgroup behavior plus one TLS path; it does not run ModelMesh, Triton, KServe, a model, GPU, "
    "MIG/vGPU, shared-process tenancy, or deployed service mesh. Actual runtime, accelerator-isolation, "
    "resource-attribution, and all-path mTLS claims require adopter verification on supported versions."
)


def kubectl(lab, *args, timeout=45, allow_failure=False, **kwargs):
    return lab.kubectl("-n", NAMESPACE, *args, timeout=timeout, allow_failure=allow_failure, **kwargs)


def apply(lab, resource):
    return json.loads(kubectl(lab, "create", "-f", "-", "-o", "json",
                               payload=json.dumps(resource)).stdout)


def certs(lab, root):
    """Generate short-lived synthetic test credentials outside captured evidence."""
    root.mkdir(mode=0o700, exist_ok=True)
    ca_key, ca_cert = root / "ca.key", root / "ca.crt"
    server_key, server_csr, server_cert = root / "server.key", root / "server.csr", root / "server.crt"
    client_key, client_csr, client_cert = root / "client.key", root / "client.csr", root / "client.crt"
    server_ext = root / "server.ext"
    client_ext = root / "client.ext"
    leaf = ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
    server_ext.write_text(leaf + f"subjectAltName=DNS:{SERVICE_DNS}\nextendedKeyUsage=serverAuth\n")
    client_ext.write_text(leaf + "extendedKeyUsage=clientAuth\n")
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=SAF-K8S-0902-004-synthetic-CA", "-sha256",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
                "-keyout", str(ca_key), "-out", str(ca_cert), timeout=20)
    for name, key, csr, certificate, extension in (
        ("model-b", server_key, server_csr, server_cert, server_ext),
        ("model-a", client_key, client_csr, client_cert, client_ext),
    ):
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(csr), timeout=20)
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
                    "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-sha256",
                    "-extfile", str(extension), "-out", str(certificate), timeout=20)
    # Secret data is transferred only by file reference. lab.command logs arguments and
    # output, never the file contents; this temporary directory is removed on exit.
    kubectl(lab, "create", "secret", "generic", "tls-server",
            f"--from-file=ca.crt={ca_cert}", f"--from-file=tls.crt={server_cert}",
            f"--from-file=tls.key={server_key}")
    kubectl(lab, "create", "secret", "generic", "tls-client",
            f"--from-file=ca.crt={ca_cert}", f"--from-file=tls.crt={client_cert}",
            f"--from-file=tls.key={client_key}")


def pod_spec(role):
    name = role
    memory_request, memory_limit = {
        "model-a": ("64Mi", "128Mi"),
        "model-b": ("96Mi", "160Mi"),
    }[role]
    mounts = [
        {"name": "workload", "mountPath": "/case", "readOnly": True},
        {"name": "scratch", "mountPath": "/dev/shm"},
    ]
    volumes = [
        {"name": "workload", "configMap": {"name": "workload"}},
        {"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}},
    ]
    if role == "model-a":
        mounts.append({"name": "client-identity", "mountPath": "/tls", "readOnly": True})
        volumes.append({"name": "client-identity", "secret": {"secretName": "tls-client",
                                                                    "defaultMode": 288}})
    else:
        mounts.append({"name": "server-identity", "mountPath": "/tls", "readOnly": True})
        volumes.append({"name": "server-identity", "secret": {"secretName": "tls-server",
                                                                    "defaultMode": 288}})
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control": CONTROL_ID,
                                "saf-k8s.example/model": role}},
        "spec": {
            "restartPolicy": "Always", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "runAsGroup": 65532, "fsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "mock-model", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "/case/workload.py", "serve", role],
                "env": [{"name": "SYNTHETIC_MARKER", "value": MARKERS[role]}],
                "ports": ([{"name": "https", "containerPort": PORT, "protocol": "TCP"}]
                          if role == "model-b" else []),
                "readinessProbe": {"periodSeconds": 2, "timeoutSeconds": 4, "failureThreshold": 4,
                                   **({"tcpSocket": {"port": PORT}} if role == SERVER_NAME else
                                      {"exec": {"command": ["python", "/case/workload.py", "ready", role]}})},
                "resources": {"requests": {"cpu": "10m", "memory": memory_request},
                              "limits": {"cpu": "250m", "memory": memory_limit}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": mounts,
            }], "volumes": volumes,
        },
    }


def wait_pod(lab, name):
    kubectl(lab, "wait", f"pod/{name}", "--for=condition=Ready", "--timeout=90s", timeout=100)
    return json.loads(kubectl(lab, "get", "pod", name, "-o", "json").stdout)


def exec_json(lab, pod, *args, allow_failure=False):
    result = kubectl(lab, "exec", f"pod/{pod}", "--", "python", "/case/workload.py", *args,
                     timeout=20, allow_failure=allow_failure)
    lines = result.stdout.strip().splitlines()
    if not lines:
        lab.block(f"Case-owned {pod} fixture returned no bounded JSON observation")
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError:
        lab.block(f"Case-owned {pod} fixture returned malformed observation JSON")


def run(lab):
    server_version = json.loads(kubectl(lab, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if server_version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, observed {server_version!r}")
    image_lock = {"node": NODE_IMAGE, "workload": IMAGE}
    lab.kubectl("create", "namespace", NAMESPACE)
    kubectl(lab, "create", "configmap", "workload",
            f"--from-file=workload.py={WORKLOAD}")
    (lab.evidence / "image-lock.raw.json").write_text(json.dumps(image_lock, indent=2) + "\n")

    with tempfile.TemporaryDirectory(prefix="saf-0902-004-tls-") as temp:
        certs(lab, Path(temp))
        for role in ("model-a", "model-b"):
            apply(lab, pod_spec(role))
        service = {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": SERVER_NAME, "namespace": NAMESPACE,
                         "labels": {"saf-k8s.example/control": CONTROL_ID}},
            "spec": {"type": "ClusterIP", "selector": {"saf-k8s.example/model": "model-b"},
                     "ports": [{"name": "https", "port": PORT, "targetPort": PORT,
                                "protocol": "TCP"}]},
        }
        apply(lab, service)
        pods = {name: wait_pod(lab, name) for name in MARKERS}
        if len({p["metadata"]["uid"] for p in pods.values()}) != 2:
            lab.block("The two mock model workloads must have distinct Kubernetes Pod UIDs")

        memory = {}
        scratch = {}
        for role in MARKERS:
            result = exec_json(lab, role, "observe", SCRATCH_NAME)
            pod = pods[role]
            container_spec = pod["spec"]["containers"][0]
            volume = next(v["emptyDir"] for v in pod["spec"]["volumes"] if v["name"] == "scratch")
            expected_request = {"model-a": "64Mi", "model-b": "96Mi"}[role]
            expected_limit = {"model-a": "128Mi", "model-b": "160Mi"}[role]
            resource_ok = (container_spec["resources"]["requests"]["memory"] == expected_request
                           and container_spec["resources"]["limits"]["memory"] == expected_limit)
            memory[role] = {"pod_uid": pod["metadata"]["uid"], "request": expected_request,
                            "limit": expected_limit, "observed_cgroup": result["cgroup"],
                            "api_resources": container_spec["resources"]}
            scratch[role] = {"pod_uid": pod["metadata"]["uid"],
                             "api_emptydir": volume, **result["scratch"]}
            lab.check("positive", f"{role} has its declared memory request/limit and live own-cgroup accounting",
                      resource_ok and result["cgroup"].get("supported") is True
                      and result["cgroup"].get("current_bytes", 0) > 0
                      and result["cgroup"].get("limit_bytes") == int(expected_limit[:-2]) * 1024 * 1024,
                      {"declared_memory_request": expected_request, "declared_memory_limit": expected_limit,
                       "own_cgroup_usage_measured": result["cgroup"].get("current_bytes", 0) > 0,
                       "own_cgroup_limit_matches": result["cgroup"].get("limit_bytes") == int(expected_limit[:-2]) * 1024 * 1024})

        same_path_distinct_data = all(
            scratch[role].get("path") == f"/dev/shm/{SCRATCH_NAME}"
            and scratch[role].get("own_marker") == MARKERS[role]
            and scratch[role].get("filesystem") == "tmpfs"
            and scratch[role]["api_emptydir"] == {"medium": "Memory", "sizeLimit": "8Mi"}
            and scratch[role].get("api_emptydir") == {"medium": "Memory", "sizeLimit": "8Mi"}
            and scratch[role].get("capacity_bytes", 0) <= SCRATCH_BYTES
            and scratch[role].get("capacity_bytes", 0) > 0
            for role in MARKERS
        ) and scratch["model-a"]["mount_namespace"] != scratch["model-b"]["mount_namespace"]
        evidence = {"control_id": CONTROL_ID, "fixture_only": True,
                    "kubernetes_version": server_version, "image_refs": image_lock,
                    "scratch": scratch, "memory": memory, "tls": {}}
        (lab.evidence / "isolation-accounting.raw.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        lab.check("green", "Two Linux mount namespaces retain different markers at the same bounded tmpfs path",
                  same_path_distinct_data,
                  {"separate_mount_namespaces": scratch["model-a"]["mount_namespace"] != scratch["model-b"]["mount_namespace"],
                   "distinct_expected_markers_retained": same_path_distinct_data,
                   "tmpfs_bound_bytes": SCRATCH_BYTES})
        phase = exec_json(lab, "model-a", "allocate")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            after_a = exec_json(lab, "model-a", "observe", SCRATCH_NAME)
            after_b = exec_json(lab, "model-b", "observe", SCRATCH_NAME)
            charged_a = after_a["cgroup"].get("shmem_bytes", 0) - memory["model-a"]["observed_cgroup"].get("shmem_bytes", 0)
            charged_b = after_b["cgroup"].get("shmem_bytes", 0) - memory["model-b"]["observed_cgroup"].get("shmem_bytes", 0)
            if charged_a >= 1048576 and abs(charged_b) <= 65536:
                break
            time.sleep(0.45)
        evidence["bounded_allocation"] = {"sample": phase, "charges": {"model-a": charged_a, "model-b": charged_b},
                                          "after_a": after_a, "after_b": after_b}
        lab.check("positive", "A one-MiB tmpfs write changes the writing model's cgroup charge independently",
                  phase.get("allocated_bytes") == 1048576 and charged_a >= 1048576 and abs(charged_b) <= 65536
                  and after_b["scratch"]["own_marker"] == MARKERS["model-b"],
                  {"writing_cgroup_charged": charged_a >= 1048576, "peer_charge_stable": abs(charged_b) <= 65536,
                   "peer_marker_preserved": after_b["scratch"]["own_marker"] == MARKERS["model-b"]})
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            slices = json.loads(kubectl(lab, "get", "endpointslices", "-l",
                                f"kubernetes.io/service-name={SERVER_NAME}", "-o", "json").stdout)
            ready = [address for item in slices["items"] for endpoint in item.get("endpoints", [])
                     if endpoint.get("conditions", {}).get("ready") for address in endpoint["addresses"]]
            if ready == [pods["model-b"]["status"]["podIP"]]:
                break
            time.sleep(0.35)
        else:
            kubectl(lab, "get", "pod", "model-b", "-o", "json")
            kubectl(lab, "logs", "pod/model-b", allow_failure=True)
            kubectl(lab, "logs", "pod/model-b", "--previous", allow_failure=True)
            lab.block("The local model Service did not select the exact reviewed backend")

        no_identity = exec_json(lab, "model-a", "request", f"https://{SERVICE_DNS}:{PORT}/healthz",
                                "no-client-cert", allow_failure=True)
        denied_at_server = [json.loads(line) for line in kubectl(lab, "logs", "pod/model-b").stdout.splitlines()
                            if line.startswith("{")]
        missing_cert = {"event": "client-certificate-required"} in denied_at_server
        denied = no_identity.get("result") == "tls-rejected" and missing_cert
        evidence["tls"]["unauthenticated"] = no_identity
        evidence["tls"]["unauthenticated_server"] = denied_at_server
        lab.check("red", "The mock endpoint rejects the TLS connection without the required client certificate",
                  denied, {"client_connection_rejected": no_identity.get("result") == "tls-rejected",
                           "server_confirmed_no_client_certificate": missing_cert})

        authenticated = exec_json(lab, "model-a", "request",
                                  f"https://{SERVICE_DNS}:{PORT}/healthz", "client-cert")
        server_logs = kubectl(lab, "logs", "pod/model-b", timeout=20).stdout.splitlines()
        server_events = [json.loads(line) for line in server_logs if line.startswith("{")]
        mutual_ok = (authenticated.get("result") == "response"
                     and authenticated.get("status") == 200
                     and authenticated.get("body") == "SYNTH-SAF-0902-004-HEALTH-OK"
                     and authenticated.get("tls_version", "").startswith("TLSv1.")
                     and any(event.get("path") == "/healthz"
                             and event.get("peer_cn") == "model-a"
                             and event.get("event") == "authenticated-health" for event in server_events))
        evidence["tls"]["authenticated"] = authenticated
        evidence["tls"]["server_events"] = server_events
        (lab.evidence / "isolation-accounting.raw.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        lab.check("positive", "Model A completes a routine /healthz request to Model B with server and client certificate verification",
                  mutual_ok, {"matched_mutual_tls": mutual_ok,
                              "peer_common_name": "model-a", "tls_version": authenticated.get("tls_version"),
                              "fixed_health_response": authenticated.get("body")})
