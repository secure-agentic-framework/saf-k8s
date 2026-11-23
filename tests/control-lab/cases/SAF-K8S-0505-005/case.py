"""Verify workload identity trust separately from service authorization."""
from hashlib import sha256
import json
from pathlib import Path
import platform
import tarfile
import time

SCOPE = (
    "One owned Kind cluster with pinned Istio 1.32.0 sidecars and STRICT destination mTLS. "
    "The authorized ServiceAccount and a different namespace's same-named account both "
    "establish mTLS and reach the same protected HTTP route before authorization. "
    "Fresh proxies after policy keep the approved namespace and account authorized. "
    "The same name in the other namespace receives HTTP 403 from the destination proxy, "
    "which records both exact verified SPIFFE URI SANs. Production policy, identity issuance "
    "governance, and other authorization implementations need their own evidence."
)
ROOT = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
NEIGHBOR = "saf-neighbor"
BACKEND = "saf-0505-005-target"
APPROVED = "saf-0505-005-approved"
DENIED = "saf-0505-005-denied"
ALLOWED_PATH = "/sensitive"
DENIED_PATH = "/other"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
PILOT_IMAGE = (
    "docker.io/istio/pilot:1.32.0@sha256:"
    "5383df363d976589a51ab438831f82e9b5303dfc42128f2fb1f493b3f6acca78"
)
PROXY_IMAGE = (
    "docker.io/istio/proxyv2:1.32.0@sha256:"
    "b8d47c6d8d6e4b3fee7ae1e6f44339ec13091c24dc07f113a35efb0141a688d0"
)
ISTIO_VERSION = "1.32.0"
ISTIO_RELEASE_SHA256 = {
    "Linux-x86_64": "b9cc0d427e2742b63ade28e15332a4b5da37ebf2d777a25ba22cc91bbfd51fbf",
    "Linux-arm64": "76f220746c75b6b0098d752da941ed91afc4e0cfd6722b853172d764fb6c2173",
    "Darwin-arm64": "1d9a82445c2395f85ce3a165dc90e182ad4e52214f85c18e93db274fd6d82fbb",
    "Darwin-x86_64": "803f30507ba687f88e10ea9b6736dfb77fcc3c66c1d3ce8dc71420bfcfe27d6c",
}


def download_istio(lab, workdir):
    system, machine = platform.system(), platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x86_64" if machine in ("x86_64", "amd64") else None
    if arch is None:
        lab.block(f"Unsupported host architecture for Istio release archive: {machine}")
    expected = ISTIO_RELEASE_SHA256.get(f"{system}-{arch}")
    if not expected:
        lab.block(f"No verified Istio {ISTIO_VERSION} release digest for host {system}-{arch}")
    release_os = "osx" if system == "Darwin" else system.lower()
    release_arch = "amd64" if arch == "x86_64" else arch
    filename = f"istio-{ISTIO_VERSION}-{release_os}-{release_arch}.tar.gz"
    archive = workdir / filename
    lab.command("curl", "--fail", "--location", "--retry", "3", "--output", str(archive),
                f"https://github.com/istio/istio/releases/download/{ISTIO_VERSION}/{filename}", timeout=240)
    if sha256(archive.read_bytes()).hexdigest() != expected:
        lab.block("Istio release archive SHA-256 mismatch")
    with tarfile.open(archive, "r:gz") as bundle:
        member_name = f"istio-{ISTIO_VERSION}/bin/istioctl"
        member = bundle.getmember(member_name)
        if not member.isfile():
            lab.block(f"Istio release archive has no regular file at {member_name}")
        source = bundle.extractfile(member)
        if source is None:
            lab.block(f"Cannot read Istio release member {member_name}")
        destination = workdir / member_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read())
        destination.chmod(0o755)
    return destination


def create_policy(lab, kind, name, spec):
    lab.create({"apiVersion": "security.istio.io/v1", "kind": kind,
                "metadata": {"name": name}, "spec": spec})


def container(name, image=PYTHON_IMAGE, **fields):
    return {
        "name": name, "image": image,
        "command": ["python", "-c", "import time; time.sleep(600)"],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                            "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        **fields,
    }


def namespaced(lab, namespace, *args, **kwargs):
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                       f"kind-{lab.cluster}", "-n", namespace, *args, **kwargs)


def mesh_pod(lab, name, command, service_account, image=PYTHON_IMAGE, *, namespace=NAMESPACE):
    workload = {
        "apiVersion": "v1", "kind": "Pod", "metadata": {
            "name": name, "labels": {"app": name},
            "annotations": {"sidecar.istio.io/proxyImage": PROXY_IMAGE},
        },
        "spec": {"restartPolicy": "Never", "serviceAccountName": service_account,
                 "containers": [container("workload", image=image, command=command)]},
    }
    namespaced(lab, namespace, "create", "-f", "-", payload=json.dumps(workload))
    namespaced(lab, namespace, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)
    state = json.loads(namespaced(lab, namespace, "get", "pod", name, "-o", "json").stdout)
    sidecars = [*state["spec"]["containers"], *(entry for entry in state["spec"].get("initContainers", [])
                                                 if entry.get("restartPolicy") == "Always")]
    proxies = [item["image"] for item in sidecars if item["name"] == "istio-proxy"]
    valid = state["spec"].get("serviceAccountName") == service_account and proxies == [PROXY_IMAGE]
    lab.check("positive", f"{namespace}/{name} runs with its exact service account and pinned sidecar",
              valid, {"service_account": state["spec"].get("serviceAccountName"),
                      "proxy_image_matches_pin": proxies == [PROXY_IMAGE]})


def request(lab, client, path, marker, namespace=NAMESPACE):
    script = (ROOT / "request.py").read_text()
    result = namespaced(lab, namespace, "exec", client, "-c", "workload", "--", "python", "-c", script,
                         path, marker, allow_failure=True, timeout=14)
    try:
        return json.loads(result.stdout) if result.returncode == 0 else {"status": 0, "body": ""}
    except json.JSONDecodeError:
        return {"status": 0, "body": ""}


def observed_peer(lab, path, marker, status, service_account, namespace):
    peer = f"spiffe://cluster.local/ns/{namespace}/sa/{service_account}"
    expected = f"SAF-0505-005|{peer}|{marker}|{path}|{status}"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        rows = lab.kubectl("logs", BACKEND, "-c", "istio-proxy").stdout.splitlines()
        if expected in rows:
            return True, peer
        time.sleep(0.5)
    return False, peer


def probe(lab, phase, identity, service_account, client, path, marker, expected_status, namespace=NAMESPACE):
    result = request(lab, client, path, marker, namespace)
    expected_body = "saf-0505-005-fixture" if expected_status == 200 else "RBAC: access denied"
    peer_seen, peer = observed_peer(lab, path, marker, expected_status, service_account, namespace)
    evidence = {"identity": identity, "expected_peer_uri_san": peer, "path": path,
                "method": "GET", "http_status": result["status"],
                "response_body_matches": result["body"] == expected_body,
                "destination_proxy_observed_authenticated_mtls_peer": peer_seen}
    lab.check(phase, f"{identity} gets HTTP {expected_status} for {path} with measured mTLS identity",
              result == {"status": expected_status, "body": expected_body} and peer_seen, evidence)
    return evidence


def run(lab):
    work = lab.kubeconfig.parent
    installer = download_istio(lab, work)
    settings = work / "istio-settings.json"
    settings.write_text(json.dumps({
        "apiVersion": "install.istio.io/v1alpha1", "kind": "IstioOperator",
        "spec": {"profile": "minimal", "values": {"pilot": {"image": PILOT_IMAGE}},
                 "meshConfig": {"accessLogFile": "/dev/stdout",
                                "accessLogFormat": "SAF-0505-005|%DOWNSTREAM_PEER_URI_SAN%|%REQ(X-SAF-CASE)%|%REQ(:PATH)%|%RESPONSE_CODE%"}},
    }))
    lab.command(str(installer), "install", "--kubeconfig", str(lab.kubeconfig), "--context",
                f"kind-{lab.cluster}", "-f", str(settings), "-y", timeout=280)
    system_args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                   "-n", "istio-system"]
    lab.command(*system_args, "rollout", "status", "deployment/istiod", "--timeout=90s", timeout=100)
    deployment = json.loads(lab.command(*system_args, "get", "deployment/istiod", "-o", "json").stdout)
    pilot_images = [row["image"] for row in deployment["spec"]["template"]["spec"]["containers"]]
    lab.check("positive", "Istio control plane uses the pinned pilot image", PILOT_IMAGE in pilot_images,
              {"istio_version": ISTIO_VERSION, "pilot_image_matches_pin": PILOT_IMAGE in pilot_images})
    lab.kubectl("create", "namespace", NEIGHBOR)
    lab.kubectl("label", "namespace", NAMESPACE, NEIGHBOR, "istio-injection=enabled")

    selector = {"matchLabels": {"app": BACKEND}}
    create_policy(lab, "PeerAuthentication", "saf-0505-005-target-strict-mtls",
                  {"selector": selector, "mtls": {"mode": "STRICT"}})
    backend_command = ["sh", "-ec", "mkdir /tmp/backend; printf saf-0505-005-fixture >/tmp/backend/sensitive; "
                       "printf saf-0505-005-fixture >/tmp/backend/other; exec httpd -f -p 8080 -h /tmp/backend"]
    lab.kubectl("create", "serviceaccount", BACKEND)
    mesh_pod(lab, BACKEND, backend_command, BACKEND, BUSYBOX_IMAGE)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": BACKEND},
                "spec": {"selector": {"app": BACKEND}, "ports": [{"name": "http", "port": 8080}]}})
    for account in (APPROVED, DENIED):
        lab.kubectl("create", "serviceaccount", account)
        mesh_pod(lab, account, ["python", "-c", "import time; time.sleep(600)"], account)

    client_command = ["python", "-c", "import time; time.sleep(600)"]
    namespaced(lab, NEIGHBOR, "create", "serviceaccount", APPROVED)
    mesh_pod(lab, APPROVED, client_command, APPROVED, namespace=NEIGHBOR)

    # Red observation: strict mTLS authenticates both identities, but does not authorize either.
    red_approved = probe(lab, "red", APPROVED, APPROVED, APPROVED, ALLOWED_PATH,
                         "saf0505005-red-approved", 200)
    red_denied = probe(lab, "red", DENIED, DENIED, DENIED, ALLOWED_PATH,
                       "saf0505005-red-denied", 200)

    neighbor_baseline = probe(lab, "red", "same account name in the other namespace", APPROVED,
                              APPROVED, ALLOWED_PATH, "saf0505005-red-neighbor", 200, NEIGHBOR)

    create_policy(lab, "AuthorizationPolicy", "saf-0505-005-boundary-authorization", {
        "selector": selector, "action": "ALLOW",
        "rules": [{"from": [{"source": {"principals": [
            f"cluster.local/ns/{NAMESPACE}/sa/{APPROVED}"]}}],
                   "to": [{"operation": {"methods": ["GET"], "paths": [ALLOWED_PATH]}}]}],
    })
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if request(lab, DENIED, ALLOWED_PATH, "saf0505005-policy-ready")["status"] == 403:
            break
        time.sleep(0.5)
    else:
        lab.block("The selected target proxy did not begin enforcing the authorization policy")

    # Fresh source proxies ensure the probes use new outbound connections after xDS propagation.
    for account in (APPROVED, DENIED):
        mesh_pod(lab, account + "-fresh", ["python", "-c", "import time; time.sleep(600)"], account)
    mesh_pod(lab, APPROVED + "-fresh", client_command, APPROVED, namespace=NEIGHBOR)
    neighbor_denied = probe(lab, "green", "same account name in the other namespace", APPROVED,
                            APPROVED + "-fresh", ALLOWED_PATH, "saf0505005-green-neighbor", 403, NEIGHBOR)
    denied_identity = probe(lab, "green", DENIED, DENIED, DENIED + "-fresh", ALLOWED_PATH,
                            "saf0505005-green-denied-identity", 403)
    denied_operation = probe(lab, "green", APPROVED, APPROVED, APPROVED + "-fresh", DENIED_PATH,
                             "saf0505005-green-denied-path", 403)
    permitted = probe(lab, "positive", APPROVED, APPROVED, APPROVED + "-fresh", ALLOWED_PATH,
                      "saf0505005-positive-approved", 200)

    (lab.evidence / "saf-k8s-0505-005-result.json").write_text(json.dumps({
        "control_id": "SAF-K8S-0505-005",
        "result_type": "synthetic service-boundary identity authorization observations",
        "fixture": "fixed local HTTP marker; no external workload or user data",
        "observations": {"before_authorization": [red_approved, red_denied, neighbor_baseline],
                         "denied_other_namespace": neighbor_denied,
                         "denied_identity": denied_identity,
                         "denied_path": denied_operation,
                         "permitted_identity_and_path": permitted},
        "limits": ["does not establish production policy coverage or rollout state",
                   "does not establish identity issuance, trust-domain governance, or token protection",
                   "does not establish application-layer authentication behavior",
                   "does not establish provider-specific NetworkPolicy or dataplane behavior"],
    }, indent=2, sort_keys=True) + "\n")
