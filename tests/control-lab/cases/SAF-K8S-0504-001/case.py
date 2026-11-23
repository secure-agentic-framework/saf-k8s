"""Verify mTLS peer identity and current per-request authorization in Istio."""
from hashlib import sha256
import json
from pathlib import Path
import platform
import tarfile
import time

from fixtures import container, pod, ready

SCOPE = (
    "A fresh local Kind Kubernetes v1.36.1 cluster with Istio 1.32.0 sidecars and namespace-owned "
    "ServiceAccounts. Two workload identities reach the same two owned HTTP routes before "
    "workload policy activation. The destination proxy authenticates exact SPIFFE URI SANs. "
    "Requests from fresh client proxies after a scoped authorization change distinguish the approved identity "
    "and path from independent denied controls. Existing streams and production mesh policy "
    "coverage need further evidence."
)
ROOT = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
BACKEND = "saf-identity-target"
ALLOWED_PATH = "/allow"
OTHER_PATH = "/other"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
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
    system = platform.system()
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64"):
        arch = "x86_64"
    else:
        lab.block(f"Unsupported host architecture for Istio release archive: {machine}")
    key = f"{system}-{arch}"
    expected = ISTIO_RELEASE_SHA256.get(key)
    if not expected:
        lab.block(f"No verified Istio {ISTIO_VERSION} release digest for host {key}")
    release_os = "osx" if system == "Darwin" else system.lower()
    release_arch = "amd64" if arch == "x86_64" else arch
    filename = f"istio-{ISTIO_VERSION}-{release_os}-{release_arch}.tar.gz"
    archive = workdir / filename
    url = f"https://github.com/istio/istio/releases/download/{ISTIO_VERSION}/{filename}"
    lab.command("curl", "--fail", "--location", "--retry", "3", "--output", str(archive),
                url, timeout=240)
    if sha256(archive.read_bytes()).hexdigest() != expected:
        lab.block("Istio release archive SHA-256 mismatch")
    with tarfile.open(archive, "r:gz") as bundle:
        root = f"istio-{ISTIO_VERSION}/"
        wanted = (root + "bin/istioctl",)
        for member_name in wanted:
            member = bundle.getmember(member_name)
            if not member.isfile():
                lab.block(f"Istio release archive has no regular file at {member_name}")
            source = bundle.extractfile(member)
            if source is None:
                lab.block(f"Cannot read Istio release member {member_name}")
            destination = workdir / member_name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read())
        istioctl_path = workdir / root / "bin/istioctl"
        istioctl_path.chmod(0o755)
    return istioctl_path


def install(lab):
    work = lab.kubeconfig.parent
    installer = download_istio(lab, work)
    settings = work / "istio-settings.json"
    settings.write_text(json.dumps({
        "apiVersion": "install.istio.io/v1alpha1", "kind": "IstioOperator",
        "spec": {
            "profile": "minimal",
            "values": {"pilot": {"image": PILOT_IMAGE}},
            "meshConfig": {
                "accessLogFile": "/dev/stdout",
                "accessLogFormat": "SAF-PEER|%DOWNSTREAM_PEER_URI_SAN%|%REQ(X-SAF-CASE)%|%REQ(:PATH)%|%RESPONSE_CODE%",
            },
        },
    }))
    lab.command(str(installer), "install", "--kubeconfig", str(lab.kubeconfig),
                "--context", f"kind-{lab.cluster}", "-f", str(settings), "-y", timeout=280)
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "-n", "istio-system"]
    lab.command(*args, "rollout", "status", "deployment/istiod", "--timeout=90s", timeout=100)
    response = lab.command(*args, "get", "deployment/istiod", "-o", "json").stdout
    images = [row["image"] for row in json.loads(response)["spec"]["template"]["spec"]["containers"]]
    pinned = PILOT_IMAGE in images
    lab.check("positive", "Istio control plane is ready from the pinned release",
              pinned, {"istio_version": ISTIO_VERSION, "pilot_image_pinned": pinned})
    lab.kubectl("label", "namespace", NAMESPACE, "istio-injection=enabled")


def apply_config(lab, kind, name, spec):
    lab.create({"apiVersion": "security.istio.io/v1", "kind": kind,
                "metadata": {"name": name}, "spec": spec})


def mesh_pod(lab, name, container_config, service_account):
    workload = pod(name, [container_config], serviceAccountName=service_account)
    workload["metadata"]["labels"] = {"app": name}
    workload["metadata"]["annotations"] = {"sidecar.istio.io/proxyImage": PROXY_IMAGE}
    lab.create(workload)
    ready(lab, name)
    state = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    spec = state["spec"]
    sidecars = [*spec["containers"], *(entry for entry in spec.get("initContainers", [])
                                         if entry.get("restartPolicy") == "Always")]
    proxies = [item["image"] for item in sidecars if item["name"] == "istio-proxy"]
    effective = state["spec"]["serviceAccountName"] == service_account and proxies == [PROXY_IMAGE]
    lab.check("positive", f"{name} has the reviewed sidecar and service account",
              effective, {"service_account": service_account, "proxy_pinned": proxies == [PROXY_IMAGE]})


def client(lab, name, service_account):
    mesh_pod(lab, name, container("workload", image=PYTHON_IMAGE,
                                  command=["python", "-c", "import time; time.sleep(600)"]),
             service_account)


def http(lab, name, path, marker):
    code = (ROOT / "request.py").read_text()
    result = lab.kubectl("exec", name, "-c", "workload", "--", "python", "-c", code, path, marker,
                         allow_failure=True, timeout=14)
    return json.loads(result.stdout) if result.returncode == 0 else {"status": 0, "body": ""}


def logged_peer(lab, name, path, marker, status):
    peer = f"spiffe://cluster.local/ns/{NAMESPACE}/sa/{name}"
    expected = f"SAF-PEER|{peer}|{marker}|{path}|{status}"
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        rows = lab.kubectl("logs", BACKEND, "-c", "istio-proxy").stdout.splitlines()
        if expected in rows:
            return True
        time.sleep(0.5)
    return False


def check_request(lab, phase, identity, path, status, marker, client_name):
    result = http(lab, client_name, path, marker)
    expected_body = "saf-identity-marker" if status == 200 else "RBAC: access denied"
    peer = logged_peer(lab, identity, path, marker, status)
    evidence = {"identity": identity, "path": path, "http_status": result["status"],
                "exact_body_matched": result["body"] == expected_body,
                "destination_proxy_confirmed_mtls_peer": peer}
    lab.check(phase, f"{identity} receives HTTP {status} on {path} with the measured mTLS identity",
              result == {"status": status, "body": expected_body} and peer, evidence)
    return evidence


def run(lab):
    install(lab)
    selector = {"matchLabels": {"app": BACKEND}}
    apply_config(lab, "PeerAuthentication", "owned-strict", {"selector": selector, "mtls": {"mode": "STRICT"}})
    app_script = (
        "mkdir /tmp/backend; printf saf-identity-marker >/tmp/backend/allow; "
        "printf saf-identity-marker >/tmp/backend/other; exec httpd -f -p 8080 -h /tmp/backend"
    )
    lab.kubectl("create", "serviceaccount", BACKEND)
    mesh_pod(lab, BACKEND, container("workload", command=["sh", "-ec", app_script]), BACKEND)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": BACKEND},
                "spec": {"selector": {"app": BACKEND}, "ports": [{"name": "http", "port": 8080}]}})
    for name in ("approved", "other"):
        lab.kubectl("create", "serviceaccount", name)
        client(lab, name, name)

    requests = [(name, path) for name in ("approved", "other") for path in (ALLOWED_PATH, OTHER_PATH)]
    baseline = [
        check_request(lab, "red", name, path, 200, f"before-{index}", name)
        for index, (name, path) in enumerate(requests)
    ]
    apply_config(lab, "AuthorizationPolicy", "owned-identity-policy", {
        "selector": selector, "action": "ALLOW",
        "rules": [{"from": [{"source": {"principals": [f"cluster.local/ns/{NAMESPACE}/sa/approved"]}}],
                   "to": [{"operation": {"methods": ["GET"], "paths": [ALLOWED_PATH]}}]}],
    })
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if http(lab, "other", ALLOWED_PATH, "propagation")["status"] == 403:
            break
        time.sleep(0.5)
    else:
        lab.block("The owned target proxy did not observe the authorization policy")
    # Earlier clients can retain their mesh upstream connections across an xDS update.
    # Use new outbound proxies with the same identities for the after-policy matrix.
    for name in ("approved", "other"):
        client(lab, f"{name}-fresh", name)
    enforced = [
        check_request(lab, "green", name, path, 403, f"after-{index}", f"{name}-fresh")
        for index, (name, path) in enumerate(requests[1:])
    ]
    allowed = check_request(lab, "positive", "approved", ALLOWED_PATH, 200, "after-permitted", "approved-fresh")
    (lab.evidence / "identity-observations.json").write_text(
        json.dumps({"baseline": baseline, "denials": enforced, "permitted": allowed},
                   indent=2, sort_keys=True) + "\n"
    )
