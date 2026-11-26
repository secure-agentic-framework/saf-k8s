"""Two-domain SPIRE bridge for the owned SAF-K8S-0910-016 API pair."""
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import shlex
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

from fixtures import container


HERE = Path(__file__).resolve().parent
NS = "saf-test"
SERVER = "spire-server-0"
SERVER_BIN = "/opt/spire/bin/spire-server"
SERVER_IMAGE = ("ghcr.io/spiffe/spire-server:1.16.0@sha256:"
                "ff546f4c62dafc479a0cd79eae9a7b6df2975754d75efd31706098e0d7548837")
AGENT_IMAGE = ("ghcr.io/spiffe/spire-agent:1.16.0@sha256:"
               "ab3a8ce70435374cc5d84c81eabf0278dc046ddbc0a736d59694ba9e5975b1b6")
SOURCE_DOMAIN = "src.saf.test"
PEER_DOMAIN = "peer.saf.test"
SOURCE_CLUSTER_ID = "saf-source"
PEER_CLUSTER_ID = "saf-peer"
SERVER_SA = "saf0910-spire-server"
AGENT_SA = "saf0910-spire-agent"
APPROVED_SA = "fixture-orchestrator-approved"
ALTERNATE_SA = "fixture-orchestrator-alternate"
GATEWAY_SA = "fixture-orchestration-service"
APPROVED_URI = f"spiffe://{SOURCE_DOMAIN}/ns/{NS}/sa/{APPROVED_SA}"
ALTERNATE_URI = f"spiffe://{SOURCE_DOMAIN}/ns/{NS}/sa/{ALTERNATE_SA}"
GATEWAY_URI = f"spiffe://{PEER_DOMAIN}/ns/{NS}/sa/{GATEWAY_SA}"
APPROVED_POD = "spire-orchestrator-approved"
ALTERNATE_POD = "spire-orchestrator-alternate"
GATEWAY_POD = "spire-orchestration-gateway"
GATEWAY_SERVICE = "spire-orchestration-gateway"
APP_CODE = "spire-orchestration-code"
WORKLOAD = "fixture-crosscluster-placement"
ADMISSION_REASON = "SAF-K8S-0910-016: placement is outside the approved fixture target"


class Cluster:
    def __init__(self, lab, name, kubeconfig, context):
        self.lab = lab
        self.name = name
        self.kubeconfig = str(kubeconfig)
        self.context = context

    def argv(self, *args, timeout=45):
        return ["kubectl", "--kubeconfig", self.kubeconfig, "--context", self.context,
                "--namespace", NS, f"--request-timeout={timeout - 5}s", *args]

    def kubectl(self, *args, timeout=45, **kwargs):
        return self.lab.command(*self.argv(*args, timeout=timeout), timeout=timeout, **kwargs)

    def quiet(self, *args, timeout=45):
        """Capture certificate-bearing stdout in memory and log only its digest/size."""
        argv = self.argv(*args, timeout=timeout)
        try:
            result = subprocess.run(argv, text=True, capture_output=True, env=self.lab.env,
                                    timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.lab.block(f"Owned cluster {self.name} redacted capture failed ({type(exc).__name__})")
        digest = hashlib.sha256(result.stdout.encode()).hexdigest()
        with (self.lab.evidence / "commands.log").open("a", encoding="utf-8") as log:
            log.write(f"$ [redacted capture] {shlex.join(argv)}\n")
            log.write(f"[stdout bytes={len(result.stdout)} sha256={digest} exit={result.returncode}]\n\n")
        if result.returncode:
            self.lab.block(f"Owned cluster {self.name} redacted capture failed")
        return result.stdout

    def create(self, obj):
        self.kubectl("create", "-f", "-", payload=json.dumps(obj, sort_keys=True))


def row(kind, name, api="v1", **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def public_roots(pem):
    certs = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    return sorted(hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest() for cert in certs)


def private_address(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or address.is_global or address.is_loopback or address.is_link_local:
        raise ValueError("SPIRE federation endpoint is not a private owned IPv4 address")
    return str(address)


def secure_public_configmap(target, name, pem):
    # The bundle is public trust material, but use a mode-0600 file so the
    # command logger never receives the certificate bytes in argv/stdin.
    with tempfile.TemporaryDirectory(prefix="saf-0910-016-public-bundle-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        bundle_file = root / "bundle.pem"
        bundle_file.write_text(pem, encoding="ascii")
        bundle_file.chmod(0o600)
        target.kubectl("delete", "configmap", name, allow_failure=True)
        target.kubectl("create", "configmap", name, "--from-file=bundle.pem=" + str(bundle_file),
                       "-o", "name", timeout=30)


def kubelet_serving_csr(target):
    nodes = json.loads(target.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1 or nodes[0]["metadata"]["name"] != f"{target.name}-control-plane":
        target.lab.block("SPIRE workload attestation expects the exact owned single-node fixture")
    node = nodes[0]["metadata"]["name"]
    address = next(item["address"] for item in nodes[0]["status"]["addresses"]
                   if item["type"] == "InternalIP")
    bridge = target.lab.command("docker", "inspect", "--format",
        '{{json (index .NetworkSettings.Networks "kind")}}', node).stdout
    if private_address(address) != json.loads(bridge).get("IPAddress"):
        target.lab.block("The kubelet-serving CSR node address differs from the owned Kind bridge")
    deadline = time.monotonic() + 40
    candidates = []
    while time.monotonic() < deadline:
        requests = json.loads(target.quiet("get", "csr", "-o", "json"))["items"]
        candidates = [csr for csr in requests
                      if csr.get("spec", {}).get("signerName") == "kubernetes.io/kubelet-serving"
                      and csr.get("spec", {}).get("username") == f"system:node:{node}"]
        if candidates:
            break
        time.sleep(0.5)
    if not 1 <= len(candidates) <= 8:
        target.lab.block("Expected a bounded set of kubelet-serving requests from the owned node")
    validated = []
    pending = []
    allowed_names = {f"IP Address:{address}", f"DNS:{node}"}
    expected_subject = f"subject=CN=system:node:{node},O=system:nodes"
    for csr in candidates:
        spec = csr["spec"]
        conditions = {item.get("type") for item in csr.get("status", {}).get("conditions", [])}
        if (set(spec.get("groups", [])) != {"system:nodes", "system:authenticated"}
                or set(spec.get("usages", [])) not in
                    ({"digital signature", "server auth"}, {"digital signature", "key encipherment", "server auth"})
                or conditions & {"Denied", "Failed"}):
            target.lab.block("The serving CSR has unexpected owned-node identity or usages")
        parsed = target.lab.command(
            "openssl", "req", "-noout", "-verify", "-subject", "-nameopt", "RFC2253", "-text",
            payload=base64.b64decode(spec["request"]).decode(), timeout=15)
        subject = {line.strip().replace("subject= ", "subject=") for line in parsed.stdout.splitlines()
                   if line.strip().startswith("subject=")}
        san_line = re.search(r"X509v3 Subject Alternative Name:[^\n]*\n([^\n]+)", parsed.stdout)
        sans = {value.strip() for value in san_line.group(1).split(",")} if san_line else set()
        if (subject != {expected_subject} or f"IP Address:{address}" not in sans
                or not sans <= allowed_names):
            target.lab.block("The serving CSR does not match the exact owned fixture identity and endpoint")
        csr_name = csr["metadata"]["name"]
        validated.append(csr_name)
        if "Approved" not in conditions:
            pending.append(csr_name)
    if pending:
        target.kubectl("certificate", "approve", *pending)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        latest = validated[-1]
        cert = target.quiet("get", "csr", latest, "-o=jsonpath={.status.certificate}", timeout=15)
        if cert.strip():
            health = target.kubectl("get", "--raw", f"/api/v1/nodes/{node}/proxy/healthz",
                                    timeout=12, allow_failure=True)
            if health.returncode == 0 and health.stdout.strip() == "ok":
                return {"node_name_matches": True, "internal_ip_matches_csr": True,
                        "serving_usage_approved": True}
        time.sleep(0.5)
    target.lab.block("The exact owned kubelet serving certificate did not become active")


def server_config(domain, cluster_id):
    return f'''server {{
  bind_address = "0.0.0.0"
  bind_port = 8081
  trust_domain = "{domain}"
  data_dir = "/run/spire/data"
  log_level = "INFO"
  default_x509_svid_ttl = "600s"
  federation {{
    bundle_endpoint {{
      address = "0.0.0.0"
      port = 8443
      profile "https_spiffe" {{}}
    }}
  }}
}}
plugins {{
  DataStore "sql" {{ plugin_data {{
    database_type = "sqlite3"
    connection_string = "/run/spire/data/datastore.sqlite3"
  }} }}
  KeyManager "memory" {{ plugin_data {{}} }}
  NodeAttestor "k8s_psat" {{ plugin_data {{
    clusters = {{ "{cluster_id}" = {{
      service_account_allow_list = ["{NS}:{AGENT_SA}"]
    }} }}
  }} }}
}}
'''


def agent_config(domain, cluster_id, socket_path):
    return f'''agent {{
  data_dir = "/run/spire/data"
  log_level = "INFO"
  server_address = "spire-server"
  server_port = 8081
  socket_path = "/run/spire/sockets/agent.sock"
  trust_bundle_path = "/run/spire/bootstrap/bundle.pem"
  trust_domain = "{domain}"
}}
plugins {{
  NodeAttestor "k8s_psat" {{ plugin_data {{
    cluster = "{cluster_id}"
    token_path = "/run/spire/psat/token"
  }} }}
  KeyManager "memory" {{ plugin_data {{}} }}
  WorkloadAttestor "k8s" {{ plugin_data {{
    kubelet_secure_port = 10250
    kubelet_ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    node_name_env = "K8S_NODE_ADDRESS"
  }} }}
  WorkloadAttestor "unix" {{ plugin_data {{}} }}
}}
'''


def install_server(target, domain, cluster_id):
    for name in (SERVER_SA, AGENT_SA):
        target.create(row("ServiceAccount", name))
    target.create(row("ConfigMap", "spire-server-config", data={
        "server.conf": server_config(domain, cluster_id)}))
    target.create(row("ConfigMap", "spire-federation-bootstrap", data={"bundle.pem": "pending\n"}))
    target.create(row("Service", "spire-server", spec={"selector": {"app": "spire-server"},
        "ports": [{"name": "grpc", "port": 8081, "targetPort": 8081},
                  {"name": "federation", "port": 8443, "targetPort": 8443}]}))
    target.create(row("Service", "spire-federation-endpoint", spec={
        "type": "NodePort", "selector": {"app": "spire-server"},
        "ports": [{"name": "federation", "port": 8443, "targetPort": 8443}]}))
    target.create(row("ClusterRole", "saf0910-spire-server-review",
        api="rbac.authorization.k8s.io/v1", rules=[
            {"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"],
             "verbs": ["create"]},
            {"apiGroups": [""], "resources": ["pods", "nodes"], "verbs": ["get"]},
        ]))
    target.create(row("ClusterRoleBinding", "saf0910-spire-server-review",
        api="rbac.authorization.k8s.io/v1",
        roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                 "name": "saf0910-spire-server-review"},
        subjects=[{"kind": "ServiceAccount", "name": SERVER_SA, "namespace": NS}]))
    target.create(row("StatefulSet", "spire-server", api="apps/v1", spec={
        "serviceName": "spire-server", "replicas": 1,
        "selector": {"matchLabels": {"app": "spire-server"}},
        "template": {"metadata": {"labels": {"app": "spire-server"}}, "spec": {
            "serviceAccountName": SERVER_SA,
            "containers": [{"name": "server", "image": SERVER_IMAGE,
                "command": ["/opt/spire/bin/spire-server"],
                "args": ["run", "-config", "/run/spire/config/server.conf"],
                "ports": [{"containerPort": 8081}, {"containerPort": 8443}],
                "readinessProbe": {"tcpSocket": {"port": 8081}, "periodSeconds": 2,
                                   "failureThreshold": 30},
                "resources": {"requests": {"cpu": "100m", "memory": "192Mi"},
                              "limits": {"cpu": "500m", "memory": "512Mi"}},
                "volumeMounts": [
                    {"name": "config", "mountPath": "/run/spire/config", "readOnly": True},
                    {"name": "data", "mountPath": "/run/spire/data"},
                    {"name": "bootstrap", "mountPath": "/run/spire/foreign", "readOnly": True},
                ]}],
            "volumes": [
                {"name": "config", "configMap": {"name": "spire-server-config"}},
                {"name": "data", "emptyDir": {}},
                {"name": "bootstrap", "configMap": {"name": "spire-federation-bootstrap",
                                                         "items": [{"key": "bundle.pem",
                                                                    "path": "bundle.pem"}]}},
            ],
        }},
    }))
    result = target.kubectl("rollout", "status", "statefulset/spire-server", "--timeout=75s",
                            timeout=85, allow_failure=True)
    if result.returncode:
        target.lab.block("The owned SPIRE server did not become ready")
    bundle = target.quiet("exec", SERVER, "-c", "server", "--", SERVER_BIN,
                          "bundle", "show", "-format", "pem", timeout=15)
    roots = public_roots(bundle)
    if not roots:
        target.lab.block("The owned SPIRE server did not expose a public root bundle")
    return bundle, roots


def replace_bootstrap(target, pem):
    if not public_roots(pem):
        target.lab.block("The peer bootstrap bundle has no public roots")
    with tempfile.TemporaryDirectory(prefix="saf-0910-016-federation-") as directory:
        patch = Path(directory) / "bootstrap.json"
        patch.write_text(json.dumps({"data": {"bundle.pem": pem}}), encoding="ascii")
        patch.chmod(0o600)
        target.kubectl("patch", "configmap", "spire-federation-bootstrap",
                       "--type=merge", "--patch-file", str(patch), "-o", "name")
    bundle_digest = hashlib.sha256(pem.encode("ascii")).hexdigest()
    target.kubectl("annotate", "pod", SERVER,
                   f"saf-lab.example/peer-bootstrap-sha256={bundle_digest}", "--overwrite")


def install_agent(target, domain, cluster_id, socket_path, bundle):
    secure_public_configmap(target, "spire-agent-bootstrap", bundle)
    target.create(row("ConfigMap", "spire-agent-config", data={
        "agent.conf": agent_config(domain, cluster_id, socket_path)}))
    target.create(row("ClusterRole", "saf0910-spire-agent-kubelet",
        api="rbac.authorization.k8s.io/v1", rules=[{
            "apiGroups": [""], "resources": ["nodes/pods"], "verbs": ["get"]}]))
    target.create(row("ClusterRoleBinding", "saf0910-spire-agent-kubelet",
        api="rbac.authorization.k8s.io/v1",
        roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                 "name": "saf0910-spire-agent-kubelet"},
        subjects=[{"kind": "ServiceAccount", "name": AGENT_SA, "namespace": NS}]))
    target.create(row("DaemonSet", "spire-agent", api="apps/v1", spec={
        "selector": {"matchLabels": {"app": "spire-agent"}},
        "template": {"metadata": {"labels": {"app": "spire-agent"}}, "spec": {
            "serviceAccountName": AGENT_SA, "hostPID": True,
            "containers": [{"name": "agent", "image": AGENT_IMAGE,
                "command": ["/opt/spire/bin/spire-agent"],
                "args": ["run", "-config", "/run/spire/config/agent.conf"],
                "readinessProbe": {"exec": {"command": ["/opt/spire/bin/spire-agent",
                    "healthcheck", "-socketPath", "/run/spire/sockets/agent.sock"]},
                    "periodSeconds": 2, "failureThreshold": 30},
                "env": [{"name": "K8S_NODE_ADDRESS", "valueFrom": {
                    "fieldRef": {"fieldPath": "status.hostIP"}}}],
                "resources": {"requests": {"cpu": "50m", "memory": "128Mi"},
                              "limits": {"cpu": "300m", "memory": "384Mi"}},
                "volumeMounts": [
                    {"name": "config", "mountPath": "/run/spire/config", "readOnly": True},
                    {"name": "bootstrap", "mountPath": "/run/spire/bootstrap", "readOnly": True},
                    {"name": "sockets", "mountPath": "/run/spire/sockets"},
                    {"name": "data", "mountPath": "/run/spire/data"},
                    {"name": "psat", "mountPath": "/run/spire/psat", "readOnly": True},
                ]}],
            "volumes": [
                {"name": "config", "configMap": {"name": "spire-agent-config"}},
                {"name": "bootstrap", "configMap": {"name": "spire-agent-bootstrap"}},
                {"name": "sockets", "hostPath": {"path": socket_path,
                                                      "type": "DirectoryOrCreate"}},
                {"name": "data", "emptyDir": {}},
                {"name": "psat", "projected": {"sources": [{"serviceAccountToken": {
                    "audience": "spire-server", "expirationSeconds": 900, "path": "token"}}]}},
            ],
        }},
    }))
    result = target.kubectl("rollout", "status", "daemonset/spire-agent", "--timeout=80s",
                            timeout=90, allow_failure=True)
    if result.returncode:
        target.lab.block("The owned SPIRE agent did not finish node attestation")
    listing = target.kubectl("exec", SERVER, "-c", "server", "--", SERVER_BIN,
                             "agent", "list").stdout
    pattern = rf"spiffe://{re.escape(domain)}/spire/agent/k8s_psat/{re.escape(cluster_id)}/[a-zA-Z0-9-]+"
    matches = set(re.findall(pattern, listing))
    if len(matches) != 1:
        target.lab.block("SPIRE did not attest exactly one owned cluster agent")
    return matches.pop()


def register(target, parent_id, spiffe_id, service_account, pod_label, container_name,
             federates_with=None):
    args = ["entry", "create", "-parentID", parent_id, "-spiffeID", spiffe_id,
            "-x509SVIDTTL", "600", "-selector", f"k8s:ns:{NS}",
            "-selector", f"k8s:sa:{service_account}",
            "-selector", f"k8s:pod-label:app:{pod_label}",
            "-selector", f"k8s:container-name:{container_name}"]
    if federates_with:
        args.extend(["-federatesWith", f"spiffe://{federates_with}"])
    target.kubectl("exec", SERVER, "-c", "server", "--", SERVER_BIN, *args, timeout=25)


def federation(target, other_domain, endpoint, other_endpoint_id):
    deadline = time.monotonic() + 120
    created = False
    while time.monotonic() < deadline:
        result = target.kubectl("exec", SERVER, "-c", "server", "--", SERVER_BIN,
            "federation", "create", "-trustDomain", other_domain,
            "-bundleEndpointURL", endpoint, "-bundleEndpointProfile", "https_spiffe",
            "-endpointSpiffeID", other_endpoint_id,
            "-trustDomainBundlePath", "/run/spire/foreign/bundle.pem",
            allow_failure=True, timeout=12)
        if result.returncode == 0:
            created = True
            break
        time.sleep(0.5)
    if not created:
        target.lab.block("SPIRE could not load the owned federated trust bundle")
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        result = target.kubectl("exec", SERVER, "-c", "server", "--", SERVER_BIN,
            "federation", "refresh", "-id", f"spiffe://{other_domain}",
            allow_failure=True, timeout=12)
        if result.returncode == 0:
            pem = target.quiet("exec", SERVER, "-c", "server", "--", SERVER_BIN,
                "bundle", "list", "-id", f"spiffe://{other_domain}", "-format", "pem", timeout=15)
            roots = public_roots(pem)
            if roots:
                return roots
        time.sleep(0.75)
    target.lab.block("The owned SPIRE servers did not complete the authenticated bundle refresh")


def service_nodeport(target):
    obj = json.loads(target.kubectl("get", "service", "spire-federation-endpoint", "-o", "json").stdout)
    port = obj["spec"]["ports"][0]["nodePort"]
    if not 30000 <= port <= 32767:
        target.lab.block("SPIRE federation service has an unexpected NodePort")
    return port


def create_workload_pod(target, name, service_account, image, mode, label):
    if mode != "gateway":
        target.create(row("ServiceAccount", service_account, automountServiceAccountToken=False))
    app_command = (["python", "/fixture/spire_orchestration.py", "serve"] if mode == "gateway"
                   else ["sleep", "3600"])
    app_name = "gateway" if mode == "gateway" else "orchestrator"
    pod = row("Pod", name, metadata={"name": name, "namespace": NS,
        "labels": {"app": label, "saf-k8s.example/control": "SAF-K8S-0910-016"}}, spec={
        # The app starts only after exact identity issuance. Bounded harness readiness
        # permits the init to retry while the attested agent syncs new entries.
        "restartPolicy": "OnFailure", "serviceAccountName": service_account,
        "automountServiceAccountToken": mode == "gateway",
        "securityContext": {"fsGroup": 65534},
        "initContainers": [{"name": "fetcher", "image": AGENT_IMAGE,
            # The SPIRE CLI writes the key owner-only. Fetch and use it as UID 65534.
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "command": ["/opt/spire/bin/spire-agent"],
            "args": ["api", "fetch", "x509", "-socketPath", "/run/spire/sockets/agent.sock",
                     "-write", "/run/svid", "-silent", "-timeout", "30s"],
            "volumeMounts": [
                {"name": "sockets", "mountPath": "/run/spire/sockets", "readOnly": True},
                {"name": "svid", "mountPath": "/run/svid"},
            ],
            "resources": {"requests": {"cpu": "25m", "memory": "32Mi"},
                          "limits": {"cpu": "100m", "memory": "96Mi"}},
        }],
        "containers": [container(app_name, image=image, imagePullPolicy="Never",
            command=app_command, ports=([{"containerPort": 8443}] if mode == "gateway" else []),
            readinessProbe=({"tcpSocket": {"port": 8443}, "periodSeconds": 1}
                            if mode == "gateway" else None),
            env=([{"name": "SAF_FIXTURE_IMAGE", "value": image}] if mode == "gateway" else []),
            volumeMounts=[
                {"name": "code", "mountPath": "/fixture", "readOnly": True},
                {"name": "svid", "mountPath": "/run/svid", "readOnly": True},
            ],
            resources={"requests": {"cpu": "25m", "memory": "32Mi"},
                       "limits": {"cpu": "150m", "memory": "128Mi"}})],
        "volumes": [
            {"name": "sockets", "hostPath": {"path": "/run/spire/saf-0910-016",
                                                 "type": "Directory"}},
            {"name": "svid", "emptyDir": {"medium": "Memory"}},
            {"name": "code", "configMap": {"name": APP_CODE}},
        ],
    })
    target.create(pod)


def fetcher_failure_category(target, name):
    # Do not send Workload API output through the command transcript.
    try:
        result = subprocess.run(target.argv("logs", name, "-c", "fetcher", "--limit-bytes=4096", timeout=15),
                                text=True, capture_output=True, env=target.lab.env, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return "capture-unavailable"
    if result.returncode:
        return "logs-unavailable"
    output = result.stdout.lower()
    categories = (
        ("invalid-cli", ("flag provided but not defined", "unknown flag", "invalid value", "usage of")),
        ("socket-unavailable", ("connection refused", "dial unix", "transport is closing")),
        ("workload-identity-unavailable", ("no identity issued", "not authorized", "no x509-svid", "workload svid", "no identity")),
        ("destination-permission", ("permission denied", "read-only file system")),
        ("missing-path", ("no such file or directory",)),
        ("fetch-deadline", ("deadline exceeded", "timed out", "timeout")),
    )
    for category, signatures in categories:
        if any(signature in output for signature in signatures):
            return category
    return "empty" if not output.strip() else "unclassified"


def wait_pod(target, name, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = target.kubectl("get", "pod", name, "-o", "json", allow_failure=True)
        if result.returncode == 0:
            phase = json.loads(result.stdout).get("status", {}).get("phase")
            if phase == "Running":
                return
            if phase == "Failed":
                category = fetcher_failure_category(target, name)
                target.lab.block(f"Owned SPIRE identity fixture {name} failed before readiness ({category})")
        time.sleep(0.5)
    category = fetcher_failure_category(target, name)
    target.lab.block(f"Owned SPIRE identity fixture {name} did not become ready ({category})")


def workload_report(target, name, expected_uri, container_name="orchestrator"):
    raw = target.kubectl("exec", name, "-c", container_name, "--", "python",
                         "/fixture/spire_orchestration.py", "identity", expected_uri,
                         timeout=15).stdout
    try:
        value = json.loads(raw)
    except ValueError:
        target.lab.block("SPIRE workload returned no normalized identity report")
    return value


def prepare_kubelets(lab, peer_info):
    local = Cluster(lab, lab.cluster, lab.kubeconfig, "kind-" + lab.cluster)
    peer = Cluster(lab, peer_info["name"], peer_info["kubeconfig"], peer_info["context"])
    return kubelet_serving_csr(local), kubelet_serving_csr(peer)


def run(lab, peer_kubectl, peer_address, peer_info, image, workload_image, kubelet_csrs):
    local = Cluster(lab, lab.cluster, lab.kubeconfig, "kind-" + lab.cluster)
    peer = Cluster(lab, peer_info["name"], peer_info["kubeconfig"], peer_info["context"])
    code = HERE / "spire_orchestration.py"
    for target in (local, peer):
        target.create(row("ConfigMap", APP_CODE, immutable=True,
                          data={"spire_orchestration.py": code.read_text()}))
    local_node_info = json.loads(lab.command("docker", "inspect", "--format",
        '{{json (index .NetworkSettings.Networks "kind")}}',
        peer_info["source_node"]).stdout)
    peer_address = private_address(peer_address)
    source_address = private_address(peer_info["source_address"])
    if (local_node_info.get("NetworkID") != peer_info.get("network_id")
            or local_node_info.get("IPAddress") != source_address):
        lab.block("The two SPIRE endpoints are not on the same owned Kind bridge")

    csr_source, csr_peer = kubelet_csrs

    # Install each server first to obtain its independent public root. Bundle
    # bytes remain in memory, then pass through mode-0600 ConfigMap source files.
    bundle_source, roots_source = install_server(local, SOURCE_DOMAIN, SOURCE_CLUSTER_ID)
    bundle_peer, roots_peer = install_server(peer, PEER_DOMAIN, PEER_CLUSTER_ID)
    replace_bootstrap(local, bundle_peer)
    replace_bootstrap(peer, bundle_source)

    parent_source = install_agent(local, SOURCE_DOMAIN, SOURCE_CLUSTER_ID,
                                  "/run/spire/saf-0910-016", bundle_source)
    parent_peer = install_agent(peer, PEER_DOMAIN, PEER_CLUSTER_ID,
                                "/run/spire/saf-0910-016", bundle_peer)
    nodeport_source = service_nodeport(local)
    nodeport_peer = service_nodeport(peer)
    roots_b_at_source = federation(local, PEER_DOMAIN,
        f"https://{peer_address}:{nodeport_peer}", f"spiffe://{PEER_DOMAIN}/spire/server")
    roots_a_at_peer = federation(peer, SOURCE_DOMAIN,
        f"https://{source_address}:{nodeport_source}", f"spiffe://{SOURCE_DOMAIN}/spire/server")
    if roots_b_at_source != roots_peer or roots_a_at_peer != roots_source:
        lab.block("SPIRE federation did not bind both trust domains to their exact source roots")

    # The peer Gateway SA and its exact Deployment Role are already created by
    # the preserved 0910-016 setup; this creates no additional authorization.
    for pod_name, service_account, uri, label in (
        (APPROVED_POD, APPROVED_SA, APPROVED_URI, APPROVED_POD),
        (ALTERNATE_POD, ALTERNATE_SA, ALTERNATE_URI, ALTERNATE_POD),
    ):
        register(local, parent_source, uri, service_account, label, "fetcher", PEER_DOMAIN)
        create_workload_pod(local, pod_name, service_account, workload_image, "client", label)
    register(peer, parent_peer, GATEWAY_URI, GATEWAY_SA, GATEWAY_POD, "fetcher", SOURCE_DOMAIN)
    create_workload_pod(peer, GATEWAY_POD, GATEWAY_SA, workload_image, "gateway", GATEWAY_POD)

    # This helper writes only the NodePort service for the one owned gateway.
    peer.create(row("Service", GATEWAY_SERVICE, spec={"type": "NodePort",
        "selector": {"app": GATEWAY_POD},
        "ports": [{"name": "mtls", "port": 8443, "targetPort": 8443}]}))
    gateway_service = json.loads(peer.kubectl("get", "service", GATEWAY_SERVICE, "-o", "json").stdout)
    gateway_port = gateway_service["spec"]["ports"][0]["nodePort"]
    if not 30000 <= gateway_port <= 32767:
        lab.block("SPIRE gateway NodePort is outside the Kubernetes assigned range")

    wait_pod(local, APPROVED_POD)
    wait_pod(local, ALTERNATE_POD)
    wait_pod(peer, GATEWAY_POD)
    peer.kubectl("wait", "--for=condition=Ready", f"pod/{GATEWAY_POD}", "--timeout=90s",
                  timeout=100)
    approved_identity = workload_report(local, APPROVED_POD, APPROVED_URI)
    alternate_identity = workload_report(local, ALTERNATE_POD, ALTERNATE_URI)
    source_foreign = approved_identity.get("foreign_bundle_roots", [])
    peer_identity = workload_report(peer, GATEWAY_POD, GATEWAY_URI, "gateway")
    issuance_ok = (
        approved_identity.get("spiffe_id") == APPROVED_URI
        and alternate_identity.get("spiffe_id") == ALTERNATE_URI
        and peer_identity.get("spiffe_id") == GATEWAY_URI
        and approved_identity.get("valid_now") is True
        and alternate_identity.get("valid_now") is True
        and peer_identity.get("valid_now") is True
        and approved_identity.get("short_lived") is True
        and alternate_identity.get("short_lived") is True
        and peer_identity.get("short_lived") is True
    )
    trust_ok = (source_foreign == roots_peer and peer_identity.get("foreign_bundle_roots") == roots_source)

    # Ensure the earlier fixture placement is removed before the SPIRE-backed
    # request recreates the same exact name under the same native VAP.
    old = peer.kubectl("get", "deployment", WORKLOAD, "-o", "json", allow_failure=True)
    if old.returncode == 0:
        old_obj = json.loads(old.stdout)
        if (old_obj.get("metadata", {}).get("labels", {}).get("saf-fixture") != "0910-016"
                or old_obj.get("metadata", {}).get("name") != WORKLOAD):
            lab.block("Refusing to remove a placement not owned by the exact fixture")
        peer.kubectl("delete", "deployment", WORKLOAD, "--wait=true", "--timeout=25s", timeout=35)
    elif "NotFound" not in old.stderr:
        lab.block("Could not inspect the existing exact fixture placement")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        remaining = peer.kubectl("get", "deployment", WORKLOAD, "-o", "json", allow_failure=True)
        if remaining.returncode and "NotFound" in remaining.stderr:
            break
        time.sleep(0.25)

    readiness = time.monotonic() + 35
    ready = None
    while time.monotonic() < readiness:
        ready = local.kubectl("exec", APPROVED_POD, "-c", "orchestrator", "--", "python",
            "/fixture/spire_orchestration.py", "probe", peer_address, str(gateway_port),
            GATEWAY_URI, "fixture-readiness", NS, timeout=15, allow_failure=True)
        try:
            if json.loads(ready.stdout) == {"ready": True}:
                break
        except ValueError:
            pass
        time.sleep(0.5)
    ready_ok = bool(ready and ready.returncode == 0 and json.loads(ready.stdout) == {"ready": True})

    alternate_request = local.kubectl("exec", ALTERNATE_POD, "-c", "orchestrator", "--", "python",
        "/fixture/spire_orchestration.py", "probe", peer_address, str(gateway_port),
        GATEWAY_URI, WORKLOAD, NS, timeout=15, allow_failure=True)
    try:
        alternate_result = json.loads(alternate_request.stdout)
    except ValueError:
        alternate_result = {"decision": "no-result"}
    refused_absent = peer.kubectl("get", "deployment", WORKLOAD, "-o", "json",
                                  allow_failure=True).returncode != 0

    approved_request = local.kubectl("exec", APPROVED_POD, "-c", "orchestrator", "--", "python",
        "/fixture/spire_orchestration.py", "probe", peer_address, str(gateway_port),
        GATEWAY_URI, WORKLOAD, NS, timeout=15, allow_failure=True)
    try:
        approved_result = json.loads(approved_request.stdout)
    except ValueError:
        approved_result = {"decision": "no-result"}
    if approved_result.get("status") == 201:
        peer.kubectl("rollout", "status", "deployment/" + WORKLOAD,
                     "--timeout=60s", timeout=70, allow_failure=True)
    persisted = peer.kubectl("get", "deployment", WORKLOAD, "-o", "json", allow_failure=True)
    persisted_ok = False
    if persisted.returncode == 0:
        obj = json.loads(persisted.stdout)
        pod_spec = obj.get("spec", {}).get("template", {}).get("spec", {})
        persisted_ok = (obj.get("metadata", {}).get("name") == WORKLOAD
                        and obj.get("metadata", {}).get("namespace") == NS
                        and obj.get("metadata", {}).get("labels", {}).get("saf-fixture") == "0910-016"
                        and pod_spec.get("automountServiceAccountToken") is False)

    gateway_log = peer.kubectl("logs", "pod/" + GATEWAY_POD, "-c", "gateway").stdout
    events = []
    for line in gateway_log.splitlines():
        if line.startswith("{"):
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    expected_event = {"event": "orchestration", "principal": APPROVED_URI,
        "decision": "created", "target_cluster": "peer", "namespace": NS,
        "name": WORKLOAD, "api_status": 201, "peer_certificate_authenticated": True,
        "tls_version_is_1_3": True, "server_identity_verified": True}
    event_ok = expected_event in events
    admission_ok = (
        json.loads(peer.kubectl("get", "validatingadmissionpolicy", "fixture-exact-orchestration-placement",
                                "-o", "json").stdout)["metadata"]["name"]
        == "fixture-exact-orchestration-placement"
        and json.loads(peer.kubectl("get", "validatingadmissionpolicybinding",
            "fixture-exact-orchestration-placement", "-o", "json").stdout)
            ["spec"]["validationActions"] == ["Deny"]
    )
    observed = {
        "both_kubelet_serving_csrs_bound_to_owned_nodes": (
            csr_source["node_name_matches"] and csr_source["internal_ip_matches_csr"]
            and csr_peer["node_name_matches"] and csr_peer["internal_ip_matches_csr"]),
        "both_agents_attested_and_three_svids_match_exact_selectors": issuance_ok,
        "two_way_federation_roots_match_the_other_issuer": trust_ok,
        "mTLS_readiness_uses_the_exact_peer_gateway_svid": ready_ok,
        "same_domain_alternate_svid_refused_before_target_write": (
            alternate_result == {"status": 403, "decision": "refused",
                                  "principal": ALTERNATE_URI, "server_identity_verified": True}
            and refused_absent),
        "approved_svid_created_exact_peer_placement": (
            approved_result == {"status": 201, "decision": "created",
                                 "principal": APPROVED_URI, "server_identity_verified": True}
            and persisted_ok),
        "native_peer_admission_remains_active": admission_ok,
        "gateway_event_binds_svid_to_api_result": event_ok,
    }
    lab.check("positive", "SPIRE-issued federated mTLS identity authorizes only the exact peer placement",
              all(observed.values()), observed)
    return {"issuer_and_federation": observed,
            "source_roots_sha256": roots_source, "peer_roots_sha256": roots_peer,
            "source_api_cluster": local.name, "peer_api_cluster": peer.name,
            "gateway_event_count": len(events)}
