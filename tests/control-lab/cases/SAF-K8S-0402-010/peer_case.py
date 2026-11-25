"""Own the second v1.37 Kind fixture and exact public-root exchange."""
import json
import re
import subprocess
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes


NODE_IMAGE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
NAMESPACE = "saf-0402-010-peer"
NAMESPACE_A = "saf-0402-010-pcr"
DOMAIN_A = "identity.example.test"
SIGNER_A = f"{DOMAIN_A}/pod-workload"
CTB_A = "identity.example.test:pod-workload:selected"
IMPORT_A = "identity.example.test:pod-workload:peer-a"
DOMAIN_B = "domain-b.fixture.invalid"
SIGNER_B = f"{DOMAIN_B}/pod-workload"
CTB_B = "domain-b.fixture.invalid:pod-workload:root"
IMPORT_B = "domain-b.fixture.invalid:pod-workload:peer-b"
LABEL_KEY = "saf-k8s.example/peer-root"
NODE_PORT = 30443


class PeerLab:
    def __init__(self, parent, cluster, kubeconfig):
        self.parent = parent
        self.cluster = cluster
        self.kubeconfig = kubeconfig
        self.env = parent.env
        self.evidence = parent.evidence

    def block(self, reason):
        self.parent.block(reason)

    def kubectl(self, *args, payload=None, allow_failure=False, timeout=45):
        command = ["kubectl", "--kubeconfig", str(self.kubeconfig), "--context", f"kind-{self.cluster}",
                   f"--request-timeout={max(1, timeout - 5)}s", *args]
        try:
            result = subprocess.run(command, input=payload, text=True, capture_output=True,
                                    env=self.env, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            self.block(f"Owned peer-cluster API request failed: {type(error).__name__}")
        if result.returncode and not allow_failure:
            self.block("Owned peer-cluster API request returned nonzero")
        return result

    def create(self, obj):
        result = self.kubectl("create", "-f", "-", "-o", "json", payload=json.dumps(obj))
        return json.loads(result.stdout)


def _call(lab, *args, payload=None, timeout=45, allow_failure=False):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               f"--request-timeout={max(1, timeout - 5)}s", *args]
    try:
        result = subprocess.run(command, input=payload, text=True, capture_output=True,
                                env=lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Owned peer-cluster API request failed: {type(error).__name__}")
    if result.returncode and not allow_failure:
        lab.block("Owned peer-cluster API request returned nonzero")
    return result


def _pem_fingerprints(bundle, *, placeholder=False):
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", bundle.encode(), re.S)
    if not blocks:
        raise ValueError("No public CA certificate in fixture trust bundle")
    values = []
    for block in blocks:
        cert = x509.load_pem_x509_certificate(block)
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Fixture trust bundle contains a non-CA certificate")
        if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
            raise ValueError("Fixture trust bundle CA cannot sign certificates")
        if not placeholder:
            cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        values.append(cert.fingerprint(hashes.SHA256()).hex())
    return values


def _inspect_node(lab, name):
    try:
        result = subprocess.run(["docker", "inspect", name], capture_output=True, text=True,
                                env=lab.env, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Owned Kind node inspection failed: {type(error).__name__}")
    if result.returncode:
        lab.block("Owned Kind node inspection returned nonzero")
    try:
        item = json.loads(result.stdout)[0]
        network = item["NetworkSettings"]["Networks"]["kind"]
        return network["NetworkID"], network["IPAddress"]
    except (ValueError, KeyError, IndexError, TypeError):
        lab.block("Owned Kind node is not attached to the expected kind network")


def _node_ip(lab, cluster):
    item = json.loads(_call(lab, "get", "node", f"{cluster}-control-plane", "-o", "json").stdout)
    values = [a["address"] for a in item["status"]["addresses"] if a["type"] == "InternalIP"]
    if len(values) != 1:
        lab.block("Expected one internal fixture node address")
    return values[0]


def _bundle(name, signer, label_value, pem):
    return {"apiVersion": "certificates.k8s.io/v1", "kind": "ClusterTrustBundle",
            "metadata": {"name": name, "labels": {LABEL_KEY: label_value}},
            "spec": {"signerName": signer, "trustBundle": pem}}


def _put_exact_bundle(lab, name, signer, label_value, pem):
    current = json.loads(_call(lab, "get", "clustertrustbundle", name, "-o", "json").stdout)
    current_spec = current.get("spec", {})
    current_labels = current.get("metadata", {}).get("labels", {})
    if (current.get("metadata", {}).get("name") != name
            or current_spec.get("signerName") != signer
            or current_labels.get(LABEL_KEY) != label_value):
        lab.block("The exact pre-created peer CTB did not match the approved signer and label")
    body = _bundle(name, signer, label_value, pem)
    body["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
    result = _call(lab, "replace", "-f", "-", "-o", "name", payload=json.dumps(body))
    return result.returncode == 0


def _rbac_objects():
    return [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "peer-server", "namespace": NAMESPACE},
         "automountServiceAccountToken": False},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "podcert-test-signer", "namespace": NAMESPACE}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
         "metadata": {"name": "peer-signer", "namespace": NAMESPACE},
         "rules": [
             {"apiGroups": ["certificates.k8s.io"], "resources": ["podcertificaterequests"], "verbs": ["list"]},
             {"apiGroups": ["certificates.k8s.io"], "resources": ["podcertificaterequests/status"], "verbs": ["update"]},
             {"apiGroups": [""], "resources": ["pods"], "resourceNames": ["peer-server"], "verbs": ["get"]},
             {"apiGroups": [""], "resources": ["serviceaccounts"], "resourceNames": ["peer-server"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
         "metadata": {"name": "peer-signer", "namespace": NAMESPACE},
         "subjects": [{"kind": "ServiceAccount", "name": "podcert-test-signer", "namespace": NAMESPACE}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "peer-signer"}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": {"name": "peer-signer"},
         "rules": [
             {"apiGroups": ["certificates.k8s.io"], "resources": ["signers"],
              "resourceNames": [SIGNER_B], "verbs": ["sign", "attest"]},
             {"apiGroups": ["certificates.k8s.io"], "resources": ["clustertrustbundles"],
              "resourceNames": [CTB_B], "verbs": ["get", "update"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
         "metadata": {"name": "peer-signer"},
         "subjects": [{"kind": "ServiceAccount", "name": "podcert-test-signer", "namespace": NAMESPACE}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "peer-signer"}},
    ]


def _signer_pod(node, image):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "podcert-test-signer", "namespace": NAMESPACE},
            "spec": {"restartPolicy": "Never", "serviceAccountName": "podcert-test-signer",
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "signer", "image": image, "imagePullPolicy": "Never",
                                     "command": ["python", "/opt/fixture/signer.py"],
                                     "env": [
                                         {"name": "EXPECTED_NODE_NAME", "value": node["metadata"]["name"]},
                                         {"name": "EXPECTED_NODE_UID", "value": node["metadata"]["uid"]},
                                         {"name": "FIXTURE_DOMAIN", "value": DOMAIN_B},
                                         {"name": "FIXTURE_NAMESPACE", "value": NAMESPACE},
                                         {"name": "FIXTURE_POD_NAME", "value": "peer-server"},
                                         {"name": "FIXTURE_WORKLOAD_SA", "value": "peer-server"},
                                         {"name": "FIXTURE_SIGNER_NAME", "value": SIGNER_B},
                                         {"name": "FIXTURE_CTB_NAME", "value": CTB_B},
                                         {"name": "FIXTURE_CTB_LABEL", "value": "domain-b"},
                                         {"name": "FIXTURE_SERVER_DNS", "value": "peer-b.fixture.invalid"}],
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def _server_pod(image):
    volumes = [{"name": "identity", "projected": {"sources": [{"podCertificate": {
        "signerName": SIGNER_B, "keyType": "ECDSAP256", "maxExpirationSeconds": 3600,
        "credentialBundlePath": "credential.pem"}}]}},
        {"name": "roots", "projected": {"sources": [
            {"clusterTrustBundle": {"signerName": SIGNER_A,
                                     "labelSelector": {"matchLabels": {LABEL_KEY: "domain-a"}},
                                     "path": "domain-a.pem", "optional": True}},
            {"clusterTrustBundle": {"signerName": SIGNER_B,
                                     "labelSelector": {"matchLabels": {LABEL_KEY: "domain-b"}},
                                     "path": "domain-b.pem", "optional": True}}]}},
        {"name": "negative-scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}},
        {"name": "server-readiness", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "peer-server", "namespace": NAMESPACE,
            "labels": {"app": "peer-server"}}, "spec": {"restartPolicy": "Never", "serviceAccountName": "peer-server",
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": volumes,
            "containers": [
                {"name": "server", "image": image, "imagePullPolicy": "Never",
                 "command": ["python", "/opt/fixture/peer_server.py"],
                 "ports": [{"name": "tls", "containerPort": 8443}],
                 "readinessProbe": {"exec": {"command": ["test", "-f", "/run/saf-peer-ready/ready"]},
                                    "periodSeconds": 2, "failureThreshold": 75},
                 "volumeMounts": [{"name": "identity", "mountPath": "/var/run/pod-identity", "readOnly": True},
                                  {"name": "roots", "mountPath": "/var/run/peer-trust", "readOnly": True},
                                  {"name": "server-readiness", "mountPath": "/run/saf-peer-ready"}],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}},
                {"name": "wrong-subject", "image": image, "imagePullPolicy": "Never",
                 "command": ["python", "/opt/fixture/peer_wrong_subject.py"],
                 "volumeMounts": [{"name": "identity", "mountPath": "/var/run/pod-identity", "readOnly": True},
                                  {"name": "roots", "mountPath": "/var/run/peer-trust", "readOnly": True}],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}},
                {"name": "wrong-issuer", "image": image, "imagePullPolicy": "Never",
                 "command": ["python", "/opt/fixture/peer_foreign_issuer.py"],
                 "volumeMounts": [{"name": "roots", "mountPath": "/var/run/peer-trust", "readOnly": True},
                                  {"name": "negative-scratch", "mountPath": "/run/saf-negative"}],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}]}}


def _log_objects(lab, pod, container, namespace=NAMESPACE):
    result = _call(lab, "logs", f"pod/{pod}", "-n", namespace, "-c", container,
                   allow_failure=True, timeout=20)
    if result.returncode:
        return []
    values = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            lab.block("Peer fixture emitted unexpected non-JSON output")
        if not isinstance(item, dict):
            lab.block("Peer fixture emitted an unexpected result object")
        values.append(item)
    return values


class PeerRun:
    def __init__(self, lab, cluster, kubeconfig, image, peer_ip):
        self.lab = lab
        self.cluster = cluster
        self.kubeconfig = kubeconfig
        self.peer = PeerLab(lab, cluster, kubeconfig)
        self.image = image
        self.peer_ip = peer_ip
        self.owned = False
        self.checked = False
        self.placeholder_a = None
        self.root_a = None
        self.root_b = None

    @classmethod
    def create(cls, lab, image, kubeconfig):
        cluster = f"{lab.cluster}-peer"
        return cls(lab, cluster, kubeconfig, image, "")

    def cleanup(self):
        try:
            if self.owned:
                clusters = self.lab.command("kind", "get", "clusters").stdout.splitlines()
                if self.cluster in clusters:
                    # Cluster deletion is scoped by the collision-checked unique
                    # name and inherited Docker context. `kind delete cluster`
                    # does not need a kubeconfig and accepts no API operations.
                    self.lab.command("kind", "delete", "cluster", "--name", self.cluster,
                                     timeout=90)
                self.owned = False
        finally:
            self.kubeconfig.unlink(missing_ok=True)

    def bootstrap(self):
        clusters = self.lab.command("kind", "get", "clusters").stdout.splitlines()
        if self.cluster in clusters:
            self.lab.block("The exact disposable peer cluster name is already in use")
        self.owned = True
        self.lab.command("kind", "create", "cluster", "--name", self.cluster, "--image", NODE_IMAGE,
                         "--kubeconfig", str(self.kubeconfig), "--wait", "90s", timeout=480)
        self.lab.command("kind", "load", "docker-image", self.image, "--name", self.cluster, timeout=120)
        b_version = json.loads(self.peer.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
        b_node = json.loads(_call(self.peer, "get", "node", f"{self.cluster}-control-plane", "-o", "json").stdout)
        a_node = json.loads(_call(self.lab, "get", "node", f"{self.lab.cluster}-control-plane", "-o", "json").stdout)
        a_network, _ = _inspect_node(self.lab, f"{self.lab.cluster}-control-plane")
        b_network, inspected_ip = _inspect_node(self.lab, f"{self.cluster}-control-plane")
        b_ips = [item["address"] for item in b_node["status"]["addresses"] if item["type"] == "InternalIP"]
        a_ips = [item["address"] for item in a_node["status"]["addresses"] if item["type"] == "InternalIP"]
        node_ok = (a_network == b_network and b_ips == [inspected_ip]
                   and len(a_ips) == 1 and b_node["status"]["nodeInfo"]["kubeletVersion"] == "v1.37.0"
                   and a_node["status"]["nodeInfo"]["kubeletVersion"] == "v1.37.0"
                   and b_version == "v1.37.0")
        if not node_ok:
            self.lab.block("Pinned peer cluster or shared Kind node-network preflight failed")
        self.peer_ip = inspected_ip
        self.lab.check("positive", "A and B are pinned v1.37.0 clusters on the same inspected kind node network",
                       node_ok, {"a_version": "v1.37.0", "b_version": b_version,
                                 "shared_kind_network": a_network == b_network,
                                 "peer_node_ip_matches_internal": b_ips == [inspected_ip]})

        # The current A CTB is a public synthetic CA created by the existing trust-bundle fixture.
        source_a = json.loads(_call(self.lab, "get", "clustertrustbundle", CTB_A, "-o", "json").stdout)
        if (source_a.get("metadata", {}).get("name") != CTB_A
                or source_a.get("spec", {}).get("signerName") != SIGNER_A
                or source_a.get("metadata", {}).get("labels", {}).get("saf-k8s.example/track") != "selected"):
            self.lab.block("A's named source CTB did not match the approved synthetic signer selection")
        self.placeholder_a = source_a["spec"]["trustBundle"]
        for obj in _rbac_objects():
            self.peer.create(obj)
        self.root_b_placeholder = _pem_fingerprints(self.placeholder_a, placeholder=True)
        self.peer.create(_bundle(CTB_B, SIGNER_B, "domain-b", self.placeholder_a))
        self.peer.create(_bundle(IMPORT_A, SIGNER_A, "domain-a", self.placeholder_a))
        # Pre-create the exact remote-B object in A so the workload projection can be declared now.
        self.lab.create(_bundle(IMPORT_B, SIGNER_B, "domain-b", self.placeholder_a))

        self.peer.create(_signer_pod(b_node, self.image))
        self.peer.kubectl("wait", "--for=condition=Ready", "pod/podcert-test-signer", "-n", NAMESPACE,
                          "--timeout=90s", timeout=100)
        self.root_b = self.wait_published_root(self.peer, CTB_B, SIGNER_B, "domain-b", self.root_b_placeholder)
        self._replace_bundle(self.lab, IMPORT_B, SIGNER_B, "domain-b", self.root_b)
        b_import_ok = self._check_bundle(self.lab, IMPORT_B, SIGNER_B, "domain-b", self.root_b)
        self.lab.check("green", "B's exact public issuer root is enrolled in A's named peer CTB",
                       b_import_ok, {"approved_source_root_matches": b_import_ok})

    def wait_published_root(self, lab, name, signer, label_value, old_fingerprints):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = _call(lab, "get", "clustertrustbundle", name, "-o", "json", allow_failure=True)
            if result.returncode == 0:
                item = json.loads(result.stdout)
                spec, labels = item.get("spec", {}), item.get("metadata", {}).get("labels", {})
                if spec.get("signerName") == signer and labels.get(LABEL_KEY) == label_value:
                    current = spec.get("trustBundle", "")
                    try:
                        fingerprints = _pem_fingerprints(current)
                    except Exception:
                        fingerprints = []
                    if len(fingerprints) == 1 and fingerprints != old_fingerprints:
                        return current
            time.sleep(1)
        self.lab.block("The exact fixture signer did not publish its expected public root")

    def _replace_bundle(self, lab, name, signer, label_value, pem):
        if not _put_exact_bundle(lab, name, signer, label_value, pem):
            lab.block("The exact approved peer CTB update failed")

    def _check_bundle(self, lab, name, signer, label_value, expected_pem):
        item = json.loads(_call(lab, "get", "clustertrustbundle", name, "-o", "json").stdout)
        spec, labels = item.get("spec", {}), item.get("metadata", {}).get("labels", {})
        return (spec.get("signerName") == signer and labels.get(LABEL_KEY) == label_value
                and _pem_fingerprints(spec.get("trustBundle", "")) == _pem_fingerprints(expected_pem))

    def publish_a_root_and_start_server(self):
        old_fp = _pem_fingerprints(self.placeholder_a, placeholder=True)
        self.root_a = self.wait_published_root(self.lab, CTB_A, SIGNER_A, "domain-a", old_fp)
        self._replace_bundle(self.peer, IMPORT_A, SIGNER_A, "domain-a", self.root_a)
        a_import_ok = self._check_bundle(self.peer, IMPORT_A, SIGNER_A, "domain-a", self.root_a)
        self.lab.check("green", "A's exact public issuer root is enrolled in B's named peer CTB",
                       a_import_ok, {"approved_source_root_matches": a_import_ok})

        server = _server_pod(self.image)
        self.peer.create(server)
        service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "peer-server", "namespace": NAMESPACE},
                   "spec": {"type": "NodePort", "selector": {"app": "peer-server"},
                            "ports": [{"name": "tls", "port": 8443, "targetPort": 8443,
                                       "protocol": "TCP", "nodePort": NODE_PORT}]}}
        self.peer.create(service)
        self.peer.kubectl("wait", "--for=condition=Ready", "pod/peer-server", "-n", NAMESPACE,
                          "--timeout=180s", timeout=190)
        svc = json.loads(self.peer.kubectl("get", "service/peer-server", "-n", NAMESPACE, "-o", "json").stdout)
        server_events = _log_objects(self.peer, "peer-server", "server")
        server_identity = [event for event in server_events
                           if event.get("server_identity_valid") is True]
        inspected = self.lab.command("docker", "inspect", f"{self.cluster}-control-plane",
                                     "--format", "{{json .HostConfig.PortBindings}}").stdout
        bindings = json.loads(inspected) or {}
        no_host_mapping = not bindings.get(f"{NODE_PORT}/tcp")
        service_ok = (svc["spec"]["type"] == "NodePort"
                      and svc["spec"]["ports"][0]["nodePort"] == NODE_PORT
                      and not svc["spec"].get("externalIPs")
                      and svc["spec"].get("externalTrafficPolicy") == "Cluster" and no_host_mapping
                      and len(server_identity) == 1
                      and server_identity[0].get("trust_roots_selected") == 2)
        if not service_ok:
            self.lab.block("The exact private fixture NodePort service did not match policy")
        self.lab.check("positive", "B exposes only its fixture NodePort Service without host port publication",
                       service_ok, {"node_port": NODE_PORT, "host_mapping": not no_host_mapping,
                                    "server_identity_and_two_roots_valid": len(server_identity) == 1
                                    and server_identity[0].get("trust_roots_selected") == 2})

    def observe_peer_results(self):
        if self.checked:
            return True
        client = _log_objects(self.lab, "authorized-workload", "peer-client", namespace=NAMESPACE_A)
        server = _log_objects(self.peer, "peer-server", "server")
        wrong_subject = _log_objects(self.peer, "peer-server", "wrong-subject")
        wrong_issuer = _log_objects(self.peer, "peer-server", "wrong-issuer")
        # Apply a bounded, sanitized gate as soon as the foreign probe reports.
        # This distinguishes B's TLS 1.3 unknown-CA alert from any generic SSL,
        # server-identity, URI, or transport failure without retaining details.
        if wrong_issuer and "tls_error_class" in wrong_issuer[-1]:
            early = wrong_issuer[-1]
            if (early.get("foreign_chain_structurally_valid") is not True
                    or early.get("foreign_issuer_not_in_b_trust") is not True
                    or early.get("tls_protocol_forced_v1_3") is not True
                    or early.get("tls_error_class") != "TLSV1_ALERT_UNKNOWN_CA"
                    or early.get("tls_alert_received_from_b") is not True):
                self.lab.block("B foreign-issuer probe failed its structural-chain or exact TLS alert gate")
        if client and "mutual_tls_allowed" in client[-1] and client[-1].get("mutual_tls_allowed") is not True:
            self.lab.block("A's authorized workload failed its strict B TLS identity gate")
        if not client or not server or not wrong_subject or not wrong_issuer:
            return False
        client_result = client[-1]
        if not client_result.get("node_ip_configured"):
            self.lab.block("A's peer client did not receive the exact inspected B node IP")
        if not client_result.get("mutual_tls_allowed"):
            self.lab.block("The A-to-B NodePort TLS gate failed before peer authorization; no peer-policy claim is made")
        server_rows = [item for item in server if "tls_authenticated" in item]
        allowed = [item for item in server_rows if item.get("tls_authenticated") and item.get("subject_allowed")]
        denied_subject = [item for item in server_rows if item.get("tls_authenticated") and not item.get("subject_allowed")]
        rejected_issuer = [item for item in server_rows if item.get("unknown_client_issuer") is True]
        start = [item for item in server if item.get("server_identity_valid") is True]
        self.lab.check("green", "A's in-Pod workload certificate proves mutual TLS, exact B SNI/URI, and B allows exact A URI",
                       client_result.get("mutual_tls_allowed") and len(allowed) == 1 and len(start) == 1,
                       {key: bool(client_result.get(key)) for key in
                        ("tls_established", "server_sni_verified", "server_uri_verified", "server_authorized_client")}
                       | {"server_authorized_exact_peer": len(allowed) == 1})

        wrong_issuer_result = wrong_issuer[-1]
        if (wrong_issuer_result.get("foreign_chain_structurally_valid") is not True
                or wrong_issuer_result.get("foreign_issuer_not_in_b_trust") is not True
                or wrong_issuer_result.get("tls_protocol_forced_v1_3") is not True
                or wrong_issuer_result.get("tls_error_class") != "TLSV1_ALERT_UNKNOWN_CA"):
            # Fail immediately with the sanitized enum only. Do not retain or surface
            # free-form OpenSSL errors, certificate data, or key material.
            self.lab.block("B foreign-issuer probe failed its structural-chain or exact TLS alert gate")
        issuer_ok = (wrong_issuer_result.get("expected_uri") is True
                     and wrong_issuer_result.get("foreign_chain_structurally_valid") is True
                     and wrong_issuer_result.get("foreign_issuer_tls_rejected") is True
                     and wrong_issuer_result.get("tls_alert_received_from_b") is True
                     and len(rejected_issuer) == 1)
        self.lab.check("red", "A-like subject from the unexchanged synthetic issuer is rejected during B TLS authentication",
                       issuer_ok, {"issuer_rejected": issuer_ok})

        wrong_subject_result = wrong_subject[-1]
        subject_ok = (wrong_subject_result.get("tls_authenticated") is True
                      and wrong_subject_result.get("server_identity_valid") is True
                      and wrong_subject_result.get("wrong_subject_denied") is True
                      and len(denied_subject) == 1)
        self.lab.check("red", "B authenticates its trusted B-issued certificate then denies the non-A URI subject",
                       subject_ok, {"trusted_peer_authenticated": wrong_subject_result.get("tls_authenticated") is True,
                                    "subject_policy_denied": wrong_subject_result.get("wrong_subject_denied") is True})
        self.checked = True
        (self.lab.evidence / "peer-nodeport-observations.json").write_text(json.dumps({
            "clusters_v1_37": True, "shared_kind_network": True,
            "a_to_b_mutual_tls_allow": True, "foreign_issuer_rejected": issuer_ok,
            "foreign_issuer_error_class": wrong_issuer_result.get("tls_error_class"),
            "trusted_wrong_subject_denied": subject_ok, "private_keys_remained_in_pods": True,
            "credential_material_recorded": False
        }, indent=2) + "\n")
        self.cleanup()
        return True

    def wait_peer_results(self):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if self.observe_peer_results():
                return
            time.sleep(3)
        self.lab.block("The live peer authorization observations did not complete in the fixture window")
