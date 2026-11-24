"""Verify narrowly scoped bearer and approved X.509 kubelet monitoring."""
import base64
import json
import re
import subprocess
import time
import uuid

from lab import NAMESPACE


SCOPE = (
    "One disposable Kubernetes v1.36.1 kind node. Verify the public kubelet "
    "serving chain and hostname, bearer-token and explicitly approved native "
    "X.509 client authentication, and endpoint-specific authorization. Provider, "
    "GPU-node and deployed network controls require separate evidence."
)
ACCOUNT = "kubelet-metrics-reader"
CLIENT_SIGNER = "kubernetes.io/kube-apiserver-client"
NODE_ENDPOINTS = {
    "/healthz": "healthz",
    "/metrics": "metrics",
    "/stats/summary": "stats",
}


def private_run(lab, args, *, input_data=None, timeout=20, allow_failure=False):
    """Run credential-bearing commands without the lab's retained command log."""
    try:
        result = subprocess.run(args, input=input_data, capture_output=True,
                                env=lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        if allow_failure:
            return None
        lab.block(f"Private fixture command failed: {type(error).__name__}")
    if result.returncode and not allow_failure:
        lab.block("A private fixture command did not succeed")
    return result


def kubectl_private(lab, *args, input_data=None, allow_failure=False, timeout=20):
    return private_run(
        lab,
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
         f"kind-{lab.cluster}", f"--request-timeout={timeout - 2}s", *args],
        input_data=input_data, timeout=timeout, allow_failure=allow_failure,
    )


def node_private(lab, node, *args, input_data=None, allow_failure=False):
    return private_run(lab, ["docker", "exec", "-i", node, *args],
                       input_data=input_data, allow_failure=allow_failure)


def mint_token(lab):
    result = kubectl_private(lab, "-n", NAMESPACE, "create", "token", ACCOUNT,
                             "--duration=10m")
    token = result.stdout.decode().strip()
    if not re.fullmatch(r"[\w-]+\.[\w-]+\.[\w-]+", token, re.ASCII):
        lab.block("TokenRequest did not return a monitor credential")
    return token


def effective_tls_settings(lab, node):
    route = f"/api/v1/nodes/{node}/proxy/configz"
    raw = kubectl_private(lab, "get", f"--raw={route}").stdout
    try:
        config = json.loads(raw)["kubeletconfig"]
        certificate = config["tlsCertFile"]
        authentication = config["authentication"]
        ca = authentication["x509"]["clientCAFile"]
    except (ValueError, KeyError, TypeError):
        lab.block("The owned kubelet did not expose its effective serving certificate path")
    if not re.fullmatch(r"/var/lib/kubelet/pki/[A-Za-z0-9_.-]+\.crt", certificate):
        lab.block("The owned kubelet serving certificate path was outside the expected node PKI directory")
    if not re.fullmatch(r"/etc/kubernetes/pki/[A-Za-z0-9_.-]+\.crt", ca):
        lab.block("The owned kubelet client CA path was outside the expected cluster PKI directory")
    webhook = authentication.get("webhook", {}).get("enabled") is True
    authorize = config.get("authorization", {}).get("mode") == "Webhook"
    lab.check("green", "The kubelet uses effective authentication and authorization webhooks",
              webhook and authorize, {"token_review_enabled": webhook, "subject_access_review_enabled": authorize})
    return certificate, ca


def kubelet_status(lab, node, certificate, path, *, token=None, client_files=None):
    args = ["docker", "exec", "-i", node, "/usr/bin/curl", "-q", "--config", "-",
            "--silent", "--show-error", "--noproxy", "*", "--max-time", "5",
            "--request", "GET", "--cacert", certificate, "--resolve",
            f"{node}:10250:127.0.0.1", "--output", "/dev/null", "--write-out",
            "%{http_code} %{ssl_verify_result}"]
    config = []
    if token:
        config.append(f'header = "Authorization: Bearer {token}"')
    if client_files:
        config.extend((f'cert = "{client_files[0]}"', f'key = "{client_files[1]}"'))
    result = private_run(lab, args + [f"https://{node}:10250{path}"],
                         input_data=("\n".join(config) + "\n").encode(), timeout=10)
    fields = result.stdout.decode().strip().split()
    if result.returncode or len(fields) != 2 or not re.fullmatch(r"[1-5][0-9][0-9]", fields[0]):
        lab.block(f"The isolated kubelet did not return a verified HTTPS status for {path}")
    if fields[1] != "0":
        lab.block("The owned kubelet serving certificate did not verify")
    return int(fields[0])


def review(lab, user, groups, node, subresource):
    result = lab.create({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "user": user,
            "groups": groups,
            "resourceAttributes": {
                "verb": "get", "resource": "nodes", "name": node,
                "subresource": subresource,
            },
        },
    })["status"]
    if result.get("evaluationError"):
        lab.block("Kubelet endpoint authorization review could not evaluate the RBAC policy")
    return result["allowed"]


def grant_bearer_monitoring(lab, node):
    api = "rbac.authorization.k8s.io/v1"
    lab.create({
        "apiVersion": api, "kind": "ClusterRole", "metadata": {"name": ACCOUNT},
        "rules": [{
            "apiGroups": [""], "resources": [f"nodes/{part}" for part in NODE_ENDPOINTS.values()],
            "resourceNames": [node], "verbs": ["get"],
        }],
    })
    lab.create({
        "apiVersion": api, "kind": "ClusterRoleBinding", "metadata": {"name": ACCOUNT},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": ACCOUNT},
        "subjects": [{"kind": "ServiceAccount", "name": ACCOUNT, "namespace": NAMESPACE}],
    })


def verify_x509_monitor(lab, node, serving_cert, client_ca):
    suffix = uuid.uuid4().hex[:10]
    username = f"saf-kubelet-health-monitor-{suffix}"
    csr_name = f"saf-kubelet-health-{suffix}"
    node_dir = f"/run/{csr_name}"
    client_key = f"{node_dir}/client.key"
    client_csr = f"{node_dir}/client.csr"
    client_cert = f"{node_dir}/client.crt"
    role_name = f"saf-kubelet-healthz-{suffix}"
    role_created = False
    csr_created = False
    key_directory_owned = False
    try:
        # Key and CSR are generated on the disposable node; neither is printed or logged.
        node_private(lab, node, "mkdir", "-m", "0700", node_dir)
        key_directory_owned = True
        node_private(lab, node, "sh", "-ceu",
                     'umask 077; exec openssl req -new -newkey rsa:2048 -nodes '
                     '-keyout "$1" -out "$2" -subj "$3"',
                     "x509-fixture", client_key, client_csr, f"/CN={username}")
        csr_bytes = node_private(lab, node, "cat", client_csr).stdout
        request = {
            "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
            "metadata": {"name": csr_name, "labels": {"saf.example/purpose": "kubelet-monitor-healthz"}},
            "spec": {
                "request": base64.b64encode(csr_bytes).decode("ascii"),
                "signerName": CLIENT_SIGNER, "expirationSeconds": 600,
                "usages": ["digital signature", "key encipherment", "client auth"],
            },
        }
        kubectl_private(lab, "create", "-f", "-", input_data=json.dumps(request).encode())
        csr_created = True
        # Approval is explicit and tied to this run's unique, purpose-labeled CSR.
        kubectl_private(lab, "certificate", "approve", csr_name)
        certificate = b""
        deadline = time.monotonic() + 45
        while not certificate and time.monotonic() < deadline:
            result = kubectl_private(lab, "get", "csr", csr_name,
                                     "-o", "jsonpath={.status.certificate}")
            encoded = result.stdout.strip()
            if encoded:
                certificate = base64.b64decode(encoded, validate=True)
            else:
                time.sleep(0.5)
        if b"-----BEGIN CERTIFICATE-----" not in certificate:
            lab.block("The explicitly approved monitoring CSR did not receive a signed certificate")
        node_private(lab, node, "sh", "-ceu",
                     'umask 077; cat > "$1"; chmod 600 "$1"',
                     "x509-certificate", client_cert, input_data=certificate)

        node_private(lab, node, "openssl", "verify", "-purpose", "sslclient",
                     "-CAfile", client_ca, client_cert)

        groups = ["system:authenticated"]
        denied = kubelet_status(lab, node, serving_cert, "/healthz",
                                client_files=(client_cert, client_key))
        lab.check("red", "The approved X.509 monitor authenticates but starts denied at /healthz",
                  denied == 403, {"http_status": denied, "tls_verified": True})
        allowed_before = review(lab, username, groups, node, "healthz")
        lab.check("green", "The approved X.509 user has no health subresource grant initially",
                  not allowed_before, allowed_before)

        api = "rbac.authorization.k8s.io/v1"
        lab.create({
            "apiVersion": api, "kind": "ClusterRole", "metadata": {"name": role_name},
            "rules": [{"apiGroups": [""], "resources": ["nodes/healthz"],
                       "resourceNames": [node], "verbs": ["get"]}],
        })
        role_created = True
        lab.create({
            "apiVersion": api, "kind": "ClusterRoleBinding",
            "metadata": {"name": role_name},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role_name},
            "subjects": [{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": username}],
        })
        deadline = time.monotonic() + 45
        while True:
            healthy = kubelet_status(lab, node, serving_cert, "/healthz",
                                     client_files=(client_cert, client_key))
            if healthy == 200 or time.monotonic() >= deadline:
                break
            time.sleep(1)
        lab.check("positive", "The approved X.509 monitor can read its named /healthz endpoint",
                  healthy == 200, {"http_status": healthy, "tls_verified": True})
        unused = kubelet_status(lab, node, serving_cert, "/metrics",
                                client_files=(client_cert, client_key))
        lab.check("green", "The X.509 monitor remains denied at unused /metrics",
                  unused == 403, {"http_status": unused, "tls_verified": True})
        permitted = review(lab, username, groups, node, "healthz")
        other = review(lab, username, groups, "unapproved-health-node", "healthz")
        lab.check("positive", "The health grant is present only for the named owned node",
                  permitted and not other, {"on_owned_node": permitted, "on_other_node": other})
        unused_allowed = review(lab, username, groups, node, "metrics")
        lab.check("green", "The X.509 health grant does not allow nodes/metrics",
                  not unused_allowed, unused_allowed)
    finally:
        if role_created:
            kubectl_private(lab, "delete", "clusterrolebinding", role_name, "--ignore-not-found")
            kubectl_private(lab, "delete", "clusterrole", role_name, "--ignore-not-found")
        if csr_created:
            kubectl_private(lab, "delete", "csr", csr_name, "--ignore-not-found")
        if key_directory_owned:
            node_private(lab, node, "rm", "-f", "--", client_key, client_csr, client_cert)
            node_private(lab, node, "rmdir", "--", node_dir)
    lab.check("positive", "The lab removes the case-owned client credential and its authorization objects",
              True, {"owned_client_files_removed": True, "owned_csr_and_rbac_removed": True})


def run(lab):
    lab.kubectl("create", "serviceaccount", ACCOUNT)
    node = f"{lab.cluster}-control-plane"
    serving_cert, client_ca = effective_tls_settings(lab, node)
    token = mint_token(lab)

    status = kubelet_status(lab, node, serving_cert, "/healthz")
    lab.check("red", "A verified HTTPS kubelet health request without credentials is denied",
              status == 401, {"http_status": status, "tls_verified": True})
    for path in NODE_ENDPOINTS:
        status = kubelet_status(lab, node, serving_cert, path, token=token)
        lab.check("red", f"An authenticated bearer monitor without a grant is denied at {path}",
                  status == 403, {"http_status": status, "tls_verified": True})

    grant_bearer_monitoring(lab, node)
    deadline = time.monotonic() + 45
    while True:
        statuses = {path: kubelet_status(lab, node, serving_cert, path, token=token)
                    for path in NODE_ENDPOINTS}
        if all(value == 200 for value in statuses.values()) or time.monotonic() >= deadline:
            break
        time.sleep(1)
    for path, status in statuses.items():
        lab.check("positive", f"The bearer monitor can read its approved {path} endpoint",
                  status == 200, {"http_status": status, "tls_verified": True})

    status = kubelet_status(lab, node, serving_cert, "/configz", token=token)
    lab.check("green", "The bearer monitor cannot read the unused /configz endpoint",
              status == 403, {"http_status": status, "tls_verified": True})
    for resource in ("proxy", "pods", "configz", "log"):
        allowed = review(lab, f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}",
                         ["system:authenticated", "system:serviceaccounts",
                          f"system:serviceaccounts:{NAMESPACE}"], node, resource)
        lab.check("green", f"Authorization still denies nodes/{resource}", not allowed, allowed)
    allowed = review(lab, f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}",
                     ["system:authenticated", "system:serviceaccounts",
                      f"system:serviceaccounts:{NAMESPACE}"],
                     "unapproved-monitoring-node", "metrics")
    lab.check("green", "The metrics grant is restricted to its named node", not allowed, allowed)

    verify_x509_monitor(lab, node, serving_cert, client_ca)
