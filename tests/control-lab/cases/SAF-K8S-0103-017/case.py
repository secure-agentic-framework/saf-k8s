"""Check legacy serving removal and controlled secure health endpoint exposure."""
import ipaddress
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
TIMEOUT = 8
HEALTH_PATH = "/healthz"
METRICS_PATH = "/metrics"
MONITOR_ACCOUNT = "fixture-secure-metrics-monitor"
MONITOR_ROLE = "fixture-secure-metrics-reader"
MONITOR_BINDING = "fixture-secure-metrics-reader"
TRUST_CA_NODE_PATH = "/etc/kubernetes/pki/saf-k8s-0103-017-fixture-ca.crt"
SERVING_CERTS = {
    "kube-controller-manager": (
        "/etc/kubernetes/saf-serving-0103-017/kube-controller-manager/server.crt",
        "/etc/kubernetes/saf-serving-0103-017/kube-controller-manager/server.key",
        "fixture-kube-controller-manager",
    ),
    "kube-scheduler": (
        "/etc/kubernetes/saf-serving-0103-017/kube-scheduler/server.crt",
        "/etc/kubernetes/saf-serving-0103-017/kube-scheduler/server.key",
        "fixture-kube-scheduler",
    ),
}
COMPONENTS = {
    "kube-controller-manager": {"port": 10257, "pod": "kube-controller-manager"},
    "kube-scheduler": {"port": 10259, "pod": "kube-scheduler"},
}
# Historical insecure serving ports from the Kubernetes component docs/source.
LEGACY_PORTS = {"kube-controller-manager": 10252, "kube-scheduler": 10251}
LEGACY_FLAGS = ("port", "address", "insecure-port")
SCOPE = (
    "On isolated disposable kind v1.36.1 Linux nodes, verify component help and "
    "effective Pod arguments contain no legacy --port, --address, or "
    "--insecure-port options, and no TCP listeners use the historical insecure "
    "ports 10252/10251. Compare secure ports 10257/10259 bound to 127.0.0.1 "
    "against an intentionally broad 0.0.0.0 bind. Probe the owned node's "
    "fixed /healthz endpoint over HTTPS, discard response bodies, and retain only "
    "status/connectivity and listener metadata. In the loopback profile only, "
    "verify fixture-CA-signed loopback serving identities and compare "
    "no-credential and short-lived API-audience ServiceAccount-token requests "
    "to /metrics; discard every body. No ports are published."
)


def kubectl(lab, cluster, *args):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{cluster}",
        "--request-timeout=3s", *args, timeout=TIMEOUT + 5,
    ).stdout


def component_command(lab, cluster, component):
    pod = f"{COMPONENTS[component]['pod']}-{cluster}-control-plane"
    try:
        row = json.loads(kubectl(lab, cluster, "-n", "kube-system", "get", f"pod/{pod}", "-o", "json"))
        container = next(item for item in row["spec"]["containers"] if item.get("name") == component)
        command = container["command"]
        argv = command + container.get("args", [])
    except (ValueError, KeyError, StopIteration, TypeError):
        lab.block(f"Could not read the {component} mirror Pod command for {cluster}")
    if not command or Path(command[0]).name != component:
        lab.block(f"Unexpected {component} command for {cluster}")
    return argv


def has_flag(argv, name):
    return any(arg == f"--{name}" or arg.startswith(f"--{name}=") for arg in argv)


def component_flags_probe(lab, cluster, component, *flags):
    pod = f"{component}-{cluster}-control-plane"
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{cluster}",
        "-n", "kube-system", "--request-timeout=10s", "exec", f"pod/{pod}",
        "-c", component, "--", component, *flags, "--help",
        allow_failure=True, timeout=20,
    )


def help_flags(lab, cluster, component):
    result = component_flags_probe(lab, cluster, component)
    if result.returncode:
        lab.block(f"Could not read help from the running {component} image")
    help_text = result.stdout + result.stderr

    def documented(name):
        return bool(re.search(rf"(?m)^[ \t]*--{re.escape(name)}(?:[= \t,]|$)", help_text))

    return {name: documented(name) for name in LEGACY_FLAGS}, all(
        documented(name) for name in ("bind-address", "secure-port")
    )


def reject_removed_flags(lab, cluster, component):
    results = {}
    for flag in ("--port=0", "--address=127.0.0.1"):
        output = component_flags_probe(lab, cluster, component, flag)
        name = flag.split("=")[0]
        results[name] = output.returncode != 0 and f"unknown flag: {name}" in (output.stderr + output.stdout)
    lab.check("green", f"{component} parser rejects both removed flags",
              all(results.values()), results)


def node_ipv4(lab, cluster):
    node = f"{cluster}-control-plane"
    raw = lab.command(
        "docker", "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", node,
    ).stdout.split()
    addresses = []
    for value in raw:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4 and not address.is_loopback and not address.is_unspecified:
            addresses.append(str(address))
    if len(set(addresses)) != 1:
        lab.block(f"Expected one isolated non-loopback IPv4 address for {node}")
    return addresses[0]


def listeners(lab, cluster):
    output = lab.command(
        "docker", "exec", f"{cluster}-control-plane", "ss", "-lntH", timeout=TIMEOUT,
    ).stdout
    by_port = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            local = fields[3]
            port = local.rsplit(":", 1)[-1]
            by_port.setdefault(port, []).append(local)
    return by_port


def component_listeners(lab, cluster):
    by_port = listeners(lab, cluster)
    secure = {}
    for component, row in COMPONENTS.items():
        matches = by_port.get(str(row["port"]), [])
        if len(matches) != 1:
            lab.block(f"Expected exactly one secure TCP listener for {component}")
        secure[component] = matches[0]
    legacy = {
        component: by_port.get(str(port), [])
        for component, port in LEGACY_PORTS.items()
    }
    return secure, legacy


def bind_arguments(argv):
    found = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--bind-address":
            found.append(argv[index + 1] if index + 1 < len(argv) else "<missing-value>")
            index += 1
        elif arg.startswith("--bind-address="):
            found.append(arg.split("=", 1)[1])
        index += 1
    return found


def health_probe(lab, cluster, address, port, *, trust_ca=None):
    """Return status/connectivity only; use fixture CA when supplied."""
    node = f"{cluster}-control-plane"
    trust = ["--cacert", trust_ca] if trust_ca else ["--insecure"]
    result = subprocess.run(
        ["docker", "exec", "--user=65534:65534", node, "/usr/bin/curl",
         "--silent", "--show-error", *trust, "--noproxy", "*",
         "--connect-timeout", "2", "--max-time", str(TIMEOUT), "--request", "GET",
         "--output", "/dev/null", "--write-out", "%{http_code}",
         f"https://{address}:{port}{HEALTH_PATH}"],
        env=lab.env, capture_output=True, text=True, timeout=TIMEOUT + 5,
    )
    status = result.stdout.strip()
    if result.returncode == 0 and re.fullmatch(r"[1-5][0-9][0-9]", status):
        return int(status), True
    if result.returncode == 7 and status == "000":
        return None, False
    lab.block("Health probe failed for a reason other than connection refusal")


def issue_monitor_token(lab):
    """Keep the short-lived synthetic bearer in memory and out of command logs."""
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--namespace", "saf-test", "--request-timeout=8s", "create", "token", MONITOR_ACCOUNT,
         "--duration=10m"],
        env=lab.env, capture_output=True, text=True, timeout=15,
    )
    token = result.stdout.strip()
    if result.returncode and "expirationSeconds" in result.stderr:
        lab.block("The pinned TokenRequest API rejected the fixture token lifetime")
    if result.returncode or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
        lab.block("Could not issue a short-lived fixture monitoring token")
    return token


def route_status(lab, cluster, port, path, *, bearer=None):
    """Probe one owned loopback route; verify local CA; body/token stay on stdin."""
    config = f'url = "https://127.0.0.1:{port}{path}"\n'
    if bearer is not None:
        config += f'header = "Authorization: Bearer {bearer}"\n'
    result = subprocess.run(
        ["docker", "exec", "-i", "--user=65534:65534", f"{cluster}-control-plane",
         "/usr/bin/curl", "--config", "-", "--silent", "--show-error",
         "--cacert", TRUST_CA_NODE_PATH,
         "--noproxy", "*", "--connect-timeout", "2", "--max-time", str(TIMEOUT),
         "--output", "/dev/null", "--write-out", "%{http_code}"],
        input=config, env=lab.env, capture_output=True, text=True, timeout=TIMEOUT + 5,
    )
    status = result.stdout.strip()
    if result.returncode == 0 and re.fullmatch(r"[1-5][0-9][0-9]", status):
        return int(status)
    lab.block("Owned HTTPS route probe failed without retaining response content")


def install_monitor_identity(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": MONITOR_ACCOUNT}, "automountServiceAccountToken": False})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": MONITOR_ROLE}, "rules": [{
                    "nonResourceURLs": [METRICS_PATH], "verbs": ["get"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": MONITOR_BINDING},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                            "name": MONITOR_ROLE},
                "subjects": [{"kind": "ServiceAccount", "name": MONITOR_ACCOUNT,
                              "namespace": "saf-test"}]})


def metrics_auth_checks(lab, cluster):
    install_monitor_identity(lab)
    token = issue_monitor_token(lab)
    try:
        for component, row in COMPONENTS.items():
            no_credential = route_status(lab, cluster, row["port"], METRICS_PATH)
            lab.check("green", f"{component} denies unauthenticated loopback GET /metrics",
                      no_credential in (401, 403),
                      {"http_status": no_credential, "body_discarded": True})

            authorized = route_status(lab, cluster, row["port"], METRICS_PATH, bearer=token)
            lab.check("positive", f"{component} permits scoped synthetic monitor GET /metrics",
                      authorized == 200,
                      {"http_status": authorized, "body_discarded": True,
                       "identity": f"system:serviceaccount:saf-test:{MONITOR_ACCOUNT}"})

    finally:
        # Never emit or persist the credential; delete its bound authorization
        # objects after the local probes. The runner also owns final cluster teardown.
        del token
        for kind, name in (("clusterrolebinding", MONITOR_BINDING),
                           ("clusterrole", MONITOR_ROLE)):
            lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                        f"kind-{lab.cluster}", "--request-timeout=8s", "delete", kind, name,
                        "--ignore-not-found=true", timeout=TIMEOUT + 5)
        lab.kubectl("delete", "serviceaccount", MONITOR_ACCOUNT,
                    "--ignore-not-found=true", timeout=TIMEOUT + 5)


def create_serving_certificate(lab, directory, component, leaf, key, common_name):
    extensions = directory / f"{component}.ext"
    csr = directory / f"{component}.csr"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
    )
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={common_name}", timeout=30)
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(directory / "ca.crt"),
                "-CAkey", str(directory / "ca.key"), "-CAcreateserial", "-out", str(leaf),
                "-days", "1", "-sha256", "-extfile", str(extensions), timeout=30)
    verified = lab.command("openssl", "verify", "-CAfile", str(directory / "ca.crt"),
                           str(leaf), allow_failure=True, timeout=15)
    public_certificate = lab.command("openssl", "x509", "-in", str(leaf), "-noout", "-text", timeout=15)
    exact_san = "IP Address:127.0.0.1" in public_certificate.stdout
    lab.check("positive", f"{component} serving certificate chains to fixture CA and includes loopback SAN",
              verified.returncode == 0 and verified.stdout.rstrip().endswith(": OK") and exact_san,
              {"fixture_ca_verified": verified.returncode == 0,
               "loopback_ip_san": exact_san, "identity": common_name})


def manifest_with_serving_cert(text, cert_path, key_path):
    # kubeadm emits one command list per control-plane static Pod. Add only the
    # two secure-serving file flags immediately before that container's image.
    replacement = (f"    - --tls-cert-file={cert_path}\n"
                   f"    - --tls-private-key-file={key_path}\n"
                   "    image:")
    updated, count = re.subn(r"(?m)^    image:", replacement, text, count=1)
    mount_dir = str(Path(cert_path).parent)
    mount_entry = ("    volumeMounts:\n"
                   f"    - mountPath: {mount_dir}\n"
                   "      name: saf-fixture-serving\n"
                   "      readOnly: true\n")
    volume_entry = ("  volumes:\n"
                    "  - hostPath:\n"
                    f"      path: {mount_dir}\n"
                    "      type: Directory\n"
                    "    name: saf-fixture-serving\n")
    if (count != 1 or "--tls-cert-file=" in text or text.count("    volumeMounts:\n") != 1
            or text.count("\n  volumes:\n") != 1 or Path(key_path).parent.as_posix() != mount_dir):
        raise ValueError("Unexpected kubeadm static Pod manifest shape")
    return updated.replace("    volumeMounts:\n", mount_entry, 1).replace("\n  volumes:\n", "\n" + volume_entry, 1)


def install_serving_identities(lab, directory):
    """Pin both loopback servers to fixture-CA-signed, distinct identities."""
    ca_key = directory / "ca.key"
    ca_cert = directory / "ca.crt"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-days", "1", "-keyout", str(ca_key), "-out", str(ca_cert),
                "-subj", "/CN=SAF-K8S-0103-017-local-fixture-CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", timeout=30)
    node = f"{lab.cluster}-control-plane"
    lab.command("docker", "exec", node, "mkdir", "-p", "/etc/kubernetes/pki", timeout=TIMEOUT)
    lab.command("docker", "cp", str(ca_cert), f"{node}:{TRUST_CA_NODE_PATH}", timeout=TIMEOUT + 5)
    lab.command("docker", "exec", node, "chmod", "0644", TRUST_CA_NODE_PATH, timeout=TIMEOUT)

    before = {}
    for component, (cert_path, key_path, common_name) in SERVING_CERTS.items():
        leaf = directory / f"{component}.crt"
        key = directory / f"{component}.key"
        create_serving_certificate(lab, directory, component, leaf, key, common_name)
        pod = f"{COMPONENTS[component]['pod']}-{lab.cluster}-control-plane"
        current = json.loads(kubectl(lab, lab.cluster, "-n", "kube-system", f"get", f"pod/{pod}", "-o", "json"))
        before[component] = current["metadata"]["uid"]
        lab.command("docker", "exec", node, "mkdir", "-p", str(Path(cert_path).parent), timeout=TIMEOUT)
        lab.command("docker", "cp", str(leaf), f"{node}:{cert_path}", timeout=TIMEOUT + 5)
        lab.command("docker", "cp", str(key), f"{node}:{key_path}", timeout=TIMEOUT + 5)
        lab.command("docker", "exec", node, "chmod", "0600", key_path, timeout=TIMEOUT)
        source = directory / f"{component}.yaml"
        lab.command("docker", "cp", f"{node}:/etc/kubernetes/manifests/{component}.yaml",
                    str(source), timeout=TIMEOUT + 5)
        try:
            manifest = manifest_with_serving_cert(source.read_text(), cert_path, key_path)
        except (OSError, ValueError):
            lab.block(f"Could not safely update owned {component} static Pod manifest")
        source.write_text(manifest)
        staged = f"/etc/kubernetes/{component}-saf-fixture.yaml"
        lab.command("docker", "cp", str(source), f"{node}:{staged}", timeout=TIMEOUT + 5)
        lab.command("docker", "exec", node, "mv", "--", staged,
                    f"/etc/kubernetes/manifests/{component}.yaml", timeout=TIMEOUT)

    # Require replacement Pods to be Ready before sending any HTTPS request.
    for component in COMPONENTS:
        pod = f"{COMPONENTS[component]['pod']}-{lab.cluster}-control-plane"
        deadline = time.monotonic() + 100
        replacement_ready = False
        while time.monotonic() < deadline:
            result = lab.command(
                "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "--namespace", "kube-system", "--request-timeout=4s", "get", f"pod/{pod}", "-o", "json",
                timeout=TIMEOUT + 5, allow_failure=True,
            )
            if result.returncode == 0:
                try:
                    row = json.loads(result.stdout)
                    ready = any(item.get("type") == "Ready" and item.get("status") == "True"
                                for item in row.get("status", {}).get("conditions", []))
                    if row["metadata"]["uid"] != before[component] and ready:
                        replacement_ready = True
                        break
                except (ValueError, KeyError, TypeError):
                    pass
            time.sleep(1)
        else:
            lab.block(f"{component} did not become Ready with its fixture serving certificate")
        lab.check("positive", f"{component} replacement mirror Pod becomes Ready with fixture serving identity",
                  replacement_ready,
                  {"replacement_uid_observed": replacement_ready,
                   "ready_condition": replacement_ready,
                   "readiness_oracle": "Kubernetes API mirror Pod status"})


def check_profile(lab, cluster, mode, *, trust_ca=None):
    expected_bind = "127.0.0.1" if mode == "loopback" else "0.0.0.0"
    node_address = node_ipv4(lab, cluster)

    for component in COMPONENTS:
        argv = component_command(lab, cluster, component)
        legacy_args = {name: has_flag(argv, name) for name in LEGACY_FLAGS}
        binds = bind_arguments(argv)
        phase = "green" if mode == "loopback" else "red"
        lab.check(phase, f"{component} effective arguments omit legacy serving flags",
                  not any(legacy_args.values()), {"legacy_flags_present": legacy_args})
        lab.check(phase, f"{component} secure bind address is {expected_bind}",
                  binds == [expected_bind], {"bind_address_arguments": binds})

        help_legacy, secure_help = help_flags(lab, cluster, component)
        lab.check("green", f"{component} v1.36.1 help omits deprecated insecure serving flags",
                  not any(help_legacy.values()) and secure_help,
                  {"legacy_flags_present": help_legacy, "secure_flags_present": secure_help})
        if mode == "loopback":
            reject_removed_flags(lab, cluster, component)

    secure, legacy = component_listeners(lab, cluster)
    for component, local in secure.items():
        lab.check("green" if mode == "loopback" else "red",
                  f"{component} secure listener has expected bind address",
                  local.startswith(f"{expected_bind}:")
                  or (mode == "wildcard" and local.rsplit(":", 1)[0] in ("*", "[::]")),
                  {"local_listener": local})
    lab.check("green", "No listener uses either historical insecure component port",
              not any(legacy.values()), {"legacy_port_listeners": legacy})

    for component, row in COMPONENTS.items():
        local_status, local_connected = health_probe(
            lab, cluster, "127.0.0.1", row["port"], trust_ca=trust_ca)
        lab.check("positive", f"{component} permitted HTTPS /healthz on loopback returns 200",
                  local_connected and local_status == 200, {"http_status": local_status})

        remote_status, remote_connected = health_probe(lab, cluster, node_address, row["port"])
        if mode == "wildcard":
            lab.check("red", f"{component} non-loopback node address reaches secure health listener",
                      remote_connected and remote_status == 200,
                      {"http_status": remote_status, "connected": remote_connected})
        else:
            lab.check("green", f"{component} non-loopback node address cannot reach loopback listener",
                      not remote_connected,
                      {"http_status": remote_status, "connected": remote_connected})
    if mode == "loopback":
        metrics_auth_checks(lab, cluster)


def wildcard_config():
    return (
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    controllerManager:\n      extraArgs:\n"
        "        - name: bind-address\n          value: 0.0.0.0\n"
        "    scheduler:\n      extraArgs:\n"
        "        - name: bind-address\n          value: 0.0.0.0\n"
    )


def run(lab):
    # The runner's case-owned kind.yaml supplies the loopback-only green profile.
    with tempfile.TemporaryDirectory(prefix="saf-k8s-0103-017-serving-identity-") as temp:
        certificate_dir = Path(temp)
        install_serving_identities(lab, certificate_dir)
        check_profile(lab, lab.cluster, "loopback", trust_ca=TRUST_CA_NODE_PATH)

    cluster = f"{lab.cluster}-exposure-red"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional exposure profile already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-k8s-exposure-profile-") as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        config = Path(temp) / "kind.yaml"
        config.write_text(wildcard_config())
        attempted = False
        try:
            attempted = True
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                "--config", str(config), "--kubeconfig", str(kubeconfig), "--wait", "90s",
                timeout=480,
            )
            original = lab.kubeconfig
            lab.kubeconfig = kubeconfig
            try:
                check_profile(lab, cluster, "wildcard")
            finally:
                lab.kubeconfig = original
        finally:
            if attempted:
                result = lab.command(
                    "kind", "delete", "cluster", "--name", cluster,
                    "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True,
                )
                if result.returncode:
                    lab.block(f"Could not confirm cleanup of exposure profile {cluster}")
