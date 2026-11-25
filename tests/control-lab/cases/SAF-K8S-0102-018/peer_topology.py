"""Read-only peer-TLS handshake checks between three owned kubeadm etcd members."""
import json
import re
import subprocess


ETCD_CERT_DIR = "/etc/kubernetes/pki/etcd"
EXPECTED_ETCD_IMAGE = "registry.k8s.io/etcd:3.6.8-0"
CONTROL_PLANES = ("control-plane", "control-plane2", "control-plane3")
EXPECTED_ALERT = "certificate required"



def kubectl(lab, *args, timeout=25, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        f"--request-timeout={timeout - 5}s", *args, timeout=timeout,
        allow_failure=allow_failure,
    )


def required_flag(command, name):
    prefix = f"--{name}="
    values = [arg[len(prefix):] for arg in command if arg.startswith(prefix)]
    if len(values) != 1 or not values[0]:
        raise RuntimeError(f"Expected exactly one configured --{name} argument")
    return values[0]


def allowed_cert_path(value, expected_names):
    # Accept only an existing etcd PKI path from the live manifest. Never read
    # the file bytes; the private key stays on its case-owned node container.
    if (not value.startswith(ETCD_CERT_DIR + "/")
            or value.rsplit("/", 1)[-1] not in expected_names
            or ".." in value.split("/")):
        raise RuntimeError("Unexpected etcd credential path in live static Pod manifest")
    return value


def assert_pinned_three_node_topology(lab):
    version = json.loads(kubectl(lab, "version", "-o", "json").stdout)
    server = version.get("serverVersion", {}).get("gitVersion")
    if server != "v1.36.1":
        lab.block(f"Expected pinned Kubernetes v1.36.1; observed {server!r}")

    nodes = json.loads(kubectl(lab, "get", "nodes", "-o", "json").stdout)["items"]
    expected = {f"{lab.cluster}-{suffix}" for suffix in CONTROL_PLANES}
    by_name = {row["metadata"]["name"]: row for row in nodes}
    if set(by_name) != expected:
        lab.block("Fresh case cluster did not contain exactly the three configured control-plane nodes")

    members = {}
    for node_name in sorted(expected):
        node = by_name[node_name]
        ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in node.get("status", {}).get("conditions", []))
        if not ready:
            lab.block(f"Expected case-owned node {node_name} to be Ready")
        addresses = [a.get("address") for a in node.get("status", {}).get("addresses", [])
                     if a.get("type") == "InternalIP"]
        if len(addresses) != 1:
            lab.block(f"Expected one InternalIP for case-owned node {node_name}")
        members[node_name] = {"ip": addresses[0]}

    pods = json.loads(kubectl(lab, "-n", "kube-system", "get", "pods", "-l",
                              "component=etcd", "-o", "json").stdout)["items"]
    by_node = {}
    for pod in pods:
        node_name = pod.get("spec", {}).get("nodeName")
        if node_name in by_node:
            lab.block(f"More than one etcd Pod is assigned to {node_name}")
        by_node[node_name] = pod
    if set(by_node) != expected:
        lab.block("Expected exactly one live etcd Pod on each of the three fixture nodes")

    for node_name, pod in by_node.items():
        containers = pod.get("spec", {}).get("containers", [])
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if (pod.get("status", {}).get("phase") != "Running" or len(containers) != 1
                or len(statuses) != 1 or statuses[0].get("ready") is not True
                or containers[0].get("image") != EXPECTED_ETCD_IMAGE):
            lab.block(f"Unexpected etcd image or readiness on {node_name}")
        command = containers[0].get("command", [])
        member_name = required_flag(command, "name")
        peer_auth = required_flag(command, "peer-client-cert-auth")
        trusted_ca = allowed_cert_path(required_flag(command, "peer-trusted-ca-file"), {"ca.crt"})
        peer_cert = allowed_cert_path(required_flag(command, "peer-cert-file"), {"peer.crt"})
        peer_key = allowed_cert_path(required_flag(command, "peer-key-file"), {"peer.key"})
        listen_urls = required_flag(command, "listen-peer-urls").split(",")
        advertised_urls = required_flag(command, "initial-advertise-peer-urls").split(",")
        if peer_auth != "true":
            lab.block(f"etcd peer client certificate authentication is not enabled on {node_name}")
        if not any(url.startswith("https://") and url.endswith(":2380") for url in listen_urls):
            lab.block(f"No HTTPS peer listener on port 2380 in {node_name} manifest")
        if not any(url == f"https://{members[node_name]['ip']}:2380" for url in advertised_urls):
            lab.block(f"Advertised peer URL does not map to {node_name}'s observed InternalIP")
        members[node_name].update({
            "member_name": member_name,
            "peer_url": f"https://{members[node_name]['ip']}:2380",
            "trusted_ca_path": trusted_ca,
            "peer_cert_path": peer_cert,
            "peer_key_path": peer_key,
        })

    if len({row["member_name"] for row in members.values()}) != 3:
        lab.block("The three observed etcd Pods do not have distinct member names")
    lab.check(
        "green", "Exactly three ready pinned etcd members map to distinct configured HTTPS peer endpoints",
        True,
        {"member_count": len(members), "distinct_member_names": True,
         "exact_node_endpoint_identity_matches": True, "peer_client_cert_auth": True},
    )
    return members


def handshake(lab, source_node, dest_ip, *, cert=None, key=None, ca_path):
    """Run OpenSSL inside an owned node; return only normalized handshake facts.

    OpenSSL receives only file paths. Certificate/private-key contents are never
    read by the host Python process, passed via stdin, printed or written to evidence.
    """
    args = [
        "docker", "exec", "-i", source_node, "timeout", "8", "openssl", "s_client",
        "-connect", f"{dest_ip}:2380", "-brief", "-CAfile", ca_path,
        "-verify_return_error", "-verify_ip", dest_ip,
    ]
    if cert is not None or key is not None:
        if cert is None or key is None:
            raise RuntimeError("Both peer certificate and key paths must be supplied")
        args.extend(["-tls1_2", "-cert", cert, "-key", key])
    else:
        args.extend(["-tls1_3", "-ign_eof"])
    try:
        result = subprocess.run(args, input=b"", capture_output=True, timeout=12, env=lab.env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"completed": False, "expected_protocol": False, "server_verified": False,
                "accepted": False, "rejection": "probe-error"}

    # TLS diagnostics exist only in memory for classification and are discarded.
    # They contain public cert summaries, never the private key bytes.
    transcript = (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace").lower()
    version = "tlsv1.2" if cert is not None else "tlsv1.3"
    protocol_matches = f"protocol version: {version}" in transcript
    server_verified = "verification: ok" in transcript
    rejection = EXPECTED_ALERT if re.search(r"alert\s+certificate required", transcript) else None
    accepted = result.returncode == 0 and protocol_matches and server_verified and rejection is None
    rejected = result.returncode != 0 and protocol_matches and server_verified and rejection == EXPECTED_ALERT
    return {
        "completed": result.returncode == 0 or rejected,
        "expected_protocol": protocol_matches,
        "server_verified": server_verified,
        "accepted": accepted,
        "rejection": rejection,
        "certificate_required": rejected,
    }


def run(lab):
    members = assert_pinned_three_node_topology(lab)
    ordered = sorted(members)

    # Negative control on every member's peer listener. Each probe runs on the
    # destination node itself, verifies the serving certificate/IP, and sends no
    # client cert or etcd application request.
    negative = {}
    for target in ordered:
        node = target
        row = members[target]
        observed = handshake(lab, node, row["ip"], ca_path=row["trusted_ca_path"])
        negative[target] = observed
    negative_ok = all(
        item.get("completed") and item.get("expected_protocol") and item.get("server_verified")
        and item.get("certificate_required") and not item.get("accepted")
        for item in negative.values()
    )
    lab.check(
        "red", "Each member peer listener rejects TLS without a client certificate after server verification",
        negative_ok,
        {name.removeprefix(lab.cluster + "-"): value for name, value in sorted(negative.items())},
    )

    # A -> B, B -> C, C -> A. Credentials remain on each origin node; only
    # endpoint and file paths are arguments. No etcd RPC follows TLS establishment.
    cycle = [(ordered[0], ordered[1]), (ordered[1], ordered[2]), (ordered[2], ordered[0])]
    positive = []
    for source, destination in cycle:
        src, dst = members[source], members[destination]
        observed = handshake(
            lab, source, dst["ip"], cert=src["peer_cert_path"], key=src["peer_key_path"],
            ca_path=src["trusted_ca_path"],
        )
        positive.append({"source": source, "destination": destination, **observed})
    positive_ok = all(
        row["source"] != row["destination"] and row.get("completed") and row.get("expected_protocol")
        and row.get("server_verified") and row.get("accepted")
        for row in positive
    )
    lab.check(
        "positive", "Existing member credentials establish verified TLS handshakes to distinct peer members",
        positive_ok,
        [{**row, "source": row["source"].removeprefix(lab.cluster + "-"),
          "destination": row["destination"].removeprefix(lab.cluster + "-")} for row in positive],
    )

    ready = kubectl(lab, "get", "--raw=/readyz", timeout=15).stdout.strip()
    lab.check("positive", "Kubernetes API readiness remains available after TLS-only probes",
              ready == "ok", {"api_ready": ready == "ok"})
