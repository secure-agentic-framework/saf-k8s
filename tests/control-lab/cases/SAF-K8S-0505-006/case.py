"""Verify an owned kube-apiserver across approved and unapproved network paths."""
import base64
import json
from pathlib import Path
import re
import time

ROOT = Path(__file__).resolve().parent
CLIENT_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "A Kubernetes v1.36.1 API server on a fresh Kind node with two additional owned internal "
    "Docker bridges. Both clients initially reach the same API server and validate its TLS "
    "certificate against the exact cluster CA. A scoped firewall on the Kind node accepts "
    "the management path and silently denies TCP/6443 from the other path. The rule's packet "
    "counter confirms the denied traffic arrived at the node. Harness loopback and node "
    "traffic remain available. Cloud provider endpoint and production network policy "
    "verification require separate environments."
)


def docker(lab, *args, **kwargs):
    return lab.command("docker", *args, **kwargs)


def addresses(lab, endpoint, node):
    inspection = json.loads(docker(lab, "network", "inspect", endpoint).stdout)[0]
    connected = {row["Name"]: row["IPv4Address"].split("/")[0]
                 for row in inspection["Containers"].values()}
    client = f"{endpoint}-client"
    if set(connected) != {client, node}:
        lab.block("The internal fixture bridge has unexpected peers")
    if not inspection["Internal"] or not connected[client] or not connected[node]:
        lab.block("Expected exclusively private IPv4 fixture addresses")
    return connected


def probe(lab, client, address, ca):
    response = docker(lab, "exec", "-i", client, "python", "-c", (ROOT / "probe.py").read_text(),
                      payload=json.dumps({"address": address, "ca": ca}), allow_failure=True, timeout=12)
    if response.returncode:
        lab.block("The fixture client did not produce a reviewed transport observation")
    return json.loads(response.stdout)


def verified(response):
    return (response.get("result") == "verified_api_response" and response["from_kubernetes"] is True
            and response["status"] in {200, 401, 403}
            and (response["status"] != 200 or response["kubernetes_version"] == "v1.36.1"))


def bootstrap_probe(lab, endpoint, node, ca):
    ips = addresses(lab, endpoint, node)
    client = f"{endpoint}-client"
    deadline = time.monotonic() + 14
    while True:
        response = probe(lab, client, ips[node], ca)
        if verified(response):
            return ips, response
        if time.monotonic() >= deadline:
            lab.block("The fixture client was unable to verify its API server route before policy")
        time.sleep(0.5)


def firewall(lab, node, *args, **kwargs):
    return docker(lab, "exec", node, "iptables", "-w", *args, **kwargs)


def run(lab):
    # The CA is public. No kubeconfig, token or client credential is copied to either test client.
    public_ca = lab.kubectl("config", "view", "--raw", "--minify",
                            "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}").stdout
    ca = base64.b64decode(public_ca, validate=True).decode()
    if "BEGIN CERTIFICATE" not in ca:
        lab.block("Expected the fixture's PEM trust anchor")

    node = f"{lab.cluster}-control-plane"
    approved, other = (f"{lab.cluster}-{role}" for role in ("management", "alternate"))
    active_networks = []
    active_clients = []
    try:
        for endpoint in (approved, other):
            docker(lab, "network", "create", "--internal", endpoint)
            active_networks.append(endpoint)
            docker(lab, "network", "connect", endpoint, node)
            client = f"{endpoint}-client"
            docker(lab, "run", "--detach", "--name", client, "--network", endpoint, "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", CLIENT_IMAGE, "python", "-c",
                   "import time; time.sleep(600)", timeout=110)
            active_clients.append(client)

        initial = {}
        for role, endpoint in (("management", approved), ("alternate", other)):
            ips, before = bootstrap_probe(lab, endpoint, node, ca)
            initial[role] = (ips, before)
            lab.check("red", f"The {role} client reaches the genuine API server before the boundary rule",
                      verified(before), before)

        other_ips = initial["alternate"][0]
        ip = other_ips[node]
        interfaces = json.loads(docker(lab, "exec", node, "ip", "-j", "-4", "address", "show").stdout)
        interfaces = [entry["ifname"] for entry in interfaces
                      if any(row.get("local") == ip for row in entry["addr_info"])]
        if len(interfaces) != 1:
            lab.block("The alternate network was not bound to a unique fixture interface")
        firewall(lab, node, "-N", "SAF_API_RESTRICT")
        firewall(lab, node, "-A", "SAF_API_RESTRICT", "-p", "tcp", "--dport", "6443", "-j", "DROP")
        firewall(lab, node, "-I", "INPUT", "1", "-i", interfaces[0], "-d", ip, "-j", "SAF_API_RESTRICT")

        rejected = probe(lab, f"{other}-client", ip, ca)
        counts = firewall(lab, node, "-L", "SAF_API_RESTRICT", "-v", "-x", "-n").stdout
        packets = re.search(r"(?m)^\s*(\d+)\s+\d+\s+DROP\s+tcp\b", counts)
        observed = {"result": rejected["result"], "matching_drop_packets": bool(packets and int(packets[1]) > 0)}
        lab.check("green", "TCP to the owned API server is denied on the alternate network",
                  rejected == {"result": "tcp_timeout"} and observed["matching_drop_packets"], observed)

        accepted = probe(lab, f"{approved}-client", initial["management"][0][node], ca)
        lab.check("positive", "The management network still reaches the same verified API service",
                  verified(accepted) and accepted == initial["management"][1], accepted)
        (lab.evidence / "endpoint-observations.json").write_text(
            json.dumps({"baseline": {key: row[1] for key, row in initial.items()},
                        "alternate_rejected": observed, "management_permitted": accepted},
                       indent=2, sort_keys=True) + "\n")
    finally:
        cleanup_ok = True
        for client in reversed(active_clients):
            cleanup_ok &= docker(lab, "rm", "-f", client, allow_failure=True).returncode == 0
        for endpoint in reversed(active_networks):
            docker(lab, "network", "disconnect", "-f", endpoint, node, allow_failure=True)
            cleanup_ok &= docker(lab, "network", "rm", endpoint, allow_failure=True).returncode == 0
        lab.check("positive", "The owned bridge clients and networks were removed", cleanup_ok,
                  {"fixture_resources_removed": cleanup_ok})
