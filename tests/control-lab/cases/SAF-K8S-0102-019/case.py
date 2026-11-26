"""Supplement Pod marker policy proof with owned kubeadm etcd host listeners."""
import ipaddress
import json
import re
import shlex
import time
from urllib.parse import urlsplit

import yaml

from fixtures import container, pod

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
PROBE_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
ETCD_CA = "/etc/kubernetes/pki/etcd/ca.crt"
ETCD_HEALTH_CERT = "/etc/kubernetes/pki/etcd/healthcheck-client.crt"
ETCD_HEALTH_KEY = "/etc/kubernetes/pki/etcd/healthcheck-client.key"
ETCD_PEER_CERT = "/etc/kubernetes/pki/etcd/peer.crt"
GUARD = "SAF019IN"
LABEL = "fixture.example/etcd-role"
SERVER = "fixture-endpoint-markers"
PORTS = {"client": 12379, "peer": 12380}
PROBES = {"api-client": "fixture-api-client", "member": "fixture-peer-member",
          "ordinary": "fixture-ordinary"}
LISTENER = """
from socketserver import BaseRequestHandler, TCPServer
import threading
class Handler(BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.server.marker)
def serve(port, marker):
    with TCPServer(('0.0.0.0', port), Handler) as server:
        server.marker = marker
        server.serve_forever()
threading.Thread(target=serve, args=(12379, b'client-marker'), daemon=True).start()
serve(12380, b'peer-marker')
"""
CONNECT = """
import socket,sys
try:
    with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1):
        print('open')
except OSError:
    print('closed')
"""
SCOPE = (
    "Four owned Kind v1.36.1 nodes (three kubeadm control planes and one worker). "
    "Preserves the published inert Pod listener checks, then inventories actual local "
    "etcd client and node-bound peer listeners. A dedicated IPv4 iptables chain inside "
    "each owned control-plane node container denies worker and workload TCP connects "
    "to actual node-bound etcd ports while preserving local API clients and exact etcd "
    "peer addresses. Real fixture etcd client/peer TLS and API readiness are positive "
    "comparators. No host firewall, external endpoint, key output, or production system."
)


def _json(result):
    return json.loads(result.stdout)


def _node(lab, container_name, *args, timeout=15, allow_failure=False):
    return lab.command("docker", "exec", container_name, *args,
                       timeout=timeout, allow_failure=allow_failure)


def _start_marker_pod(lab, namespace, name, node_name, role, program, *, server=False):
    command = ["python", "-c", program] if not server else ["python", "-c", program]
    spec = pod(
        name, [container("unit", image=PROBE_IMAGE, command=command,
                         resources={"requests": {"cpu": "5m", "memory": "12Mi"},
                                    "limits": {"cpu": "100m", "memory": "48Mi"}})],
        automountServiceAccountToken=False,
        nodeSelector={"kubernetes.io/hostname": node_name},
    )
    spec["metadata"].update(namespace=namespace, labels={LABEL: role})
    lab.create(spec)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    return _json(lab.kubectl("-n", namespace, "get", "pod", name, "-o", "json"))


def _start(lab, name, role, node_name, program):
    return _start_marker_pod(lab, "saf-test", name, node_name, role, program)


def _sample(lab, address, probe_role, port_role):
    result = lab.kubectl(
        "-n", "saf-test", "exec", "pod/" + PROBES[probe_role], "--", "python", "-c",
        CONNECT, address, str(PORTS[port_role]), allow_failure=True, timeout=12)
    if result.returncode == 0 and result.stdout.strip() in ("open", "closed"):
        return result.stdout.strip()
    lab.block("Owned marker connectivity probe did not return a bounded network outcome")


def _marker_policy(lab, namespace, name, types, pods=None, **rules):
    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": name, "namespace": namespace},
                "spec": {"podSelector": pods or {}, "policyTypes": types, **rules}})


def _marker_checks(lab, worker_node):
    lab.kubectl("-n", "saf-test", "label", "namespace", "saf-test",
                "pod-security.kubernetes.io/enforce=restricted", "--overwrite")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=70s", timeout=80)
    _start(lab, SERVER, "listener", worker_node, LISTENER)
    for role, name in PROBES.items():
        _start(lab, name, role, worker_node, "import time; time.sleep(900)")
    lab.kubectl("-n", "saf-test", "wait", "--for=condition=Ready", "pod", "--all",
                "--timeout=90s", timeout=100)
    server = _json(lab.kubectl("-n", "saf-test", "get", "pod", SERVER, "-o", "json"))
    endpoint = server["status"]["podIP"]
    baseline = {port: _sample(lab, endpoint, "ordinary", port) for port in PORTS}
    lab.check("red", "Both inert listeners are reachable from the ordinary Pod before ingress policy",
              baseline == {"client": "open", "peer": "open"}, baseline)

    routes = {"client": "api-client", "peer": "member"}
    peers = [{"podSelector": {"matchLabels": {LABEL: role}}} for role in routes.values()]
    _marker_policy(lab, "saf-test", SERVER, ["Ingress"],
                   {"matchLabels": {LABEL: "listener"}},
                   ingress=[{"from": [source],
                             "ports": [{"protocol": "TCP", "port": PORTS[port]}]}
                            for source, port in zip(peers, routes)])
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline and _sample(lab, endpoint, "ordinary", "client") != "closed":
        time.sleep(0.4)
    denied = {"ordinary_client": _sample(lab, endpoint, "ordinary", "client"),
              "ordinary_peer": _sample(lab, endpoint, "ordinary", "peer"),
              "client_on_peer": _sample(lab, endpoint, "api-client", "peer"),
              "peer_on_client": _sample(lab, endpoint, "member", "client")}
    lab.check("green", "Workload ingress and unintended cross-class marker paths are denied",
              set(denied.values()) == {"closed"}, denied)
    approved = {port: _sample(lab, endpoint, role, port) for port, role in routes.items()}
    lab.check("positive", "The approved marker client and member retain their intended connectivity",
              approved == baseline, {"approved_paths_reachable": approved == baseline})


def _pods_by_node(lab, component):
    rows = _json(lab.kubectl("-n", "kube-system", "get", "pods", "-l",
                             f"component={component}", "-o", "json"))["items"]
    result = {}
    for row in rows:
        node = row.get("spec", {}).get("nodeName")
        if not node or node in result:
            lab.block("Static etcd/API Pods were not one-to-one with fixture nodes")
        result[node] = row
    return result


def _internal_ipv4(row):
    values = [address["address"] for address in row.get("status", {}).get("addresses", [])
              if address.get("type") == "InternalIP"]
    parsed = [value for value in values if ipaddress.ip_address(value).version == 4]
    if len(parsed) != 1:
        raise ValueError("Fixture profile needs one IPv4 InternalIP per node")
    return parsed[0]


def _url_list(value, label):
    result = []
    for item in value.split(","):
        parsed = urlsplit(item)
        if parsed.scheme != "https" or not parsed.hostname or not parsed.port:
            raise ValueError(f"Unexpected {label} URL in owned kubeadm profile")
        result.append((parsed.hostname, parsed.port))
    return result


def _flag(command, name):
    prefix = name + "="
    values = []
    for index, arg in enumerate(command):
        if arg.startswith(prefix):
            values.append(arg[len(prefix):])
        elif arg == name and index + 1 < len(command):
            values.append(command[index + 1])
    if len(values) != 1:
        raise ValueError(f"Expected one exact {name} flag")
    return values[0]


def _listeners(lab, node, node_ip, etcd_pod):
    manifest = _node(lab, node, "cat", "/etc/kubernetes/manifests/etcd.yaml").stdout
    doc = yaml.safe_load(manifest)
    commands = doc.get("spec", {}).get("containers", [{}])[0].get("command", [])
    client = _url_list(_flag(commands, "--listen-client-urls"), "client")
    peer = _url_list(_flag(commands, "--listen-peer-urls"), "peer")
    advertised = _url_list(_flag(commands, "--initial-advertise-peer-urls"),
                           "advertised peer")
    peer_ports = {port for _, port in peer}
    client_ports = {port for _, port in client}
    if len(peer_ports) != 1 or len(client_ports) != 1:
        lab.block("Owned kubeadm profile exposed ambiguous etcd listener ports")
    peer_port = next(iter(peer_ports))
    client_port = next(iter(client_ports))
    if any(host not in (node_ip, "0.0.0.0") for host, _ in peer):
        lab.block("Actual etcd peer listen URL is outside the reviewed node IPv4 profile")
    if (len(advertised) != 1 or advertised[0][0] != node_ip
            or advertised[0][1] != peer_port):
        lab.block("Each etcd member must advertise its exact guarded node IPv4 peer endpoint")
    member_name = _flag(commands, "--name")
    if any("::" in host for host, _ in client + peer):
        lab.block("This candidate is IPv4-only and refuses an IPv6 etcd listener")
    sockets = _node(lab, node, "ss", "-H", "-lnt").stdout.splitlines()
    bound = {}
    for line in sockets:
        fields = line.split()
        if len(fields) < 4:
            continue
        address = fields[3]
        try:
            host, port_text = address.rsplit(":", 1)
            port = int(port_text)
        except ValueError:
            continue
        host = host.strip("[]")
        try:
            if ipaddress.ip_address(host).version == 6:
                lab.block("This candidate is IPv4-only and refuses an IPv6 listening socket")
        except ValueError:
            if ":" in host:
                lab.block("This candidate is IPv4-only and refuses an IPv6 listening socket")
        if host in ("*", "0.0.0.0"):
            host = "0.0.0.0"
        bound.setdefault(port, set()).add(host)
    if peer_port not in bound or not (node_ip in bound[peer_port] or "0.0.0.0" in bound[peer_port]):
        lab.block("The actual etcd peer URL did not match a node-bound listening socket")
    if client_port not in bound:
        lab.block("The actual etcd client URL did not match a listening socket")
    client_node_bound = any(host not in ("127.0.0.1", "localhost")
                            for host in bound[client_port])
    api_manifest = _node(lab, node, "cat", "/etc/kubernetes/manifests/kube-apiserver.yaml").stdout
    api_doc = yaml.safe_load(api_manifest)
    api_command = api_doc.get("spec", {}).get("containers", [{}])[0].get("command", [])
    api_urls = _url_list(_flag(api_command, "--etcd-servers"), "API etcd client")
    if any(host not in ("127.0.0.1", "localhost") or port != client_port
           for host, port in api_urls):
        lab.block("API server client path is outside the reviewed local etcd listener")
    return {"client_port": client_port, "peer_port": peer_port,
            "client_node_bound": client_node_bound, "pod": etcd_pod,
            "member_name": member_name,
            "advertised_peer_urls": [f"https://{host}:{port}" for host, port in advertised],
            "peer_urls": [f"https://{host}:{port}" for host, port in peer],
            "client_urls": [f"https://{host}:{port}" for host, port in client]}


def _tcp_pod(lab, probe, ip, port):
    result = lab.kubectl("-n", "saf-test", "exec", f"pod/{probe}", "--",
                         "python", "-c", CONNECT, ip, str(port), timeout=10)
    value = result.stdout.strip()
    if value not in ("open", "closed"):
        lab.block("The owned Pod host-listener probe did not return a bounded Boolean outcome")
    return value


def _tcp_worker(lab, worker, ip, port):
    script = ("if timeout 3 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "
              f"{shlex.quote(ip)} {int(port)} >/dev/null 2>&1; then printf open; "
              "else printf closed; fi")
    result = _node(lab, worker, "bash", "-ceu", script, timeout=8)
    value = result.stdout.strip()
    if value not in ("open", "closed"):
        lab.block("The owned worker host-listener probe did not return a bounded Boolean outcome")
    return value


def _client_health(lab, row):
    pod_name = row["pod"]["metadata"]["name"]
    command = ["etcdctl", "--endpoints=https://127.0.0.1:2379",
               f"--cacert={ETCD_CA}", f"--cert={ETCD_HEALTH_CERT}",
               f"--key={ETCD_HEALTH_KEY}", "endpoint", "health"]
    result = lab.kubectl("-n", "kube-system", "exec", pod_name, "-c", "etcd", "--",
                         *command, timeout=15)
    return result.returncode == 0 and " is healthy:" in result.stdout


def _membership(lab, member_rows):
    source = next(iter(member_rows.values()))
    pod_name = source["pod"]["metadata"]["name"]
    result = lab.kubectl(
        "-n", "kube-system", "exec", pod_name, "-c", "etcd", "--", "etcdctl",
        "--endpoints=https://127.0.0.1:2379", f"--cacert={ETCD_CA}",
        f"--cert={ETCD_HEALTH_CERT}", f"--key={ETCD_HEALTH_KEY}",
        "member", "list", "--write-out=json", timeout=15)
    members = _json(result).get("members", [])
    return {(str(row.get("ID")), row.get("name"), tuple(sorted(row.get("peerURLs", []))))
            for row in members}


def _expected_membership(lab, member_rows):
    """Bind native endpoint member IDs to each manifest name and guarded IP."""
    expected = set()
    for row in member_rows.values():
        pod_name = row["pod"]["metadata"]["name"]
        result = lab.kubectl(
            "-n", "kube-system", "exec", pod_name, "-c", "etcd", "--", "etcdctl",
            "--endpoints=https://127.0.0.1:2379", f"--cacert={ETCD_CA}",
            f"--cert={ETCD_HEALTH_CERT}", f"--key={ETCD_HEALTH_KEY}",
            "endpoint", "status", "--write-out=json", timeout=15)
        statuses = _json(result)
        if not isinstance(statuses, list) or len(statuses) != 1:
            lab.block("A local etcd endpoint did not return one bounded native status")
        member_id = statuses[0].get("Status", {}).get("header", {}).get("member_id")
        if not isinstance(member_id, int) or member_id <= 0:
            lab.block("The local etcd endpoint did not expose its native member ID")
        expected.add((str(member_id), row["member_name"],
                      tuple(sorted(row["advertised_peer_urls"]))))
    if len(expected) != len(member_rows):
        lab.block("Native etcd endpoint identities were not unique across guarded members")
    return expected


def _api_ready(lab):
    result = lab.kubectl("get", "--raw=/readyz", timeout=15, allow_failure=True)
    return result.returncode == 0 and result.stdout.strip() == "ok"


def _api_marker(lab, name):
    value = "synthetic-0102-019-host-guard-v1"
    payload = {"apiVersion": "v1", "kind": "ConfigMap",
               "metadata": {"name": name, "namespace": "saf-test"},
               "data": {"marker": value}}
    created = lab.kubectl("-n", "saf-test", "create", "-f", "-", "-o", "json",
                          payload=json.dumps(payload), allow_failure=True)
    if created.returncode:
        return False
    readback = lab.kubectl("-n", "saf-test", "get", "configmap", name, "-o", "json",
                           allow_failure=True)
    return readback.returncode == 0 and _json(readback).get("data") == {"marker": value}


def _peer_tls(lab, source, target, target_ip, peer_port, expected_fingerprint):
    script = r'''set -eu
target_ip="$1"; target_port="$2"; expected="$3"
out="$(timeout 8 openssl s_client -tls1_2 -msg -showcerts -verify_return_error \
  -verify_ip "$target_ip" -connect "$target_ip:$target_port" \
  -CAfile /etc/kubernetes/pki/etcd/ca.crt \
  -cert /etc/kubernetes/pki/etcd/peer.crt \
  -key /etc/kubernetes/pki/etcd/peer.key </dev/null 2>&1)" || true
printf '%s\n' "$out" | grep -Eq 'Verify return code: 0|Verification: OK' || { echo trust_check_failed; exit 1; }
printf '%s\n' "$out" | grep -Eq '^>>> .*Handshake.*Finished$' || { echo client_finished_absent; exit 1; }
printf '%s\n' "$out" | grep -Eq '^<<< .*Handshake.*Finished$' || { echo peer_finished_absent; exit 1; }
actual="$(printf '%s\n' "$out" | awk '/BEGIN CERTIFICATE/{inside=1} inside{print} /END CERTIFICATE/{exit}' \
  | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')"
test -n "$actual" && test "$actual" = "$expected" || { echo peer_leaf_mismatch; exit 1; }
printf 'verified_leaf_match\n'
'''
    result = _node(lab, source, "sh", "-ceu", script, "--", target_ip,
                   str(peer_port), expected_fingerprint, timeout=12, allow_failure=True)
    return result.returncode == 0 and result.stdout.strip() == "verified_leaf_match"


def _fingerprint(lab, node, path):
    result = _node(lab, node, "openssl", "x509", "-in", path, "-noout",
                   "-fingerprint", "-sha256", timeout=8)
    match = re.search(r"=([0-9A-Fa-f:]+)", result.stdout)
    if not match:
        lab.block("A public etcd certificate fingerprint was not observable")
    return match.group(1).replace(":", "").lower()


def _guard_install(lab, node, peer_port, client_port, client_node_bound, peer_ips):
    commands = [
        f"! iptables -w -S {GUARD} >/dev/null 2>&1",
        f"iptables -w -N {GUARD}",
        # If any later setup command fails, remove only the chain just created.
        f"trap 'while iptables -w -C INPUT -j {GUARD} 2>/dev/null; do iptables -w -D INPUT -j {GUARD}; done; iptables -w -F {GUARD} 2>/dev/null || true; iptables -w -X {GUARD} 2>/dev/null || true' EXIT",
        f"iptables -w -I INPUT 1 -j {GUARD}",
        f"iptables -w -A {GUARD} -i lo -j RETURN",
    ]
    for peer_ip in sorted(set(peer_ips)):
        commands.append(f"iptables -w -A {GUARD} -p tcp --dport {peer_port} "
                        f"-s {shlex.quote(peer_ip)} -j RETURN")
    commands.append(f"iptables -w -A {GUARD} -p tcp --dport {peer_port} -j DROP")
    # Local kubeadm client URLs remain on loopback. Apply an external guard only
    # where ss confirmed a node-bound client listener in the owned profile.
    if client_node_bound:
        commands.append(f"iptables -w -A {GUARD} -p tcp --dport {client_port} -j DROP")
    commands.extend([f"iptables -w -A {GUARD} -j RETURN",
                     "trap - EXIT", "printf guard_installed"])
    _node(lab, node, "sh", "-ceu", "\n".join(commands), timeout=12)


def _guard_remove(lab, node):
    script = f'''set -eu
while iptables -w -C INPUT -j {GUARD} 2>/dev/null; do
  iptables -w -D INPUT -j {GUARD}
done
if iptables -w -S {GUARD} >/dev/null 2>&1; then
  iptables -w -F {GUARD}
  iptables -w -X {GUARD}
fi
! iptables -w -C INPUT -j {GUARD} 2>/dev/null
! iptables -w -S {GUARD} >/dev/null 2>&1
printf guard_removed
'''
    result = _node(lab, node, "sh", "-ceu", script, timeout=12, allow_failure=True)
    if result.returncode or result.stdout.strip() != "guard_removed":
        lab.block("The exact owned etcd listener guard did not cleanly restore")


def _drop_count(lab, node, port):
    result = _node(lab, node, "iptables", "-w", "-L", GUARD, "-v", "-x", "-n",
                   timeout=8)
    for line in result.stdout.splitlines():
        if "DROP" in line and f"dpt:{port}" in line:
            return int(line.split()[0])
    lab.block("The owned drop rule counter was not observable")


def _host_inventory(lab):
    version = _json(lab.kubectl("version", "-o", "json"))
    if version.get("serverVersion", {}).get("gitVersion") != "v1.36.1":
        lab.block("This reviewed listener profile requires Kubernetes v1.36.1")
    nodes = _json(lab.kubectl("get", "nodes", "-o", "json"))["items"]
    control = [row for row in nodes if "node-role.kubernetes.io/control-plane"
               in row.get("metadata", {}).get("labels", {})]
    workers = [row for row in nodes if row not in control]
    if len(control) != 3 or len(workers) != 1:
        lab.block("The exact owned topology must be three control planes and one worker")
    control.sort(key=lambda row: row["metadata"]["name"])
    etcd = _pods_by_node(lab, "etcd")
    apis = _pods_by_node(lab, "kube-apiserver")
    control_names = {row["metadata"]["name"] for row in control}
    if set(etcd) != control_names or set(apis) != control_names:
        lab.block("Actual etcd and API static Pods did not map one-to-one to the three owned nodes")
    worker_name = workers[0]["metadata"]["name"]
    member_rows = {}
    inspect_worker = lab.command(
        "docker", "inspect", "--format",
        '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}', worker_name)
    if inspect_worker.stdout.strip() != lab.cluster:
        lab.block("The worker probe source is not owned by this exact Kind cluster")
    for ordinal, row in enumerate(control, 1):
        node_name = row["metadata"]["name"]
        ip = _internal_ipv4(row)
        inspect = lab.command(
            "docker", "inspect", "--format",
            '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}', node_name)
        if inspect.stdout.strip() != lab.cluster:
            lab.block("An etcd node container is not owned by this exact Kind cluster")
        _node(lab, node_name, "sh", "-ceu", "command -v iptables >/dev/null; "
              "command -v ss >/dev/null; command -v openssl >/dev/null", timeout=8)
        _node(lab, worker_name, "sh", "-ceu", "command -v bash >/dev/null", timeout=8)
        pod = etcd[node_name]
        listeners = _listeners(lab, node_name, ip, pod)
        if (listeners["pod"].get("status", {}).get("phase") != "Running"
                or len(listeners["pod"].get("status", {}).get("containerStatuses", [])) != 1
                or listeners["pod"]["status"]["containerStatuses"][0].get("ready") is not True):
            lab.block("An actual etcd static Pod is not ready")
        listeners.update({"node": node_name, "ip": ip, "ordinal": ordinal,
                          "api_pod": apis[node_name]})
        member_rows[node_name] = listeners
    return member_rows, worker_name, _internal_ipv4(workers[0])


def _api_baseline(lab, members, marker_name):
    health = all(_client_health(lab, row) for row in members.values())
    api = _api_ready(lab) and _api_marker(lab, marker_name)
    return health and api


def run(lab):
    context = lab.command("docker", "context", "show", timeout=8).stdout.strip()
    if context != lab.context:
        lab.block("Docker context does not match the runner-owned case context")
    members, worker, worker_ip = _host_inventory(lab)
    _marker_checks(lab, worker)

    baseline_membership = _membership(lab, members)
    expected_membership = _expected_membership(lab, members)
    if (len(baseline_membership) != 3 or baseline_membership != expected_membership
            or not _api_baseline(lab, members, "etcd-host-baseline")):
        lab.block("Three-member etcd/API baseline did not pass before host listener probes")

    before_reachability = []
    for row in members.values():
        # Verify externalized peer reachability from both a normal Pod and the
        # worker node namespace before exercising the guard.
        pod_peer = _tcp_pod(lab, PROBES["ordinary"], row["ip"], row["peer_port"])
        worker_peer = _tcp_worker(lab, worker, row["ip"], row["peer_port"])
        client_paths = {"pod": "not_node_bound", "worker": "not_node_bound"}
        if row["client_node_bound"]:
            client_paths = {
                "pod": _tcp_pod(lab, PROBES["ordinary"], row["ip"], row["client_port"]),
                "worker": _tcp_worker(lab, worker, row["ip"], row["client_port"]),
            }
        before_reachability.append(pod_peer == worker_peer == "open"
                                   and all(value in ("open", "not_node_bound")
                                           for value in client_paths.values()))
    lab.check("positive", "Actual kubeadm client and peer binds map to three ready owned members",
              all(row["peer_port"] == next(iter({item["peer_port"] for item in members.values()}))
                  for row in members.values())
              and len(baseline_membership) == 3
              and baseline_membership == expected_membership,
              {"owned_control_plane_members": len(members),
               "node_bound_peer_listeners_observed": len(members),
               "loopback_client_paths_preserved": all(_client_health(lab, row)
                                                        for row in members.values())})
    lab.check("red", "Worker and ordinary Pod reach each real node-bound peer listener before the host guard",
              all(before_reachability),
              {"worker_and_workload_baseline_reachable_for_all_members": all(before_reachability),
               "members_observed": len(before_reachability)})

    peer_ips = [row["ip"] for row in members.values()]
    denied_all = True
    positive_all = True
    peer_tls_pairs_total = 0
    peer_tls_pairs_ok = True
    for ordinal, (node_name, row) in enumerate(members.items(), 1):
        installed = False
        try:
            _guard_install(lab, node_name, row["peer_port"], row["client_port"],
                           row["client_node_bound"], peer_ips)
            installed = True
            peer_drop_before = _drop_count(lab, node_name, row["peer_port"])
            client_drop_before = (_drop_count(lab, node_name, row["client_port"])
                                  if row["client_node_bound"] else None)
            blocked_pod = _tcp_pod(lab, PROBES["ordinary"], row["ip"], row["peer_port"])
            blocked_worker = _tcp_worker(lab, worker, row["ip"], row["peer_port"])
            peer_drop_after = _drop_count(lab, node_name, row["peer_port"])
            client_blocked = True
            if row["client_node_bound"]:
                client_blocked = (_tcp_pod(lab, PROBES["ordinary"], row["ip"], row["client_port"]) == "closed"
                                  and _tcp_worker(lab, worker, row["ip"], row["client_port"]) == "closed"
                                  and _drop_count(lab, node_name, row["client_port"]) >= client_drop_before + 2)
            dropped = (blocked_pod == blocked_worker == "closed"
                       and peer_drop_after >= peer_drop_before + 2 and client_blocked)

            target_fingerprint = _fingerprint(lab, node_name, ETCD_PEER_CERT)
            peer_sources = [item for name, item in members.items() if name != node_name]
            peer_results = []
            for source in peer_sources:
                peer_results.append(_peer_tls(
                    lab, source["node"], row["node"], row["ip"],
                    row["peer_port"], target_fingerprint))
            peer_tls_pairs_total += len(peer_results)
            target_peer_ok = len(peer_results) == len(members) - 1 and all(peer_results)
            peer_tls_pairs_ok = peer_tls_pairs_ok and target_peer_ok
            client_ok = _client_health(lab, row)
            member_ok = (_membership(lab, members) == expected_membership
                         and all(_client_health(lab, item) for item in members.values()))
            api_ok = (_api_ready(lab) and _api_marker(lab, f"etcd-host-guard-{ordinal}"))
            positive = target_peer_ok and client_ok and member_ok and api_ok
            denied_all = denied_all and dropped
            positive_all = positive_all and positive
            if not dropped or not positive:
                lab.block("The owned host listener guard did not preserve exact etcd/API comparators")
        finally:
            if installed:
                _guard_remove(lab, node_name)
        if not _api_baseline(lab, members, f"etcd-host-restored-{ordinal}"):
            lab.block("API readiness or local etcd health failed after exact guard removal")

    lab.check("green", "Owned node input guards block worker and workload connects to actual etcd host peers",
              denied_all,
              {"worker_and_workload_denied_on_all_three_members": denied_all,
               "owned_drop_counters_confirmed": denied_all})
    lab.check("positive", "Real peer TLS, local etcd clients, membership, API readiness and marker storage remain healthy",
              positive_all and peer_tls_pairs_total == 6 and peer_tls_pairs_ok,
              {"all_six_directed_member_peer_tls_pairs_verified":
                   peer_tls_pairs_total == 6 and peer_tls_pairs_ok,
               "local_healthcheck_client_paths": positive_all,
               "member_identity_unchanged": positive_all,
               "api_ready_and_marker_readback": positive_all,
               "three_member_quorum_restored_after_each_guard": positive_all})
