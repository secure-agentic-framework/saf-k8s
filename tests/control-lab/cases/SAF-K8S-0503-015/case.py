"""Check scoped DNS egress to one approved case-owned resolver Pod."""
import json
import time
from pathlib import Path

from fixtures import pod


CONTROL_ID = "SAF-K8S-0503-015"
NAMESPACE = "saf-0503-015"
ROLE_LABEL = "saf-k8s.example/0503-015-role"
CLIENT = "saf-0503-015-selected-client"
COMPARATOR = "saf-0503-015-unselected-comparator"
APPROVED = "saf-0503-015-approved-dns"
UNAPPROVED = "saf-0503-015-unapproved-dns"
QNAME = "path.saf-0503-015.test"
APPROVED_ANSWER = "192.0.2.53"
UNAPPROVED_ANSWER = "198.51.100.53"
DNS_PORT = 5353
OTHER_PORT = 5354
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster with the ready bundled, policy-capable "
    "kindnet CNI and one case-owned namespace. Two case-owned non-root Python DNS fixture "
    "Pods serve only the reserved .test name path.saf-0503-015.test over UDP and TCP on "
    "ports 5353 and 5354, returning only RFC 5737 TEST-NET-1/2 marker addresses. An exact "
    "selected client and an unselected comparator send ordinary DNS wire queries directly "
    "to those Pod IPs. The native Kubernetes NetworkPolicy permits the selected client only "
    "to the approved fixture Pod on UDP/TCP 5353. No public target, upstream forwarding, "
    "external DNS, host networking, privilege change, evasion, or data transfer is used. "
    "The case does not establish production CNI support, cluster-wide resolver configuration, "
    "NodeLocal DNSCache behavior, policy governance, or controls against node-local paths."
)


DNS_SERVER = r'''import socket, struct, threading
QNAME = "path.saf-0503-015.test"
ANSWER = {"approved": "192.0.2.53", "unapproved": "198.51.100.53"}[__import__("sys").argv[1]]
PORTS = (5353, 5354)
def response(packet):
    if len(packet) < 17:
        return b""
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    if qd != 1:
        return b""
    pos = 12
    labels = []
    while pos < len(packet) and packet[pos]:
        size = packet[pos]
        if size & 0xc0:
            return b""
        pos += 1
        if pos + size > len(packet):
            return b""
        labels.append(packet[pos:pos+size].decode("ascii", "strict"))
        pos += size
    pos += 1
    if pos + 4 > len(packet):
        return b""
    qtype, qclass = struct.unpack("!HH", packet[pos:pos+4])
    question = packet[12:pos+4]
    matched = ".".join(labels).lower() == QNAME and qtype == 1 and qclass == 1
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(ANSWER) if matched else b""
    rcode = 0 if matched else 3
    header = struct.pack("!HHHHHH", ident, 0x8180 | rcode, 1, int(matched), 0, 0)
    return header + question + answer
def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", port))
    while True:
        packet, peer = s.recvfrom(4096); reply = response(packet)
        if reply: s.sendto(reply, peer)
def tcp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(16)
    while True:
        conn, _ = s.accept()
        try:
            def receive(size):
                chunks = []
                while sum(map(len, chunks)) < size:
                    chunk = conn.recv(size-sum(map(len, chunks)))
                    if not chunk: return b""
                    chunks.append(chunk)
                return b"".join(chunks)
            prefix = receive(2)
            if len(prefix) == 2:
                size = struct.unpack("!H", prefix)[0]; packet = receive(size)
                reply = response(packet)
                if reply: conn.sendall(struct.pack("!H", len(reply)) + reply)
        finally: conn.close()
for port in PORTS:
    threading.Thread(target=udp, args=(port,), daemon=True).start()
    threading.Thread(target=tcp, args=(port,), daemon=True).start()
threading.Event().wait()
'''


DNS_QUERY = r'''import json, secrets, socket, struct, sys
server, port, transport, name, expected = sys.argv[1:]
ident = secrets.randbits(16)
question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\0" + struct.pack("!HH", 1, 1)
packet = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "UDP" else socket.SOCK_STREAM)
s.settimeout(1.5)
def receive(size):
    chunks = []
    while sum(map(len, chunks)) < size:
        chunk = s.recv(size-sum(map(len, chunks)))
        if not chunk: raise OSError("short DNS TCP response")
        chunks.append(chunk)
    return b"".join(chunks)
try:
    if transport == "UDP":
        s.sendto(packet, (server, int(port))); data, _ = s.recvfrom(4096)
    else:
        s.connect((server, int(port))); s.sendall(struct.pack("!H", len(packet)) + packet)
        prefix = receive(2)
        if len(prefix) != 2: raise OSError("short DNS TCP length")
        size = struct.unpack("!H", prefix)[0]
        data = receive(size)
    if len(data) < 12 or struct.unpack("!H", data[:2])[0] != ident:
        raise RuntimeError("invalid DNS response")
    flags, answers = struct.unpack("!H", data[2:4])[0], struct.unpack("!H", data[6:8])[0]
    pos = 12
    while pos < len(data) and data[pos] != 0:
        if data[pos] & 0xc0 == 0xc0: pos += 2; break
        pos += data[pos] + 1
    else: pos += 1
    pos += 4; found = []
    for _ in range(answers):
        if pos + 2 > len(data): raise RuntimeError("truncated answer name")
        if data[pos] & 0xc0 == 0xc0: pos += 2
        else:
            while data[pos] != 0: pos += data[pos] + 1
            pos += 1
        if pos + 10 > len(data): raise RuntimeError("truncated answer record")
        typ, cls, ttl, size = struct.unpack("!HHIH", data[pos:pos+10]); pos += 10
        if typ == 1 and cls == 1 and size == 4: found.append(socket.inet_ntoa(data[pos:pos+4]))
        pos += size
    print(json.dumps({"response": True, "rcode": flags & 15, "answer_matches": found == [expected],
                      "answer_count": len(found), "transport": transport}, sort_keys=True))
except (OSError, TimeoutError) as error:
    print(json.dumps({"response": False, "timed_out": isinstance(error, TimeoutError) or isinstance(error, socket.timeout),
                      "transport": transport}, sort_keys=True))
finally:
    s.close()
'''


def create(lab, resource):
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(resource))


def add_pod(lab, name, role=None):
    labels = {ROLE_LABEL: role} if role else {}
    command = ["python", "-u", "-c", "import time; time.sleep(3600)"]
    if role in ("approved-dns", "unapproved-dns"):
        command = ["python", "-u", "-c", DNS_SERVER, role.split("-")[0]]
    workload = pod(
        name,
        [{"name": "fixture", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
          "command": command,
          "ports": ([{"name": "dns-udp", "containerPort": DNS_PORT, "protocol": "UDP"},
                     {"name": "dns-tcp", "containerPort": DNS_PORT, "protocol": "TCP"},
                     {"name": "alt-udp", "containerPort": OTHER_PORT, "protocol": "UDP"},
                     {"name": "alt-tcp", "containerPort": OTHER_PORT, "protocol": "TCP"}]
                    if role in ("approved-dns", "unapproved-dns") else []),
          "securityContext": {"allowPrivilegeEscalation": False,
                              "capabilities": {"drop": ["ALL"]},
                              "readOnlyRootFilesystem": True,
                              "runAsNonRoot": True, "runAsUser": 65532,
                              "runAsGroup": 65532,
                              "seccompProfile": {"type": "RuntimeDefault"}},
          "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                        "limits": {"cpu": "100m", "memory": "64Mi"}}}],
        automountServiceAccountToken=False,
        securityContext={"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                         "seccompProfile": {"type": "RuntimeDefault"}},
    )
    workload["metadata"].update(namespace=NAMESPACE, labels=labels)
    create(lab, workload)
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl("-n", NAMESPACE, "get", f"pod/{name}", "-o", "json").stdout)
    if current.get("metadata", {}).get("name") != name or not current.get("status", {}).get("podIP"):
        lab.block(f"Case-owned Pod {NAMESPACE}/{name} was not assigned a Pod IP")
    return current["status"]["podIP"]


def query(lab, client, server, port, transport, expected):
    result = lab.kubectl(
        "-n", NAMESPACE, "exec", f"pod/{client}", "--", "python", "-c", DNS_QUERY,
        server, str(port), transport, QNAME, expected,
        allow_failure=False, timeout=12,
    )
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        lab.block("DNS query probe did not return its stable JSON observation")


def expect(lab, phase, claim, client, server, port, transport, expected, allowed):
    deadline = time.monotonic() + 12
    observed = None
    consecutive = 0
    while time.monotonic() < deadline:
        observed = query(lab, client, server, port, transport, expected)
        if allowed:
            passed = observed.get("response") is True and observed.get("rcode") == 0 and observed.get("answer_matches") is True
        else:
            passed = observed.get("response") is False and observed.get("timed_out") is True
        consecutive = consecutive + 1 if passed else 0
        if consecutive == 2:
            break
        time.sleep(0.4)
    lab.check(phase, claim, consecutive == 2,
              {"namespace": NAMESPACE, "source_pod": client,
               "destination_pod": APPROVED if expected == APPROVED_ANSWER else UNAPPROVED,
               "qname": QNAME, "transport": transport, "destination_port": port,
               "expected_response": allowed, "two_consecutive_observations": consecutive == 2,
               "answer_matches_expected": allowed and bool(observed and observed.get("answer_matches"))})


def verify_platform(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    server_version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet", "--timeout=70s", timeout=80)
    cni = json.loads(lab.kubectl("-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    images = [item["image"] for item in cni["spec"]["template"]["spec"]["containers"]]
    identified = kind_version.startswith("kind v0.32.0") and server_version == "v1.36.1" and any("kindnetd" in image for image in images)
    lab.check("positive", "The pinned v1.36.1 Kind cluster and policy-capable bundled kindnet are ready",
              identified, {"kind_version": kind_version, "kubernetes_version": server_version,
                           "cni_daemonset": "kube-system/kindnet", "cni_images": images})
    if not identified:
        lab.block("The case requires its pinned Kind v0.32.0 / Kubernetes v1.36.1 platform")


def run(lab):
    verify_platform(lab)
    lab.kubectl("create", "namespace", NAMESPACE)
    approved_ip = add_pod(lab, APPROVED, "approved-dns")
    unapproved_ip = add_pod(lab, UNAPPROVED, "unapproved-dns")
    add_pod(lab, CLIENT, "selected-client")
    add_pod(lab, COMPARATOR)
    diagnostic = lab.evidence / "diagnostics"
    diagnostic.mkdir(exist_ok=True)
    (diagnostic / "dynamic-pod-addresses.json").write_text(json.dumps({
        "scope": "run-specific diagnostic; not a stable assertion",
        "namespace": NAMESPACE,
        "pods": {APPROVED: approved_ip, UNAPPROVED: unapproved_ip},
    }, indent=2) + "\n")

    # Every direct path and listener port is live before policy is applied.
    for client in (CLIENT, COMPARATOR):
        for name, address, answer in ((APPROVED, approved_ip, APPROVED_ANSWER),
                                      (UNAPPROVED, unapproved_ip, UNAPPROVED_ANSWER)):
            for port in (DNS_PORT, OTHER_PORT):
                for transport in ("UDP", "TCP"):
                    expect(lab, "red", f"Without policy, {client} resolves through {name} on {transport}/{port}",
                           client, address, port, transport, answer, True)

    # Confirm the selector, policy types, sole egress peer and exact transport/port set.
    policy_path = Path(__file__).with_name("network-policy.yaml")
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(policy_path))
    policy = json.loads(lab.kubectl("-n", NAMESPACE, "get", "networkpolicy",
                                    "saf-0503-015-approved-dns-only", "-o", "json").stdout)
    client_pod = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", CLIENT, "-o", "json").stdout)
    comparator_pod = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", COMPARATOR, "-o", "json").stdout)
    approved_pod = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", APPROVED, "-o", "json").stdout)
    unapproved_pod = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", UNAPPROVED, "-o", "json").stdout)
    spec = policy.get("spec", {})
    selected = client_pod["metadata"].get("labels", {}).get(ROLE_LABEL) == "selected-client"
    exact_selector = spec.get("podSelector") == {"matchLabels": {ROLE_LABEL: "selected-client"}}
    comparator_unselected = not (
        comparator_pod["metadata"].get("labels", {}).get(ROLE_LABEL) == "selected-client")
    approved_fixture_label = approved_pod["metadata"].get("labels", {}).get(ROLE_LABEL) == "approved-dns"
    unapproved_fixture_excluded = unapproved_pod["metadata"].get("labels", {}).get(ROLE_LABEL) == "unapproved-dns"
    only_egress = spec.get("policyTypes") == ["Egress"] and len(spec.get("egress", [])) == 1
    rule = spec.get("egress", [{}])[0]
    exact_peer = rule.get("to") == [{"podSelector": {"matchLabels": {ROLE_LABEL: "approved-dns"}}}]
    exact_ports = sorted((item.get("protocol"), item.get("port")) for item in rule.get("ports", [])) == [
        ("TCP", DNS_PORT), ("UDP", DNS_PORT)]
    existing_policies = json.loads(lab.kubectl("-n", NAMESPACE, "get", "networkpolicies", "-o", "json").stdout)["items"]
    sole_policy = len(existing_policies) == 1 and existing_policies[0]["metadata"]["name"] == "saf-0503-015-approved-dns-only"
    lab.check("positive", "The exact selected workload has one native egress policy for approved Pod UDP/TCP DNS port",
              selected and exact_selector and comparator_unselected and approved_fixture_label
              and unapproved_fixture_excluded and only_egress and exact_peer and exact_ports and sole_policy,
              {"namespace": NAMESPACE, "selected_pod": CLIENT, "comparator_pod": COMPARATOR,
               "policy_name": "saf-0503-015-approved-dns-only", "selected_label_matches": selected,
               "exact_pod_selector": exact_selector, "comparator_unselected": comparator_unselected,
               "approved_fixture_label_matches": approved_fixture_label,
               "unapproved_fixture_is_distinct": unapproved_fixture_excluded,
               "egress_only": only_egress, "exact_approved_pod_peer": exact_peer,
               "only_udp_tcp_5353": exact_ports, "sole_namespace_policy": sole_policy})

    for transport in ("UDP", "TCP"):
        expect(lab, "positive", f"Selected workload retains approved DNS continuity over {transport}/5353",
               CLIENT, approved_ip, DNS_PORT, transport, APPROVED_ANSWER, True)
        expect(lab, "green", f"Selected workload cannot resolve through unapproved Pod over {transport}/5353",
               CLIENT, unapproved_ip, DNS_PORT, transport, UNAPPROVED_ANSWER, False)
        expect(lab, "green", f"Selected workload cannot use the alternate approved-Pod port over {transport}/5354",
               CLIENT, approved_ip, OTHER_PORT, transport, APPROVED_ANSWER, False)
        expect(lab, "positive", f"Unselected comparator remains unaffected on unapproved DNS over {transport}/5353",
               COMPARATOR, unapproved_ip, DNS_PORT, transport, UNAPPROVED_ANSWER, True)
        expect(lab, "positive", f"Unselected comparator remains unaffected on approved DNS over {transport}/5353",
               COMPARATOR, approved_ip, DNS_PORT, transport, APPROVED_ANSWER, True)
        expect(lab, "positive", f"Alternate approved-Pod DNS port remains healthy for the comparator over {transport}/5354",
               COMPARATOR, approved_ip, OTHER_PORT, transport, APPROVED_ANSWER, True)
