"""Witness scoped authorization between two independently owned clusters."""
import importlib.util
import json
from pathlib import Path
import ipaddress
import time

HERE = Path(__file__).resolve().parent
IDENTITY_CASE = HERE.parent / "SAF-K8S-0910-021"
SCOPE = (
    "Two actual Kind API servers and one case-owned route. Both clients authenticate with distinct "
    "fixture certificates and exercise both operations before and after the exact route policy. "
    "The destination's own application log independently records each governed decision. "
    "The fixture adds source-cluster egress policy over the exact private peer node IP and dynamic NodePort. "
    "It does not infer or match the NodePort-observed source address and does not claim production CNI coverage."
)


def _network_platform_check(lab):
    version = lab.command("kind", "version").stdout.strip()
    if not version.startswith("kind v0.32.0"):
        lab.block(f"Expected kind v0.32.0 for the reviewed kindnet fixture, got {version!r}")
    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {}).get("gitVersion")
    if server != "v1.36.1":
        lab.block(f"Expected source Kubernetes v1.36.1, got {server!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet", "--timeout=60s", timeout=70)
    obj = json.loads(lab.kubectl("-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    images = [item.get("image", "") for item in obj["spec"]["template"]["spec"]["containers"]]
    if not any("kindnetd" in image for image in images):
        lab.block("The source cluster does not expose the expected kindnet daemonset")
    lab.check("positive", "Source cluster reports pinned Kind/Kubernetes versions and the kindnet daemonset",
              True, {"kind_version": version, "kubernetes_version": server, "kindnet_images": images})


def run(lab):
    spec = importlib.util.spec_from_file_location("saf_operation_identity", IDENTITY_CASE / "case.py")
    identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity)
    runtime = identity.load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_operation_runtime")
    bridge = identity.load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_operation_peer")
    image = runtime.load_runtime(lab)
    root, ca = identity.pki(lab)
    routes = {identity.APPROVED: "/v1/gradient/shard-a", identity.OTHER: "/v1/gradient/shard-b"}
    accounts = tuple(routes)
    pairs = [(caller, route) for caller in accounts for route in routes.values()]
    network_only = "fixture-network-unapproved"
    network_uri = identity.uri(network_only)
    network_route = routes[identity.APPROVED]

    # Add a valid same-CA mTLS identity that is intentionally not selected by
    # the source-cluster network allow policy. It is used only for a fixed marker.
    key = root / f"{network_only}.key"
    cert = root / f"{network_only}.crt"
    csr = root / f"{network_only}.csr"
    ext = root / f"{network_only}.ext"
    ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                   "extendedKeyUsage=clientAuth\n"
                   f"subjectAltName=URI:{network_uri}\n"
                   "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", f"/CN={network_only}", "-keyout", str(key), "-out", str(csr))
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(root / "root.crt"),
                "-CAkey", str(root / "root.key"), "-CAcreateserial", "-days", "1",
                "-sha256", "-extfile", str(ext), "-out", str(cert))

    def config(name, data):
        return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": data}

    def secret(call, name):
        call("create", "secret", "tls", name, "--cert=" + str(root / f"{name}.crt"),
             "--key=" + str(root / f"{name}.key"), "-o", "name")

    with bridge.owned_peer(lab, image) as (peer, address):
        def create(contents):
            return peer("create", "-f", "-", "-o", "json", payload=json.dumps(contents))

        for resource in (config(identity.CODE, {
            "identity_fixture.py": (IDENTITY_CASE / "identity_fixture.py").read_text(),
            "route_service.py": (HERE / "route_service.py").read_text(),
        }), config(identity.TRUST, {"ca.crt": ca.read_text()})):
            create(resource)
            lab.create(resource)

        secret(peer, identity.NAME)
        endpoint = identity.workload(identity.NAME, image, credential=True, server=True)
        endpoint["spec"]["containers"][0]["command"] = ["python", "/code/route_service.py", "serve"]
        create(endpoint)
        service = {"type": "NodePort", "selector": {"app": identity.NAME},
                   "ports": [{"name": "mtls", "port": 8443, "targetPort": 8443}]}
        response = create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": identity.NAME},
                           "spec": service})
        port = json.loads(response.stdout)["spec"]["ports"][0]["nodePort"]
        for account in (*accounts, network_only):
            lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account},
                        "automountServiceAccountToken": False})
            secret(lab.kubectl, account)
            source_pod = identity.workload(account, image, credential=True)
            role = "network-approved" if account in accounts else "network-unapproved"
            source_pod["metadata"]["labels"].update({
                "saf.example/network-scope": "0910-022-source",
                "saf.example/network-role": role,
            })
            lab.create(source_pod)
        peer("wait", "--for=condition=Ready", f"pod/{identity.NAME}", "--timeout=80s", timeout=90)
        for account in (*accounts, network_only):
            identity.ready(lab, account)

        def send(caller, route):
            result = lab.kubectl("exec", caller, "--", "python", "/code/route_service.py",
                                 address, str(port), identity.DNS, route, timeout=15)
            return json.loads(result.stdout)

        def send_network_probe(caller):
            result = lab.kubectl("exec", caller, "--", "python", "/code/route_service.py",
                                 address, str(port), identity.DNS, network_route, timeout=15)
            return json.loads(result.stdout)

        def expected_network(caller):
            return {"status": 200, "tls": "TLSv1.3",
                    "body": {"caller": identity.uri(caller), "operation": network_route,
                             "decision": "accepted"}}

        def peer_events():
            return [json.loads(line) for line in peer("logs", f"pod/{identity.NAME}").stdout.splitlines()
                    if line.startswith("{")]

        def network_event(caller):
            return {"mode": "baseline", "status": 200, "caller": identity.uri(caller),
                    "operation": network_route, "decision": "accepted"}

        def network_policy(name, selector, egress):
            return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                    "metadata": {"name": name, "namespace": "saf-test"},
                    "spec": {"podSelector": {"matchLabels": selector},
                             "policyTypes": ["Egress"], "egress": egress}}

        def verify_network_policy(name, expected_spec):
            policy_obj = json.loads(lab.kubectl("-n", "saf-test", "get", "networkpolicy", name,
                                                "-o", "json").stdout)
            actual = policy_obj.get("spec", {})
            actual.setdefault("egress", [])
            if actual != expected_spec:
                lab.block(f"NetworkPolicy {name} did not match the exact reviewed egress rules")

        def wait_route(caller, expected, *, blocked=False):
            last = None
            for _ in range(6):
                last = send_network_probe(caller)
                if last == expected:
                    return last
                # A successful response while expecting a deny, or a TLS/app
                # failure while expecting a route, is a failed comparison rather
                # than a network-policy denial. Only retry the transient absence.
                if last != {"status": "route-unavailable"}:
                    lab.block(f"Unexpected network route result for {caller}: {last}")
                time.sleep(0.5)
            lab.block(f"Expected network route observation did not settle for {caller}: {last}")

        def reply(caller, route, allowed):
            return {"status": 200 if allowed else 403, "tls": "TLSv1.3",
                    "body": {"caller": identity.uri(caller), "operation": route,
                             "decision": "accepted" if allowed else "operation-not-authorized"}}

        def await_reply(pair, expected, pending):
            deadline = time.monotonic() + 20
            while True:
                result = send(*pair)
                if result == expected:
                    return result
                if result.get("status") not in pending or time.monotonic() >= deadline:
                    peer("get", "service,endpointslice,pod", "-o", "wide", allow_failure=True)
                    peer("logs", f"pod/{identity.NAME}", allow_failure=True)
                    lab.block(f"The private NodePort did not produce {expected} for {pair}: {result}")
                time.sleep(0.25)

        _network_platform_check(lab)
        network_baseline = [wait_route(caller, expected_network(caller))
                            for caller in (identity.APPROVED, identity.OTHER, network_only)]
        expected_network_baseline = [expected_network(caller) for caller in (identity.APPROVED, identity.OTHER, network_only)]
        baseline_events = peer_events()
        expected_baseline_events = [network_event(caller)
                                    for caller in (identity.APPROVED, identity.OTHER, network_only)]
        lab.check("red", "The exact private peer NodePort route works for authenticated source Pods before default deny",
                  network_baseline == expected_network_baseline and baseline_events == expected_baseline_events,
                  {"source_replies": network_baseline, "destination_events": baseline_events})

        default_deny_spec = {"podSelector": {"matchLabels": {"saf.example/network-scope": "0910-022-source"}},
                             "policyTypes": ["Egress"], "egress": []}
        default_deny = network_policy("0910-022-source-egress-default-deny",
                                      {"saf.example/network-scope": "0910-022-source"}, [])
        lab.create(default_deny)
        verify_network_policy("0910-022-source-egress-default-deny", default_deny_spec)
        time.sleep(3)  # bounded policy-programming allowance; the route probes remain low volume
        blocked_default_deny = [wait_route(caller, {"status": "route-unavailable"}, blocked=True)
                                for caller in (identity.APPROVED, identity.OTHER, network_only)]
        denied_events = peer_events()
        lab.check("green", "Default-deny egress blocks the previously working cross-cluster route before the peer application receives requests",
                  blocked_default_deny == [{"status": "route-unavailable"}] * 3
                  and denied_events == baseline_events,
                  {"source_replies": blocked_default_deny,
                   "destination_events_unchanged": denied_events == baseline_events})

        allow_selector = {"saf.example/network-scope": "0910-022-source",
                          "saf.example/network-role": "network-approved"}
        allow_egress = [{"to": [{"ipBlock": {"cidr": str(ipaddress.IPv4Address(address)) + "/32"}}],
                         "ports": [{"protocol": "TCP", "port": port}]}]
        allow_policy = network_policy("0910-022-allow-reviewed-peer-nodeport", allow_selector, allow_egress)
        lab.create(allow_policy)
        time.sleep(3)  # bounded policy-programming allowance; the route probes remain low volume
        allow_spec = {"podSelector": {"matchLabels": allow_selector}, "policyTypes": ["Egress"],
                      "egress": allow_egress}
        verify_network_policy("0910-022-allow-reviewed-peer-nodeport", allow_spec)
        allow_results = [wait_route(caller, expected_network(caller))
                         for caller in (identity.APPROVED, identity.OTHER)]
        unapproved_result = wait_route(network_only, {"status": "route-unavailable"}, blocked=True)
        allow_expected = [expected_network(caller) for caller in (identity.APPROVED, identity.OTHER)]
        allow_events = peer_events()
        expected_allow_events = [network_event(caller) for caller in (identity.APPROVED, identity.OTHER)]
        lab.check("positive", "The exact peer node IP and NodePort are restored only for reviewed source Pods; the other source remains denied",
                  allow_results == allow_expected and unapproved_result == {"status": "route-unavailable"}
                  and allow_events == baseline_events + expected_allow_events,
                  {"allowed_sources": allow_results, "unapproved_source": unapproved_result,
                   "exact_observed_peer_ipv4_and_nodeport_policy": True,
                   "only_approved_source_events": allow_events == baseline_events + expected_allow_events})

        baseline = [await_reply(pairs[0], reply(*pairs[0], True), {"route-unavailable"})]
        baseline.extend(send(*pair) for pair in pairs[1:])
        lab.check("red", "Each authenticated caller can reach both operations before route scoping",
                  baseline == [reply(caller, route, True) for caller, route in pairs], baseline)

        change = {"spec": {"ports": [{"name": "mtls", "port": 8443, "targetPort": 8444, "nodePort": port}]}}
        peer("patch", "service", identity.NAME, "--type=merge", "-p", json.dumps(change))
        denied_pairs = [(caller, route) for caller, route in pairs if routes[caller] != route]
        first, second = denied_pairs
        observed = await_reply(first, reply(*first, False), {"route-unavailable", 200})
        denied = [observed, send(*second)]
        lab.check("green", "Each authenticated caller is denied the other caller's operation",
                  denied == [reply(caller, route, False) for caller, route in denied_pairs], denied)

        allowed = [send(caller, routes[caller]) for caller in accounts]
        expected_allowed = [reply(caller, routes[caller], True) for caller in accounts]
        expected_events = [
            {"mode": "scoped", "status": row["status"], **row["body"]}
            for row in [reply(*first, False), reply(*second, False), *expected_allowed]
        ]
        logs = peer("logs", f"pod/{identity.NAME}").stdout
        events = [event for line in logs.splitlines() if line.startswith("{")
                  if (event := json.loads(line))["mode"] == "scoped"]
        lab.check("positive", "Each caller retains its own operation and the destination records all four decisions",
                  allowed == expected_allowed and events == expected_events,
                  {"allowed": allowed, "destination_events": events})
    (lab.evidence / "cross-cluster-route-authorization.json").write_text(json.dumps({
        "before_policy": baseline, "authorized": allowed, "denied": denied, "destination_events": events,
    }, indent=2, sort_keys=True) + "\n")
