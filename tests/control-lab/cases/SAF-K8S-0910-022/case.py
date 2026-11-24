"""Witness scoped authorization between two independently owned clusters."""
import importlib.util
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
IDENTITY_CASE = HERE.parent / "SAF-K8S-0910-021"
SCOPE = (
    "Two actual Kind API servers and one case-owned route. Both clients authenticate with distinct "
    "fixture certificates and exercise both operations before and after the exact route policy. "
    "The destination's own application log independently records each governed decision. "
    "The fixture covers these two operations and does not claim production mesh or RBAC coverage."
)


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
        for account in accounts:
            lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account},
                        "automountServiceAccountToken": False})
            secret(lab.kubectl, account)
            lab.create(identity.workload(account, image, credential=True))
        peer("wait", "--for=condition=Ready", f"pod/{identity.NAME}", "--timeout=80s", timeout=90)
        for account in accounts:
            identity.ready(lab, account)

        def send(caller, route):
            result = lab.kubectl("exec", caller, "--", "python", "/code/route_service.py",
                                 address, str(port), identity.DNS, route, timeout=15)
            return json.loads(result.stdout)

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
