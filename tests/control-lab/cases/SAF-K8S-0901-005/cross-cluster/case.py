"""Run the pinned Flower Fleet workflow between separately owned Kind clusters."""

from contextlib import contextmanager
from ipaddress import IPv4Address
import json
from pathlib import Path
import runpy
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace

from fixtures import container, pod, ready
from lab import NODE_IMAGE

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
RELAY_CONFIG = "cross-cluster-fleet"
retirement = runpy.run_path(str(HERE / "retirement.py"))
ROSTER = retirement["ROSTER"]
GATEWAY_LABEL = {"cross-cluster-fleet": "gateway"}
PEER_LABEL = {"cross-cluster-fleet": "peer"}
PROBE = "fixture-fleet-unenrolled"
PARTICIPANT_IDENTITIES = ("participant-a", "participant-b", "participant-c")
CLI_COMMAND = (
    'work=$(mktemp -d); trap \'rm -rf "$work"\' EXIT; '
    'cp /flowerapp/pyproject.toml /flowerapp/client_app.py '
    '/flowerapp/server_app.py "$work/"; cd "$work"; flwr run . fixture --stream'
)


def obj(client, *args):
    return json.loads(client.kubectl(*args, "-o", "json").stdout)


def create(client, kind, name, api_version="v1", **fields):
    return client.create({"apiVersion": api_version, "kind": kind, "metadata": {"name": name}, **fields})


def bridge_address(lab, owner):
    name = f"{owner.cluster}-control-plane"
    node = obj(owner, "get", "node", name)
    if node["metadata"]["name"] != name:
        lab.block("The cluster did not expose its exact owned Kind control plane")
    node_ips = [entry["address"] for entry in node["status"]["addresses"] if entry["type"] == "InternalIP"]
    network = json.loads(lab.command("docker", "inspect", "--format",
                                     '{{json (index .NetworkSettings.Networks "kind")}}', name).stdout)
    bridge_ip = IPv4Address(network["IPAddress"])
    if str(bridge_ip) not in node_ips or bridge_ip.is_global or bridge_ip.is_link_local or bridge_ip.is_loopback:
        lab.block("The Kubernetes node does not identify its private Kind bridge address")
    return str(bridge_ip), network["NetworkID"]


@contextmanager
def owned_peer(lab, image, directory):
    peer = type(lab)(lab.evidence, lab.context, directory / "peer-kubeconfig")
    if peer.cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Refusing to reuse an existing secondary cluster")
    config = directory / "peer-kind.json"
    config.write_text(json.dumps({
        "kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4",
        "networking": {"apiServerAddress": "127.0.0.1", "podSubnet": "10.246.0.0/16",
                       "serviceSubnet": "10.102.0.0/16"},
        "nodes": [{"role": "control-plane"}],
    }), encoding="utf-8")
    try:
        lab.command("kind", "create", "cluster", "--name", peer.cluster, "--image", NODE_IMAGE,
                    "--kubeconfig", str(peer.kubeconfig), "--config", str(config), "--wait", "90s", timeout=420)
        main_uid = obj(lab, "get", "namespace", "kube-system")["metadata"]["uid"]
        peer_uid = obj(peer, "get", "namespace", "kube-system")["metadata"]["uid"]
        if not main_uid or not peer_uid or main_uid == peer_uid:
            lab.block("The two Kubernetes APIs need distinct cluster identities")
        source_address, source_network = bridge_address(lab, lab)
        peer_address, peer_network = bridge_address(lab, peer)
        if source_network != peer_network or source_address == peer_address:
            lab.block("The two owned nodes are not distinct on the shared Kind bridge")
        if obj(peer, "version")["serverVersion"]["gitVersion"] != "v1.36.1":
            lab.block("Expected Kubernetes v1.36.1 on the secondary Kind cluster")
        peer.kubectl("create", "namespace", NAMESPACE)
        lab.command("kind", "load", "docker-image", image, "--name", peer.cluster, timeout=120)
        yield peer, source_address
    finally:
        lab.command("kind", "delete", "cluster", "--name", peer.cluster,
                    "--kubeconfig", str(peer.kubeconfig), timeout=100)
        if peer.cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
            lab.block("The separately owned peer cluster remains present after deletion")


def secret(client, name, files):
    args = [f"--from-file={key}={file}" for key, file in files.items()]
    client.kubectl("create", "secret", "generic", name, *args, "-o", "name")


def configure(client, flower, code):
    create(client, "ConfigMap", RELAY_CONFIG, immutable=True, data=code)
    create(client, "ConfigMap", flower.APP_CONFIG, immutable=True, data={
        name: (flower.HERE / name).read_text(encoding="utf-8")
        for name in ("pyproject.toml", "client_app.py", "server_app.py")
    })


def relay_container(*mode):
    result = container(
        "relay", image=PYTHON_IMAGE, imagePullPolicy="IfNotPresent",
        command=["python", "-B", "/fleet/relay.py", *map(str, mode)],
        volumeMounts=[{"name": "fleet", "mountPath": "/fleet", "readOnly": True},
                      {"name": "relay-tls", "mountPath": "/tls", "readOnly": True}],
        resources={"requests": {"cpu": "10m", "memory": "24Mi"},
                   "limits": {"cpu": "250m", "memory": "80Mi"}},
        securityContext={"runAsNonRoot": True, "readOnlyRootFilesystem": True,
                         "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                         "seccompProfile": {"type": "RuntimeDefault"}},
    )
    if mode == ("server",):
        result["volumeMounts"].append({"name": "enrollment", "mountPath": "/enrollment", "readOnly": True})
        result["ports"] = [{"containerPort": 9443, "name": "fleet-tls"}]
        result["readinessProbe"] = {"tcpSocket": {"port": 9443}, "periodSeconds": 1}
    return result


def relay_volumes(credential):
    return [{"name": "fleet", "configMap": {"name": RELAY_CONFIG}},
            {"name": "relay-tls", "secret": {"secretName": credential, "defaultMode": 0o440}}]


def install_flower(client, flower, name, image, command, args, relay, credential, labels, *, server=False):
    def create_pod(item):
        item["metadata"]["labels"].update(labels)
        item["spec"]["volumes"].extend(relay_volumes(credential))
        item["spec"]["containers"].append(relay)
        if server:
            item["spec"]["volumes"].append({"name": "enrollment", "configMap": {"name": ROSTER}})
        client.create(item)

    env = {"SAF_FLOWER_RESULT_PATH": "/flower-results/result.json",
           "FLWR_HOME": "/flower-home"} if server else None
    flower.create_flower_pod(SimpleNamespace(create=create_pod), name, image, [command], args,
                             result_volume=server, env=env)


def probes(lab, peer, flower, endpoint, port):
    unit = relay_container()
    unit["command"] = ["python", "-c", "import time; time.sleep(300)"]
    request = pod(PROBE, [unit], automountServiceAccountToken=False, volumes=relay_volumes("unassigned"),
                  securityContext={"runAsUser": 49999, "runAsGroup": 49999, "fsGroup": 49999,
                                   "runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}})
    request["metadata"]["labels"] = PEER_LABEL
    peer.create(request)
    ready(peer, PROBE)

    def observe(name, mode):
        result = peer.kubectl("exec", f"pod/{name}", "-c", "relay", "--", "python", "-B", "/fleet/relay.py",
                              "probe", endpoint, str(port), mode, timeout=22)
        return json.loads(result.stdout)

    deadline = time.monotonic() + 20
    while True:
        approved = observe(flower.NODE_A, "approved")
        if approved == {"mode": "approved", "outcome": "admitted", "tls": "TLSv1.3"}:
            break
        if time.monotonic() >= deadline:
            lab.block(f"The gateway did not accept the enrolled positive probe: {approved}")
        time.sleep(0.5)
    expected = {"wrong-server": "rejected-by-server-identity",
                "missing": "rejected-by-tls", "unassigned": "closed-without-admission"}
    actuals = {mode: observe(flower.NODE_A if mode == "wrong-server" else PROBE, mode) for mode in expected}
    observations = {
        "enrolled_leaf_and_expected_server_establish_the_same_route": True,
        "missing_client_certificate_rejected_before_admission": actuals["missing"].get("outcome") in {
            expected["missing"], "closed-without-admission"
        } and set(actuals["missing"]) == {"mode", "outcome"},
        "trusted_unassigned_leaf_rejected_before_flower": actuals["unassigned"] == {
            "mode": "unassigned", "outcome": expected["unassigned"]},
        "wrong_server_identity_rejected": actuals["wrong-server"] == {
            "mode": "wrong-server", "outcome": expected["wrong-server"]},
    }
    return observations, actuals


def aggregate(client, name, path, expected_round, expected_values):
    result = client.kubectl("exec", f"pod/{name}", "-c", "flower", "--", "cat", path,
                             timeout=20, allow_failure=True)
    if result.returncode:
        return False
    report = json.loads(result.stdout)
    values = report.get("aggregate", [])
    return (set(report) == {"workflow", "round", "participant_result_count", "failure_count", "aggregate"}
            and report["workflow"] == "SecAggPlusWorkflow"
            and report["round"] == expected_round and report["participant_result_count"] == 3
            and report["failure_count"] == 0 and len(values) == 2
            and all(abs(float(actual) - expected) <= 0.001 for actual, expected in zip(values, expected_values)))


def exercise(lab, peer, flower, images, source_address, directory):
    certs, allowlist = runpy.run_path(str(HERE / "pki.py"))["generate"](lab, directory / "pki")
    relay_code = {name: (HERE / name).read_text(encoding="utf-8") for name in ("relay.py", "hold.py")}
    configure(lab, flower, relay_code)
    configure(peer, flower, relay_code)
    create(lab, "ConfigMap", ROSTER, data={"allow.json": json.dumps(allowlist, sort_keys=True)})
    secret(lab, "fleet-server", certs["server"])
    for name in (*PARTICIPANT_IDENTITIES, "unassigned"):
        secret(peer, name, certs[name])
    create(lab, "ConfigMap", flower.FLOWER_HOME_CONFIG, immutable=True, data={
        "config.toml": '[superlink.fixture]\naddress = "127.0.0.1:9093"\ninsecure = true\n',
    })
    install_flower(lab, flower, flower.LINK, images["superlink"]["image"], "flower-superlink",
                   ["--insecure", "--isolation", "subprocess", "--fleet-api-address", "127.0.0.1:9092",
                    "--control-api-address", "127.0.0.1:9093", "--serverappio-api-address", "127.0.0.1:9091"],
                   relay_container("server"), "fleet-server", GATEWAY_LABEL, server=True)
    service = create(lab, "Service", RELAY_CONFIG, spec={
        "type": "NodePort", "selector": GATEWAY_LABEL,
        "ports": [{"port": 9443, "targetPort": "fleet-tls", "protocol": "TCP"}],
    })
    port = service["spec"]["ports"][0]["nodePort"]
    if not 30000 <= port <= 32767:
        lab.block("Expected a dynamic NodePort on the primary fixture node")
    create(peer, "NetworkPolicy", RELAY_CONFIG, "networking.k8s.io/v1", spec={
        "podSelector": {"matchLabels": PEER_LABEL}, "policyTypes": ["Egress"],
        "egress": [{"to": [{"ipBlock": {"cidr": f"{source_address}/32"}}],
                    "ports": [{"protocol": "TCP", "port": port}]}],
    })
    allowed_names = flower.NODE_A, flower.NODE_B, flower.NODE_C
    for partition, (pod_name, credential) in enumerate(zip(allowed_names, PARTICIPANT_IDENTITIES)):
        install_flower(peer, flower, pod_name, images["supernode"]["image"], "flower-supernode", [
            "--insecure", "--superlink", "127.0.0.1:19092", "--node-config", f"partition-id={partition}",
            "--clientappio-api-address", "127.0.0.1:9094", "--isolation", "subprocess",
        ], relay_container("client", source_address, port), credential, PEER_LABEL)
    ready(lab, flower.LINK)
    for name in allowed_names:
        ready(peer, name)

    identity, outcomes = probes(lab, peer, flower, source_address, port)
    logs = lab.kubectl("logs", f"pod/{flower.LINK}", "-c", "relay", "--tail=150").stdout
    events = [json.loads(line) for line in logs.splitlines()]
    identity["gateway_tls_required_missing_client_certificate"] = {"event": "client-certificate-required"} in events
    identity["gateway_observed_trusted_unassigned_client"] = {"event": "unenrolled-client"} in events
    # OpenSSL reports the server alert directly on some clients and as an EOF on others.
    # Normalize only after the exact certificate-required result on the gateway.
    if identity["gateway_tls_required_missing_client_certificate"] and identity["missing_client_certificate_rejected_before_admission"]:
        outcomes["missing"] = {"mode": "missing", "outcome": "rejected-by-tls"}
    lab.check("cross-cluster-enrollment", "The Fleet gateway authenticates the server and admitted participant leaves",
              all(identity.values()), identity)

    result = lab.kubectl("exec", f"pod/{flower.LINK}", "-c", "flower", "--", "sh", "-ec", CLI_COMMAND,
                         timeout=220, allow_failure=True)
    equal = aggregate(lab, flower.LINK, "/flower-results/result.json", 1, [3.5, 1.25])
    weighted = aggregate(lab, flower.LINK, "/flower-results/weighted-result.json", 2,
                         [4.208333333333333, 2.0416666666666665])
    logs = lab.kubectl("logs", f"pod/{flower.LINK}", "-c", "relay", "--tail=150").stdout
    events = [json.loads(line) for line in logs.splitlines()]
    forwarded = {row["participant"] for row in events
                 if row.get("event") == "fleet-forwarded" and row.get("client_and_server_bytes") is True}
    inventory = [obj(client, "get", "pods", "-l", f"fixture={flower.LABEL}")["items"]
                 for client in (lab, peer)]
    topology = [{item["metadata"]["name"] for item in group} for group in inventory]
    observed = {
        "aggregator_and_three_participants_in_distinct_clusters": topology == [{flower.LINK}, set(allowed_names)],
        "each_enrolled_leaf_forwarded_both_directions_of_live_fleet_stream": forwarded == set(PARTICIPANT_IDENTITIES),
        "flower_cli_completed": result.returncode == 0,
        "three_participant_equal_round_matches_only_aggregate": equal,
        "three_participant_weighted_round_matches_only_aggregate": weighted,
    }
    if not all(observed.values()):
        lab.kubectl("logs", f"pod/{flower.LINK}", "-c", "flower", "--tail=60", allow_failure=True)
        for name in allowed_names:
            peer.kubectl("logs", f"pod/{name}", "-c", "flower", "--tail=60", allow_failure=True)
    else:
        retirement["retire"](lab, peer, allowed_names, flower.LINK, source_address, port, allowlist)
    return identity, outcomes, observed


def run(lab, flower, images):
    with TemporaryDirectory(prefix="saf-fleet-transport-") as temp:
        directory = Path(temp)
        with owned_peer(lab, images["supernode"]["image"], directory) as (peer, source_address):
            identity, outcomes, observed = exercise(lab, peer, flower, images, source_address, directory)
    observed["secondary_kind_cluster_deleted"] = True
    (lab.evidence / "flower-cross-cluster-mtls.json").write_text(
        json.dumps({"identity": identity, "probes": outcomes, "workflow": observed,
                    "flower": "1.29.0", "kubernetes": "v1.36.1", "transport": "TLSv1.3"},
                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lab.check("cross-cluster-secagg", "Three authenticated Fleet streams run both pinned Flower rounds across two Kind clusters",
              all(observed.values()), observed)
