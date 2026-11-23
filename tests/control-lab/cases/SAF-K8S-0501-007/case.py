"""Exercise a synthetic east-west segment rule using authentic Cilium/Hubble flows.

The harness owns Kind lifecycle. This case only creates case-owned resources in that
fresh cluster and writes bounded flow evidence under the harness evidence directory.
"""
import hashlib
import json
from pathlib import Path
import time


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
KUBERNETES_VERSION = "v1.36.1"
KIND_VERSION = "v0.32.0"
CILIUM_VERSION = "1.20.5"
INSTALLS_CNI = True
CHART_SOURCE = "oci://quay.io/cilium/charts/cilium"
CHART_HASH = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
CILIUM_IMAGE = (
    "quay.io/cilium/cilium:v1.20.5@sha256:"
    "aa72499f075ad729947ea91b026218aceba24f1a8e4534bf36b8368c7c561526"
)
HUBBLE_SERVER = "unix:///var/run/cilium/hubble.sock"
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
PORT = 18080
SEGMENT_LABEL = "saf-k8s.example/workload-segment"
ROLE_LABEL = "saf-k8s.example/role"
NAMESPACES = {
    "training": "saf-0501-007-training",
    "inference": "saf-0501-007-inference",
    "pipeline": "saf-0501-007-pipeline",
}
CLIENT = "synthetic-client"
SERVERS = {"inference": "inference-sink", "pipeline": "pipeline-sink"}
MARKERS = {
    "inference": "saf-0501-007-inference-fixed-marker",
    "pipeline": "saf-0501-007-pipeline-fixed-marker",
}
SCOPE = (
    "One fresh local Kind v0.32.0 / Kubernetes v1.36.1 cluster with Cilium 1.20.5 "
    "and its embedded Hubble observer. Three case-owned namespaces represent training, "
    "inference, and pipeline. Only fixed-marker IPv4 TCP/18080 requests between the "
    "training client and the two case-owned responders are examined. The red phase runs "
    "without NetworkPolicy; the green phase applies default deny and permits training to "
    "pipeline while denying training to inference. A named synthetic segment rule labels "
    "the training-to-inference flow as expected-denied and reports whether authentic "
    "Hubble telemetry agrees. No production workloads, external destinations, packet "
    "capture, model/data inspection, SIEM, baseline learning, or production anomaly "
    "detection are evaluated."
)


def prepare_kind(_lab, temporary):
    profile = temporary / "kind.yaml"
    profile.write_bytes(Path(__file__).with_name("kind-profile.yaml").read_bytes())
    return profile


def _kubectl(lab, *args, timeout=60, allow_failure=False, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        *args, payload=payload, timeout=timeout, allow_failure=allow_failure,
    )


def _create(lab, resource):
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(resource))


def _container(name, command):
    return {
        "name": name,
        "image": IMAGE,
        "command": command,
        "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                      "limits": {"cpu": "75m", "memory": "24Mi"}},
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def _pod(namespace, segment, name, *, marker=None):
    command = ["sh", "-ec", "exec sleep 900"]
    if marker is not None:
        command = [
            "sh", "-ec",
            f"printf %s {marker} >/tmp/index.html; exec httpd -f -p {PORT} -h /tmp",
        ]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {SEGMENT_LABEL: segment, ROLE_LABEL: name},
        },
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "containers": [_container(name, command)],
        },
    }


def _policy(namespace, name, selector, policy_types, **rules):
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"podSelector": selector, "policyTypes": policy_types, **rules},
    }


def _peer(segment, role):
    # Within one peer, both selectors are conjunctive by Kubernetes API semantics.
    return {
        "namespaceSelector": {"matchLabels": {SEGMENT_LABEL: segment}},
        "podSelector": {"matchLabels": {ROLE_LABEL: role}},
    }


def _install_policy(lab):
    for namespace in NAMESPACES.values():
        _create(lab, _policy(namespace, "default-deny-ingress-egress", {}, ["Ingress", "Egress"]))

    training = NAMESPACES["training"]
    pipeline = NAMESPACES["pipeline"]
    _create(lab, _policy(
        training, "allow-training-egress-to-pipeline", {"matchLabels": {ROLE_LABEL: CLIENT}},
        ["Egress"], egress=[{"to": [_peer("pipeline", SERVERS["pipeline"])],
                            "ports": [{"protocol": "TCP", "port": PORT}]}],
    ))
    _create(lab, _policy(
        pipeline, "allow-training-ingress", {"matchLabels": {ROLE_LABEL: SERVERS["pipeline"]}},
        ["Ingress"], ingress=[{"from": [_peer("training", CLIENT)],
                               "ports": [{"protocol": "TCP", "port": PORT}]}],
    ))


def _wait_pod(lab, namespace, name):
    _kubectl(lab, "-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
             "--timeout=90s", timeout=100)
    pod = json.loads(_kubectl(lab, "-n", namespace, "get", "pod", name, "-o", "json").stdout)
    if pod.get("status", {}).get("phase") != "Running":
        lab.block(f"Case-owned pod {namespace}/{name} is not Running")
    address = pod.get("status", {}).get("podIP")
    if not address:
        lab.block(f"Case-owned pod {namespace}/{name} has no Pod IP")
    return address


def _request(lab, destination, expected_marker=None):
    result = _kubectl(
        lab, "-n", NAMESPACES["training"], "exec", f"pod/{CLIENT}", "--",
        "wget", "-q", "-T", "2", "-O", "-", f"http://{destination}:{PORT}/",
        timeout=14, allow_failure=True,
    )
    if expected_marker is not None:
        if result.returncode != 0 or result.stdout.strip() != expected_marker:
            return False, "fixed-marker-missing"
        return True, "fixed-marker-received"
    combined = (result.stdout + result.stderr).lower()
    if "timed out" in combined or "timeout" in combined:
        return True, "bounded-timeout"
    return False, "request-failed-without-timeout"


def _cilium_exec(lab, *args, timeout=40):
    result = _kubectl(
        lab, "-n", "kube-system", "exec", "daemonset/cilium", "-c", "cilium-agent", "--", *args,
        timeout=timeout,
    )
    return result.stdout


def _hubble_flows(lab, segment):
    raw = _cilium_exec(
        lab, "hubble", "observe", "--server", HUBBLE_SERVER, "--since", "90s",
        "--from-pod", f"{NAMESPACES['training']}/{CLIENT}",
        "--to-pod", f"{NAMESPACES[segment]}/{SERVERS[segment]}", "--output", "json",
    )
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _matching_flows(events, destination_segment):
    destination_namespace = NAMESPACES[destination_segment]
    destination_pod = SERVERS[destination_segment]
    matched = []
    for event in events:
        flow = event.get("flow", event)
        source = flow.get("source") or {}
        destination = flow.get("destination") or {}
        tcp = (flow.get("l4") or {}).get("TCP") or {}
        if (source.get("namespace") == NAMESPACES["training"]
                and source.get("pod_name") == CLIENT
                and destination.get("namespace") == destination_namespace
                and destination.get("pod_name") == destination_pod
                and tcp.get("destination_port") == PORT
                and flow.get("traffic_direction") == "EGRESS"
                and (flow.get("verdict") == "DROPPED"
                     or (flow.get("verdict") == "FORWARDED"
                         and flow.get("trace_observation_point") == "TO_ENDPOINT"))):
            matched.append(flow)
    return matched


def _classify(flows, phase, destination_segment):
    # This named rule is deliberately synthetic: it labels one declared segment edge.
    if destination_segment == "inference":
        rule = "synthetic-segment-training-to-inference-tcp-18080"
        expected = "FORWARDED" if phase == "red" else "DROPPED"
    else:
        rule = "synthetic-segment-training-to-pipeline-tcp-18080"
        expected = "FORWARDED"
    valid = [flow for flow in flows if flow.get("verdict") == expected]
    reason_ok = expected != "DROPPED" or any(
        flow.get("drop_reason_desc") == "POLICY_DENIED" for flow in valid
    )
    identities_ok = all(
        (flow.get("source") or {}).get("namespace") == NAMESPACES["training"]
        and (flow.get("source") or {}).get("pod_name") == CLIENT
        and (flow.get("destination") or {}).get("namespace") == NAMESPACES[destination_segment]
        and (flow.get("destination") or {}).get("pod_name") == SERVERS[destination_segment]
        and ((flow.get("l4") or {}).get("TCP") or {}).get("destination_port") == PORT
        for flow in valid
    )
    return rule, expected, bool(valid) and identities_ok and reason_ok


def _record_and_check(lab, phase, destination_segment, result, events):
    flows = _matching_flows(events, destination_segment)
    rule, expected, classified = _classify(flows, phase, destination_segment)
    flow_records = []
    for flow in flows:
        flow_records.append({
            "time": flow.get("time"),
            "source": flow.get("source"),
            "destination": flow.get("destination"),
            "l4": flow.get("l4"),
            "verdict": flow.get("verdict"),
            "drop_reason_desc": flow.get("drop_reason_desc"),
            "traffic_direction": flow.get("traffic_direction"),
            "trace_observation_point": flow.get("trace_observation_point"),
            "uuid": flow.get("uuid"),
        })
    evidence = lab.evidence / "hubble-events.json"
    previous = []
    if evidence.exists():
        previous = json.loads(evidence.read_text(encoding="utf-8"))
    previous.extend({"phase": phase, "segment_rule": rule, "event": item} for item in flow_records)
    evidence.write_text(json.dumps(previous, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    policy_match = any(flow.get("verdict") == expected for flow in flows)
    if destination_segment == "inference" and phase == "green":
        policy_match = any(flow.get("verdict") == "DROPPED"
                           and flow.get("drop_reason_desc") == "POLICY_DENIED" for flow in flows)
    elif destination_segment == "inference" and phase == "red":
        policy_match = any(flow.get("verdict") == "FORWARDED" for flow in flows)
    app_match = result[0] if destination_segment == "pipeline" else (
        result[0] if phase == "red" else result[1] == "bounded-timeout"
    )
    ok = policy_match and classified and app_match
    observation = {
        "source": f"{NAMESPACES['training']}/{CLIENT}",
        "destination": f"{NAMESPACES[destination_segment]}/{SERVERS[destination_segment]}",
        "protocol": f"TCP/{PORT}",
        "expected_verdict": expected,
        "direction": "EGRESS",
        "matching_hubble_events": bool(flows),
        "identity_fields_verified": classified,
        "segment_rule": rule,
        "application_observation": result[1],
    }
    lab.check(phase, f"{phase} {destination_segment} flow matches synthetic segment rule",
              ok, observation)


def _install_cilium(lab):
    work = lab.kubeconfig.parent
    registry = work / "helm-registry.json"
    lab.command("helm", "pull", CHART_SOURCE, "--version", CILIUM_VERSION,
                "--destination", str(work), "--registry-config", str(registry), timeout=100)
    chart = work / f"cilium-{CILIUM_VERSION}.tgz"
    if hashlib.sha256(chart.read_bytes()).hexdigest() != CHART_HASH:
        lab.block("The downloaded Cilium Helm chart does not match the reviewed content digest")
    lab.command(
        "helm", "install", "cilium", str(chart), "--namespace", "kube-system",
        "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
        "-f", str(Path(__file__).with_name("cilium-values.yaml")),
        "--wait", "--timeout", "4m", timeout=260,
    )
    _kubectl(lab, "wait", "--for=condition=Ready", "node", "--all", "--timeout=90s", timeout=105)
    deployment = json.loads(_kubectl(lab, "-n", "kube-system", "get", "daemonset/cilium",
                                     "-o", "json").stdout)
    agents = deployment["spec"]["template"]["spec"]["containers"]
    image_match = any(container["name"] == "cilium-agent" and container["image"] == CILIUM_IMAGE
                      for container in agents)
    healthy_hubble = "): Ok" in _cilium_exec(lab, "hubble", "status", "--server", HUBBLE_SERVER)
    lab.check("positive", "The pinned Cilium agent and Hubble observer are ready",
              image_match and healthy_hubble,
              {"expected_agent_image": image_match, "observer_healthy": healthy_hubble,
               "cilium_release": CILIUM_VERSION})


def _flow_id(event):
    return event.get("flow", event).get("uuid")


def _observe(lab, phase, segment, address):
    expected_marker = None if phase == "green" else MARKERS[segment]
    deadline = time.monotonic() + 30
    while True:
        baseline = {_flow_id(e) for e in _hubble_flows(lab, segment)}
        result = _request(lab, address, expected_marker)
        events = [e for e in _hubble_flows(lab, segment)
                  if _flow_id(e) is not None and _flow_id(e) not in baseline]
        flows = _matching_flows(events, segment)
        _, expected, classified = _classify(flows, phase, segment)
        contrary_verdict = any(flow.get("verdict") != expected for flow in flows)
        if result[0] and classified and not contrary_verdict:
            break
        if time.monotonic() >= deadline:
            lab.block(f"{phase} {segment} never showed one consistent application and Hubble observation")
        time.sleep(0.5)
    _record_and_check(lab, phase, segment, result, events)


def run(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith(f"kind {KIND_VERSION}"):
        lab.block(f"Expected Kind {KIND_VERSION}, got {kind_version!r}")
    server_version = json.loads(_kubectl(lab, "version", "-o", "json").stdout)
    actual_k8s = server_version.get("serverVersion", {}).get("gitVersion")
    if actual_k8s != KUBERNETES_VERSION:
        lab.block(f"Expected Kubernetes {KUBERNETES_VERSION}, got {actual_k8s!r}")
    _install_cilium(lab)

    addresses = {}
    for segment, namespace in NAMESPACES.items():
        _kubectl(lab, "create", "namespace", namespace)
        _kubectl(lab, "label", "namespace", namespace, f"{SEGMENT_LABEL}={segment}")
    _create(lab, _pod(NAMESPACES["training"], "training", CLIENT))
    for segment in ("inference", "pipeline"):
        _create(lab, _pod(NAMESPACES[segment], segment, SERVERS[segment], marker=MARKERS[segment]))
    _wait_pod(lab, NAMESPACES["training"], CLIENT)
    for segment in ("inference", "pipeline"):
        addresses[segment] = _wait_pod(lab, NAMESPACES[segment], SERVERS[segment])

    # The baseline and green probes each compare only newly observed flow IDs.
    for segment in ("inference", "pipeline"):
        _observe(lab, "red", segment, addresses[segment])
    _install_policy(lab)
    _observe(lab, "green", "inference", addresses["inference"])
    _observe(lab, "positive", "pipeline", addresses["pipeline"])
