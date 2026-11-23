"""Run a narrow, synthetic CNI selection gate in disposable Kind clusters.

The harness owns the primary Cilium cluster. This case creates and deletes one
additional Kind cluster for the bundled kindnet comparison. All workloads,
namespaces, and policies are case-owned and use fixed synthetic markers.
"""
from copy import copy
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
    "training": "saf-0502-001-training",
    "inference": "saf-0502-001-inference",
    "pipeline": "saf-0502-001-pipeline",
}
CLIENT = "synthetic-client"
SERVERS = {"inference": "inference-sink", "pipeline": "pipeline-sink"}
MARKERS = {
    "inference": "saf-0502-001-inference-fixed-marker",
    "pipeline": "saf-0502-001-pipeline-fixed-marker",
}
SYNTHETIC_MINIMUM_PROFILE = {
    "profile_id": "SAF-K8S-0502-001-synthetic-minimum-v1",
    "required": {
        "standard_kubernetes_networkpolicy_enforcement":
            "Observed a baseline marker, a default-deny block, and an explicitly permitted marker path",
        "versioned_candidate_artifacts": "Image and chart digests recorded",
        "scoped_structured_flow_evidence": {
            "observer_interface_id": "SAF-K8S-0502-001-hubble-json-v1",
            "approved_for_this_synthetic_case": True,
            "interface": "Cilium embedded Hubble CLI over the local Unix socket",
            "protocol": "Structured Hubble flow JSON matched to endpoints, TCP port, direction, verdict, and drop reason",
            "required_for_each_candidate": True,
        },
    },
    "not_scored_here": [
        "pod-to-pod encryption mode and cryptographic configuration",
        "FQDN filtering semantics and DNS failure behavior",
        "L7 policy coverage and protocol parsing",
        "performance under security-enabled configuration",
        "flow export beyond the named local observer interface, retention, and operational metrics",
        "managed-service feature gaps and compensating controls",
    ],
}
SCOPE = (
    "One harness-owned local Kind v0.32.0 / Kubernetes v1.36.1 cluster runs pinned "
    "Cilium 1.20.5 with embedded Hubble; one case-owned local Kind cluster runs the "
    "kindnet bundled in the same digest-pinned node image. Fixed-marker IPv4 TCP/18080 "
    "requests use only case-owned pods and namespaces. Both candidates receive actual "
    "baseline, denied, and explicitly permitted fixed-marker probes. The synthetic "
    "profile also requires scoped structured flow evidence through its named Hubble "
    "JSON observer interface. Bundled kindnet's lack of this specific integration "
    "does not imply it lacks NetworkPolicy enforcement or all telemetry. The profile "
    "also requires pinned artifact evidence. Encryption, FQDN/L7 policy, performance, "
    "production selection, "
    "managed-provider gaps, and compensating controls are not evaluated. No workload "
    "fixture requests an external destination."
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
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {SEGMENT_LABEL: segment, ROLE_LABEL: name}},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "containers": [_container(name, command)],
        },
    }


def _policy(namespace, name, selector, policy_types, **rules):
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"podSelector": selector, "policyTypes": policy_types, **rules},
    }


def _peer(segment, role):
    return {
        "namespaceSelector": {"matchLabels": {SEGMENT_LABEL: segment}},
        "podSelector": {"matchLabels": {ROLE_LABEL: role}},
    }


def _install_policy(lab):
    for namespace in NAMESPACES.values():
        _create(lab, _policy(namespace, "default-deny-ingress-egress", {},
                              ["Ingress", "Egress"]))
    training, pipeline = NAMESPACES["training"], NAMESPACES["pipeline"]
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
    if pod.get("status", {}).get("phase") != "Running" or not pod.get("status", {}).get("podIP"):
        lab.block(f"Case-owned pod {namespace}/{name} is not Running with a Pod IP")
    return pod["status"]["podIP"]


def _request(lab, destination, expected_marker=None):
    result = _kubectl(
        lab, "-n", NAMESPACES["training"], "exec", f"pod/{CLIENT}", "--",
        "wget", "-q", "-T", "2", "-O", "-", f"http://{destination}:{PORT}/",
        timeout=14, allow_failure=True,
    )
    if expected_marker is not None:
        return ((result.returncode == 0 and result.stdout.strip() == expected_marker),
                "fixed-marker-received" if result.returncode == 0 and result.stdout.strip() == expected_marker
                else "fixed-marker-missing")
    combined = (result.stdout + result.stderr).lower()
    if "timed out" in combined or "timeout" in combined:
        return True, "bounded-timeout"
    return False, "request-failed-without-timeout"


def _cilium_exec(lab, *args, timeout=40):
    return _kubectl(lab, "-n", "kube-system", "exec", "daemonset/cilium", "-c",
                    "cilium-agent", "--", *args, timeout=timeout).stdout


def _hubble_flows(lab, segment):
    raw = _cilium_exec(
        lab, "hubble", "observe", "--server", HUBBLE_SERVER, "--since", "90s",
        "--from-pod", f"{NAMESPACES['training']}/{CLIENT}",
        "--to-pod", f"{NAMESPACES[segment]}/{SERVERS[segment]}", "--output", "json",
    )
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _flow_id(event):
    return event.get("flow", event).get("uuid")


def _matching_flows(events, destination_segment):
    matched = []
    for event in events:
        flow = event.get("flow", event)
        source, destination = flow.get("source") or {}, flow.get("destination") or {}
        tcp = (flow.get("l4") or {}).get("TCP") or {}
        if (source.get("namespace") == NAMESPACES["training"]
                and source.get("pod_name") == CLIENT
                and destination.get("namespace") == NAMESPACES[destination_segment]
                and destination.get("pod_name") == SERVERS[destination_segment]
                and tcp.get("destination_port") == PORT
                and flow.get("traffic_direction") == "EGRESS"
                and (flow.get("verdict") == "DROPPED"
                     or (flow.get("verdict") == "FORWARDED"
                         and flow.get("trace_observation_point") == "TO_ENDPOINT"))):
            matched.append(flow)
    return matched


def _classify(flows, phase, segment):
    expected = "DROPPED" if segment == "inference" and phase == "green" else "FORWARDED"
    valid = [flow for flow in flows if flow.get("verdict") == expected]
    reason_ok = expected != "DROPPED" or any(
        flow.get("drop_reason_desc") == "POLICY_DENIED" for flow in valid
    )
    identities_ok = all(
        (flow.get("source") or {}).get("namespace") == NAMESPACES["training"]
        and (flow.get("source") or {}).get("pod_name") == CLIENT
        and (flow.get("destination") or {}).get("namespace") == NAMESPACES[segment]
        and (flow.get("destination") or {}).get("pod_name") == SERVERS[segment]
        and ((flow.get("l4") or {}).get("TCP") or {}).get("destination_port") == PORT
        for flow in valid
    )
    return expected, bool(valid) and identities_ok and reason_ok


def _record_and_check(lab, phase, segment, result, events):
    flows = _matching_flows(events, segment)
    expected, classified = _classify(flows, phase, segment)
    policy_match = any(flow.get("verdict") == expected for flow in flows)
    if segment == "inference" and phase == "green":
        policy_match = any(flow.get("verdict") == "DROPPED"
                           and flow.get("drop_reason_desc") == "POLICY_DENIED" for flow in flows)
    app_match = result[0] if segment == "pipeline" or phase == "red" else result[1] == "bounded-timeout"
    ok = policy_match and classified and app_match
    observations = [{
        "time": flow.get("time"), "source": flow.get("source"),
        "destination": flow.get("destination"), "l4": flow.get("l4"),
        "verdict": flow.get("verdict"), "drop_reason_desc": flow.get("drop_reason_desc"),
        "traffic_direction": flow.get("traffic_direction"),
        "trace_observation_point": flow.get("trace_observation_point"),
        "uuid": flow.get("uuid"),
    } for flow in flows]
    evidence = lab.evidence / "cilium-hubble-receipts.json"
    records = json.loads(evidence.read_text()) if evidence.exists() else []
    record = {"phase": phase, "segment": segment, "expected_verdict": expected,
              "application_observation": result[1], "flows": observations,
              "check_passed": ok}
    records.append(record)
    evidence.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    lab.check(phase, f"Cilium {phase} {segment} request matches synthetic minimum profile",
              ok, {"source": f"{NAMESPACES['training']}/{CLIENT}",
                   "destination": f"{NAMESPACES[segment]}/{SERVERS[segment]}",
                   "protocol": f"TCP/{PORT}", "expected_verdict": expected,
                   "matching_hubble_events": bool(flows), "identity_fields_verified": classified,
                   "application_observation": result[1]})
    return record


def _observe(lab, phase, segment, address):
    marker = None if phase == "green" and segment == "inference" else MARKERS[segment]
    deadline = time.monotonic() + 30
    while True:
        baseline = {_flow_id(event) for event in _hubble_flows(lab, segment)}
        result = _request(lab, address, marker)
        events = [event for event in _hubble_flows(lab, segment)
                  if _flow_id(event) is not None and _flow_id(event) not in baseline]
        flows = _matching_flows(events, segment)
        _, classified = _classify(flows, phase, segment)
        expected, _ = _classify(flows, phase, segment)
        contrary = any(flow.get("verdict") != expected for flow in flows)
        if result[0] and classified and not contrary:
            break
        if time.monotonic() >= deadline:
            lab.block(f"{phase} {segment} did not produce consistent application and Hubble evidence")
        time.sleep(0.5)
    return _record_and_check(lab, phase, segment, result, events)


def _install_cilium(lab):
    work = lab.kubeconfig.parent
    registry = work / "helm-registry.json"
    lab.command("helm", "pull", CHART_SOURCE, "--version", CILIUM_VERSION,
                "--destination", str(work), "--registry-config", str(registry), timeout=100)
    chart = work / f"cilium-{CILIUM_VERSION}.tgz"
    if hashlib.sha256(chart.read_bytes()).hexdigest() != CHART_HASH:
        lab.block("Downloaded Cilium chart does not match the reviewed content digest")
    lab.command(
        "helm", "install", "cilium", str(chart), "--namespace", "kube-system",
        "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
        "-f", str(Path(__file__).with_name("cilium-values.yaml")),
        "--wait", "--timeout", "4m", timeout=260,
    )
    _kubectl(lab, "-n", "kube-system", "rollout", "status", "daemonset/cilium",
             "--timeout=90s", timeout=100)
    _kubectl(lab, "wait", "--for=condition=Ready", "node", "--all", "--timeout=90s", timeout=105)
    ds = json.loads(_kubectl(lab, "-n", "kube-system", "get", "daemonset/cilium", "-o", "json").stdout)
    containers = ds["spec"]["template"]["spec"]["containers"]
    image_match = any(c["name"] == "cilium-agent" and c["image"] == CILIUM_IMAGE for c in containers)
    ds_status = _daemonset_counts(ds)
    desired = ds_status.get("desiredNumberScheduled", 0)
    daemonset_ready = (desired > 0 and ds_status.get("numberReady", 0) == desired
                       and ds_status.get("updatedNumberScheduled", 0) == desired
                       and ds_status.get("numberAvailable", 0) == desired)
    hubble_ok = "): Ok" in _cilium_exec(lab, "hubble", "status", "--server", HUBBLE_SERVER)
    lab.check("positive", "Pinned Cilium agent and embedded Hubble observer are ready",
              image_match and daemonset_ready and hubble_ok,
              {"expected_agent_image": CILIUM_IMAGE, "observed_agent_image_match": image_match,
               "daemonset_status": ds_status, "daemonset_ready": daemonset_ready,
               "observer_healthy": hubble_ok, "cilium_release": CILIUM_VERSION,
               "chart_sha256": CHART_HASH})
    return {"agent_image_match": image_match, "daemonset_ready": daemonset_ready,
            "daemonset_status": ds_status, "observer_healthy": hubble_ok}


def _daemonset_counts(daemonset):
    return {
        key: daemonset.get("status", {}).get(key, 0)
        for key in ("desiredNumberScheduled", "updatedNumberScheduled", "numberReady", "numberAvailable")
    }


def _verify_version(lab):
    version = json.loads(_kubectl(lab, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if version != KUBERNETES_VERSION:
        lab.block(f"Expected Kubernetes {KUBERNETES_VERSION}, got {version!r}")


def _deploy_markers(lab):
    for segment, namespace in NAMESPACES.items():
        _kubectl(lab, "create", "namespace", namespace)
        _kubectl(lab, "label", "namespace", namespace, f"{SEGMENT_LABEL}={segment}")
    _create(lab, _pod(NAMESPACES["training"], "training", CLIENT))
    for segment, marker in MARKERS.items():
        _create(lab, _pod(NAMESPACES[segment], segment, SERVERS[segment], marker=marker))
    _wait_pod(lab, NAMESPACES["training"], CLIENT)
    return {segment: _wait_pod(lab, NAMESPACES[segment], SERVERS[segment]) for segment in MARKERS}


def _kindnet_probe(lab, phase, segment, address):
    expected = None if phase == "green" else MARKERS[segment]
    deadline = time.monotonic() + 35
    while True:
        matched, observation = _request(lab, address, expected)
        if matched or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check(phase, f"Bundled kindnet {phase} {segment} marker path matches the policy expectation",
              matched, {"observation": observation, "port": PORT})
    return {"matched": matched, "observation": observation}


def _probe_candidate(lab, probe):
    addresses = _deploy_markers(lab)
    observations = {}
    for phase, segment in (("red", "inference"), ("red", "pipeline"),
                           ("green", "inference"), ("positive", "pipeline")):
        if phase == "green":
            _install_policy(lab)
        observations[f"{phase}:{segment}"] = probe(lab, phase, segment, addresses[segment])
    return observations


def _kindnet_candidate(lab):
    peer = copy(lab)
    peer.cluster = f"{lab.cluster}-kindnet"
    peer.kubeconfig = lab.kubeconfig.with_name("kindnet-kubeconfig")
    if peer.cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Refusing to reuse an existing peer cluster")
    try:
        lab.command("kind", "create", "cluster", "--name", peer.cluster, "--image", NODE_IMAGE,
                    "--kubeconfig", str(peer.kubeconfig), "--wait", "90s", timeout=480)
        _verify_version(peer)
        _kubectl(peer, "-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                 "--timeout=90s", timeout=100)
        controllers = json.loads(_kubectl(peer, "-n", "kube-system", "get", "daemonsets",
                                         "-o", "json").stdout)["items"]
        kindnet = next(controller for controller in controllers if controller["metadata"]["name"] == "kindnet")
        installed = sorted(controller["metadata"]["name"] for controller in controllers)
        images = [container["image"] for container in kindnet["spec"]["template"]["spec"]["containers"]]
        counts = _daemonset_counts(kindnet)
        desired = counts["desiredNumberScheduled"]
        observer_available = "cilium" in installed
        lab.check("positive", "Bundled kindnet is ready and there is no Cilium daemon for the named observer",
                  desired > 0 and all(value == desired for value in counts.values())
                  and bool(images) and not observer_available,
                  {"daemonsets": installed, "kindnet_counts": counts, "kindnet_images": images})
        observations = _probe_candidate(peer, _kindnet_probe)
    finally:
        deletion = lab.command("kind", "delete", "cluster", "--name", peer.cluster,
                               "--kubeconfig", str(peer.kubeconfig), timeout=90, allow_failure=True)
        remaining = lab.command("kind", "get", "clusters", allow_failure=True)
        deleted = deletion.returncode == 0 and remaining.returncode == 0 and (
            peer.cluster not in remaining.stdout.splitlines()
        )
        lab.check("positive", "Owned kindnet peer was deleted and is absent from the cluster inventory",
                  deleted, {"owned_peer_clusters": 1, "deleted_peer_clusters": int(deleted)})
    return {
        "node_image": NODE_IMAGE,
        "kindnet_images": images,
        "marker_probes": observations,
        "policy_checks_passed": all(record["matched"] for record in observations.values()),
        "named_observer_available": observer_available,
    }


def run(lab):
    version = lab.command("kind", "version").stdout.strip()
    if not version.startswith(f"kind {KIND_VERSION} "):
        lab.block(f"Expected Kind {KIND_VERSION}, got {version!r}")
    _verify_version(lab)
    kindnet = _kindnet_candidate(lab)
    cilium_install = _install_cilium(lab)
    cilium_flows = _probe_candidate(lab, _observe)
    cilium = {
        "node_image": NODE_IMAGE,
        "agent_image": CILIUM_IMAGE,
        "chart_sha256": CHART_HASH,
        "policy_checks_passed": all(record["check_passed"] for record in cilium_flows.values()),
        "named_observer_available": cilium_install["observer_healthy"] and
            all(record["flows"] for record in cilium_flows.values()),
    }
    candidates = {"bundled_kindnet": kindnet, "cilium": cilium}
    decision_fields = ("policy_checks_passed", "named_observer_available", "profile_pass")
    for candidate in candidates.values():
        candidate["profile_pass"] = candidate["policy_checks_passed"] and candidate["named_observer_available"]
    (lab.evidence / "selection-record.json").write_text(
        json.dumps({"profile": SYNTHETIC_MINIMUM_PROFILE, "candidates": candidates}, indent=2, sort_keys=True) + "\n"
    )
    lab.check("green", "Both configurations enforce the same marker policy and the required observer changes the selection",
              kindnet["policy_checks_passed"] and cilium["policy_checks_passed"]
              and not kindnet["profile_pass"] and cilium["profile_pass"],
              {name: {key: candidate[key] for key in decision_fields}
               for name, candidate in candidates.items()})
