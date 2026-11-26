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
    "An owned Kubernetes v1.36.1 Kind instance runs pinned Cilium 1.20.5 with "
    "its embedded Hubble observer. Fixed benign IPv4 TCP paths compare training "
    "and notebook traffic with inference and pipeline responders. Local rules "
    "compare observed outcomes against a fixed synthetic profile. A correlated "
    "policy-denial event is delivered to two independent case-owned TLS receiver "
    "services and each independently returns a matching stored event. The case "
    "covers the named test paths and receivers, with adopter evidence required "
    "for the selected production flow collectors, rules and retention."
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


ANOMALY_RULE_ID = "synthetic-unexpected-training-to-inference-forward"


def _flow_event_matches_anomaly(event):
    flow = event.get("flow", event)
    source = flow.get("source") or {}
    destination = flow.get("destination") or {}
    tcp = (flow.get("l4") or {}).get("TCP") or {}
    return (
        source.get("namespace") == NAMESPACES["training"]
        and source.get("pod_name") == CLIENT
        and destination.get("namespace") == NAMESPACES["inference"]
        and destination.get("pod_name") == SERVERS["inference"]
        and tcp.get("destination_port") == PORT
        and flow.get("traffic_direction") == "EGRESS"
        and flow.get("verdict") == "FORWARDED"
        and flow.get("trace_observation_point") == "TO_ENDPOINT"
    )


def _apply_fixed_anomaly_rule(records, enabled):
    matching = [record for record in records if _flow_event_matches_anomaly(record.get("event") or {})]
    # Deduplicate the fixed rule into one case-local alert for this bounded run.
    alerts = []
    if enabled and matching:
        alerts.append({
            "alert_id": "fixture-alert-001",
            "rule_id": ANOMALY_RULE_ID,
            "phase": "red-prepolicy",
            "source": f"{NAMESPACES['training']}/{CLIENT}",
            "destination": f"{NAMESPACES['inference']}/{SERVERS['inference']}",
            "protocol": f"TCP/{PORT}",
            "verdict": "FORWARDED",
            "reason": "expected-denied-segment-edge-reached-endpoint-before-policy",
        })
    return matching, alerts


def _evaluate_anomaly_rule(lab):
    evidence_path = lab.evidence / "hubble-events.json"
    records = json.loads(evidence_path.read_text(encoding="utf-8"))
    matching, alerts = _apply_fixed_anomaly_rule(records, enabled=True)
    matches_baseline = bool(matching) and all(record.get("phase") == "red" for record in matching)

    permitted = [
        record for record in records
        if record.get("segment_rule") == "synthetic-segment-training-to-pipeline-tcp-18080"
        and record.get("event", {}).get("verdict") == "FORWARDED"
    ]
    denied = [
        record for record in records
        if record.get("segment_rule") == "synthetic-segment-training-to-inference-tcp-18080"
        and record.get("phase") == "green"
        and record.get("event", {}).get("verdict") == "DROPPED"
        and record.get("event", {}).get("drop_reason_desc") == "POLICY_DENIED"
    ]
    benign = permitted + denied
    benign_false_positives = [record for record in benign
                              if _flow_event_matches_anomaly(record.get("event") or {})]

    disabled_matching, disabled_alerts = _apply_fixed_anomaly_rule(records, enabled=False)
    result = {
        "rule_id": ANOMALY_RULE_ID,
        "rule_enabled": True,
        "matching_observed_flow_count": len(matching),
        "deduplicated_alert_count": len(alerts),
        "benign_comparator_count": len(benign),
        "benign_false_positive_count": len(benign_false_positives),
        "disabled_rule_alert_count": len(disabled_alerts),
        "disabled_rule_candidate_count": len(disabled_matching),
        "alerts": alerts,
    }
    alert_path = lab.evidence / "anomaly-rule-evaluation.json"
    alert_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    persisted = json.loads(alert_path.read_text(encoding="utf-8"))

    artifact_persisted = (persisted.get("rule_id") == ANOMALY_RULE_ID
                          and persisted.get("deduplicated_alert_count") == 1
                          and len(persisted.get("alerts", [])) == 1)
    alert_emitted = matches_baseline and len(alerts) == 1 and artifact_persisted
    lab.check(
        "green", "Enabled fixed segment rule emits one alert for the observed forwarded expected-denied edge",
        alert_emitted,
        {"rule_enabled": True, "expected_one_deduplicated_alert": alert_emitted,
         "source_identity_verified": matches_baseline, "alert_artifact_written": artifact_persisted},
    )
    comparators_present = bool(permitted and denied)
    benign_clear = comparators_present and not benign_false_positives
    lab.check(
        "positive", "Permitted pipeline and policy-dropped inference comparator flows do not trigger the rule",
        benign_clear,
        {"benign_comparators_present": comparators_present, "no_comparator_alert": benign_clear},
    )
    disabled_clear = (bool(matching) and len(disabled_matching) == len(matching)
                      and not disabled_alerts and not persisted.get("disabled_rule_alert_count"))
    lab.check(
        "positive", "Disabling the rule suppresses an alert for the same observed synthetic candidate",
        disabled_clear,
        {"same_observed_candidate_present": bool(matching), "disabled_rule_alert_count_zero": disabled_clear},
    )


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
    _evaluate_anomaly_rule(lab)
    _run_monitoring_supplement(lab)


NOTEBOOK_NS = "saf-0501-007-notebook"
NOTEBOOK_CLIENT = "notebook-client"
RECEIVER_NS = "saf-0501-007-alerts"
RECEIVER_A = "alert-receiver-a"
RECEIVER_B = "alert-receiver-b"
FORWARDER = "alert-forwarder"
ALERT_ID = "saf-0501-007-notebook-policy-denied-001"
RULE_ID = "notebook-to-inference-policy-deny"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
ALERTS_DATA = "saf-0501-007-alert-delivery"




def _json_output(result, message):
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise RuntimeError(message)


def _observe_for_pair(lab, source_ns, source_pod, destination_ns, destination_pod):
    raw = _cilium_exec(
        lab, "hubble", "observe", "--server", HUBBLE_SERVER, "--since", "90s",
        "--from-pod", f"{source_ns}/{source_pod}",
        "--to-pod", f"{destination_ns}/{destination_pod}", "--output", "json",
    )
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _matching(events, source_ns, destination_ns, destination_pod, port, expected_verdict):
    found = []
    for event in events:
        flow = event.get("flow", event)
        source = flow.get("source") or {}
        dest = flow.get("destination") or {}
        tcp = (flow.get("l4") or {}).get("TCP") or {}
        if (source.get("namespace") == source_ns and source.get("pod_name") == NOTEBOOK_CLIENT
                and dest.get("namespace") == destination_ns and dest.get("pod_name") == destination_pod
                and tcp.get("destination_port") == port and flow.get("traffic_direction") == "EGRESS"
                and flow.get("verdict") == expected_verdict):
            found.append(flow)
    return found


def _new_observation(lab, source_ns, destination_ns, destination_pod, address, allowed):
    before = _observe_for_pair(lab, source_ns, NOTEBOOK_CLIENT, destination_ns, destination_pod)
    baseline_ids = {_flow_id(event) for event in before}
    result = _kubectl(
        lab, "-n", source_ns, "exec", f"pod/{NOTEBOOK_CLIENT}", "--",
        "wget", "-q", "-T", "2", "-O", "-", f"http://{address}:{PORT}/",
        timeout=14, allow_failure=True,
    )
    if allowed:
        app_ok = result.returncode == 0 and result.stdout.strip() == MARKERS["pipeline"]
    else:
        diagnostic = (result.stdout + result.stderr).lower()
        app_ok = result.returncode != 0 and "timeout" in diagnostic.replace("timed out", "timeout")
    deadline = time.monotonic() + 12
    latest = []
    while time.monotonic() < deadline:
        events = _observe_for_pair(lab, source_ns, NOTEBOOK_CLIENT, destination_ns, destination_pod)
        new_events = [event for event in events if _flow_id(event) not in baseline_ids]
        expected = "FORWARDED" if allowed else "DROPPED"
        latest = _matching(new_events, source_ns, destination_ns, destination_pod, PORT, expected)
        if allowed:
            latest = [flow for flow in latest if flow.get("trace_observation_point") == "TO_ENDPOINT"]
        else:
            latest = [flow for flow in latest if flow.get("drop_reason_desc") == "POLICY_DENIED"]
        if app_ok and latest:
            break
        time.sleep(0.3)
    return app_ok, latest



def _matches_notebook_deny_rule(flow, *, inference_ns, inference_pod, port):
    source=flow.get("source") or {}
    destination=flow.get("destination") or {}
    tcp=(flow.get("l4") or {}).get("TCP") or {}
    return (source.get("namespace")==NOTEBOOK_NS and source.get("pod_name")==NOTEBOOK_CLIENT
            and destination.get("namespace")==inference_ns and destination.get("pod_name")==inference_pod
            and tcp.get("destination_port")==port and flow.get("verdict")=="DROPPED"
            and flow.get("drop_reason_desc")=="POLICY_DENIED")

def _issue_receiver_certs(lab, work):
    authority = work / "saf-0501-007-authority"
    authority.mkdir(mode=0o700, parents=True, exist_ok=True)
    ca_key, ca_cert = authority / "ca.key", authority / "ca.crt"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=SAF 0501-007 synthetic receiver authority",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-keyout", str(ca_key), "-out", str(ca_cert), timeout=25)
    ca_key.chmod(0o600)
    for name in (RECEIVER_A, RECEIVER_B):
        dns = f"{name}.{RECEIVER_NS}.svc.cluster.local"
        key, csr, cert, ext = (authority / f"{name}.{suffix}" for suffix in ("key", "csr", "crt", "ext"))
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=DNS:" + dns + "\n")
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={dns}",
                    "-keyout", str(key), "-out", str(csr), timeout=25)
        key.chmod(0o600)
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                    "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(ext), "-out", str(cert), timeout=15)
        lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                    "-n", RECEIVER_NS, "create", "secret", "tls", f"{name}-identity",
                    "--cert=" + str(cert), "--key=" + str(key), timeout=15)
    return ca_cert


def _secure_pod(name, namespace, *, command, volumes, image=PYTHON_IMAGE, containers_extra=None):
    container = {"name":"fixture","image":image,"command":command,
                 "securityContext":{"allowPrivilegeEscalation":False,"capabilities":{"drop":["ALL"]},
                                    "runAsNonRoot":True,"runAsUser":10001},
                 "resources":{"requests":{"cpu":"5m","memory":"16Mi"},
                             "limits":{"cpu":"100m","memory":"64Mi"}},
                 "volumeMounts":volumes}
    if containers_extra:
        container.update(containers_extra)
    return {"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"namespace":namespace,
            "labels":{"saf-k8s.example/fixture":name}},
            "spec":{"restartPolicy":"Never","automountServiceAccountToken":False,
                    "securityContext":{"fsGroup":10001,"seccompProfile":{"type":"RuntimeDefault"}},
                    "containers":[container]}}


def _create_receivers(lab, ca_cert, work, alert):
    receiver_source = Path(__file__).with_name("alert_receiver.py")
    _kubectl(lab, "-n", RECEIVER_NS, "create", "configmap", "receiver-source",
                      "--from-file=receiver.py=" + str(receiver_source), timeout=15)
    _kubectl(lab, "-n", RECEIVER_NS, "create", "configmap", "receiver-trust",
                      "--from-file=ca.crt=" + str(ca_cert), timeout=15)
    for name in (RECEIVER_A, RECEIVER_B):
        pod = _secure_pod(name, RECEIVER_NS, command=["python", "-B", "/fixture/receiver.py"], volumes=[
            {"name":"code","mountPath":"/fixture","readOnly":True},
            {"name":"identity","mountPath":"/tls","readOnly":True}],
            containers_extra={"readinessProbe":{"tcpSocket":{"port":8443},"periodSeconds":1},
                              "volumeMounts":[{"name":"code","mountPath":"/fixture","readOnly":True},
                                               {"name":"identity","mountPath":"/tls","readOnly":True}]})
        pod["spec"]["volumes"] = [
            {"name":"code","configMap":{"name":"receiver-source","items":[{"key":"receiver.py","path":"receiver.py"}]}},
            {"name":"identity","secret":{"secretName":f"{name}-identity","defaultMode":0o440}},
        ]
        _create(lab, pod)
        _kubectl(lab, "-n", RECEIVER_NS, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=45s", timeout=55)
        service = {"apiVersion":"v1","kind":"Service","metadata":{"name":name,"namespace":RECEIVER_NS},
                  "spec":{"selector":{"saf-k8s.example/fixture":name},"ports":[{"name":"https","port":8443,"targetPort":8443}]}}
        _create(lab, service)
        deadline=time.monotonic()+10
        ready_endpoint=False
        while time.monotonic()<deadline:
            endpoints=_json_output(_kubectl(lab,"-n",RECEIVER_NS,"get","endpoints",name,"-o","json"),
                                   "Could not inspect owned receiver Service endpoints")
            ready_endpoint=any(subset.get("addresses") for subset in endpoints.get("subsets",[]))
            if ready_endpoint:
                break
            time.sleep(0.2)
        if not ready_endpoint:
            lab.block(f"Owned alert receiver {name} has no ready Service endpoint")

    delivery_source = Path(__file__).with_name("alert_delivery.py")
    alert_file = work / "alert.json"
    alert_file.write_text(json.dumps(alert, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    _kubectl(lab, "-n", RECEIVER_NS, "create", "configmap", ALERTS_DATA,
                      "--from-file=delivery.py=" + str(delivery_source),
                      "--from-file=alert.json=" + str(alert_file), timeout=15)
    forwarder = _secure_pod(FORWARDER, RECEIVER_NS, command=["python","-c","import time; time.sleep(1800)"],
        volumes=[{"name":"delivery","mountPath":"/fixture","readOnly":True},
                 {"name":"trust","mountPath":"/trust","readOnly":True}])
    forwarder["spec"]["volumes"]=[
        {"name":"delivery","configMap":{"name":ALERTS_DATA,"items":[
            {"key":"delivery.py","path":"delivery.py"},{"key":"alert.json","path":"alert.json"}]}},
        {"name":"trust","configMap":{"name":"receiver-trust","items":[{"key":"ca.crt","path":"ca.crt"}]}},
    ]
    _create(lab,forwarder)
    _kubectl(lab,"-n",RECEIVER_NS,"wait","--for=condition=Ready",f"pod/{FORWARDER}","--timeout=45s",timeout=55)
    output=_kubectl(lab,"-n",RECEIVER_NS,"exec",FORWARDER,"-c","fixture","--","python","-B","/fixture/delivery.py",timeout=20)
    result=_json_output(output,"Alert delivery client did not produce a normalized receipt")
    return result


def _run_monitoring_supplement(lab):
    """Append five scoped checks after the published eight-check case."""
    port=PORT
    client=NOTEBOOK_CLIENT
    pipeline_ns=NAMESPACES["pipeline"]
    inference_ns=NAMESPACES["inference"]
    pipeline_pod=SERVERS["pipeline"]
    inference_pod=SERVERS["inference"]

    _kubectl(lab,"create","namespace",NOTEBOOK_NS)
    _kubectl(lab,"label","namespace",NOTEBOOK_NS,f"{SEGMENT_LABEL}=notebook")
    _kubectl(lab,"create","namespace",RECEIVER_NS)
    _create(lab, _pod(NOTEBOOK_NS,"notebook",client))
    _wait_pod(lab,NOTEBOOK_NS,client)
    pipeline_ip=_wait_pod(lab,pipeline_ns,pipeline_pod)
    inference_ip=_wait_pod(lab,inference_ns,inference_pod)
    # A source-side default-deny plus exactly one allowed peer defines the notebook boundary.
    _create(lab, {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
            "metadata":{"name":"notebook-egress-default-deny","namespace":NOTEBOOK_NS},
            "spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[]}})
    _create(lab, {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
            "metadata":{"name":"notebook-to-pipeline-only","namespace":NOTEBOOK_NS},
            "spec":{"podSelector":{"matchLabels":{ROLE_LABEL:client}},"policyTypes":["Egress"],
                    "egress":[{"to":[_peer("pipeline",pipeline_pod)],"ports":[{"protocol":"TCP","port":port}]}]}})
    _create(lab, {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
            "metadata":{"name":"allow-notebook-to-pipeline","namespace":pipeline_ns},
            "spec":{"podSelector":{"matchLabels":{ROLE_LABEL:pipeline_pod}},"policyTypes":["Ingress"],
                    "ingress":[{"from":[_peer("notebook",client)],"ports":[{"protocol":"TCP","port":port}]}]}})

    allowed_ok, allowed_flows = _new_observation(lab,NOTEBOOK_NS,pipeline_ns,pipeline_pod,pipeline_ip,True)
    allowed_valid=allowed_ok and bool(allowed_flows)
    lab.check("positive","One notebook-to-pipeline request is accepted and observed by Hubble",
        allowed_valid,{"application_marker_received":allowed_ok,"matching_forwarded_hubble_flow":bool(allowed_flows),
                       "tuple":"notebook->pipeline TCP/18080"})

    denied_ok, denied_flows = _new_observation(lab,NOTEBOOK_NS,inference_ns,inference_pod,inference_ip,False)
    denied_valid=(denied_ok and any(flow.get("drop_reason_desc")=="POLICY_DENIED" and flow.get("uuid")
                                        for flow in denied_flows))
    lab.check("green","Notebook-to-inference is denied by the scoped egress policy and independently observed",
        denied_valid,{"application_request_denied":denied_ok,"policy_denied_hubble_flow":denied_valid,
                      "tuple":"notebook->inference TCP/18080"})

    # Profile uses exact expected permitted route keys, not packet counts or a learned model.
    prior_path=lab.evidence/"hubble-events.json"
    prior=json.loads(prior_path.read_text(encoding="utf-8")) if prior_path.is_file() else []
    training_pipeline_phases=set()
    training_pipeline_flows=[]
    for item in prior:
        flow = item.get("event") or {}
        if (flow.get("verdict")=="FORWARDED"
                and (flow.get("source") or {}).get("namespace")==NAMESPACES["training"]
                and (flow.get("destination") or {}).get("namespace")==pipeline_ns
                and (flow.get("destination") or {}).get("pod_name")==pipeline_pod
                and (((flow.get("l4") or {}).get("TCP") or {}).get("destination_port")==port)):
            training_pipeline_phases.add(item.get("phase"))
            training_pipeline_flows.append(flow)
    training_pipeline={"red","positive"}.issubset(training_pipeline_phases)
    profile={"synthetic_reference":True,"fixed_probe_counts":{"training->pipeline TCP/18080":2,
             "notebook->pipeline TCP/18080":1},
             "observed_allowed_routes":{"training->pipeline TCP/18080":training_pipeline,
                                        "notebook->pipeline TCP/18080":bool(allowed_flows)}}
    (lab.evidence/"baseline-profile.json").write_text(json.dumps(profile,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    profile_route_keys={(NAMESPACES["training"],pipeline_ns,port),(NOTEBOOK_NS,pipeline_ns,port)}
    denied_tuple_outside=(NOTEBOOK_NS,inference_ns,port) not in profile_route_keys
    profile_ok=training_pipeline and bool(allowed_flows) and denied_tuple_outside

    # Evaluate a fixed route/verdict predicate against the actual selected flows.
    allowed_comparators=training_pipeline_flows+allowed_flows
    comparator_matches=[flow for flow in allowed_comparators
                        if _matches_notebook_deny_rule(flow,inference_ns=inference_ns,
                                                       inference_pod=inference_pod,port=port)]
    denied_candidates=[flow for flow in denied_flows
                       if _matches_notebook_deny_rule(flow,inference_ns=inference_ns,
                                                      inference_pod=inference_pod,port=port)]
    allowed_comparators_clear=bool(training_pipeline_flows and allowed_flows) and not comparator_matches
    alert={"event_id":ALERT_ID,"rule_id":RULE_ID,
           "source":f"{NOTEBOOK_NS}/{client}","destination":f"{inference_ns}/{inference_pod}",
           "protocol":f"TCP/{port}","verdict":"DROPPED","reason":"POLICY_DENIED",
           "hubble_flow_uuid":denied_candidates[0].get("uuid")} if denied_candidates else None
    lab.check("positive","The fixed baseline profile identifies one denied notebook edge outside its two allowed route keys",
        profile_ok,{"profile_written":(lab.evidence/"baseline-profile.json").is_file(),
                    "allowed_training_pipeline_observed":training_pipeline,
                    "allowed_notebook_pipeline_observed":bool(allowed_flows),
                    "denied_notebook_inference_outside_profile":denied_tuple_outside})

    alert_path=lab.evidence/"notebook-denied-alert.json"
    alert_path.write_text(json.dumps({"alert_count":1 if alert else 0,"alerts":[alert] if alert else []},
                                     indent=2,sort_keys=True)+"\n",encoding="utf-8")
    rule_ok=bool(alert and denied_valid and allowed_comparators_clear and profile_ok
                 and json.loads(alert_path.read_text())["alert_count"]==1)
    lab.check("green","The fixed rule emits exactly one alert for the Hubble policy-denied notebook path and none for allowed comparators",
        rule_ok,{"one_alert_for_observed_denial":rule_ok,
                 "allowed_route_comparators_clear":allowed_comparators_clear,
                 "deduplicated_alert_count":1 if alert else 0})
    ca_cert=_issue_receiver_certs(lab,lab.kubeconfig.parent)
    deliveries=_create_receivers(lab,ca_cert,lab.kubeconfig.parent,alert or {})
    receivers=deliveries.get("receivers",[])
    expected_hosts=[f"{RECEIVER_A}.{RECEIVER_NS}.svc.cluster.local",f"{RECEIVER_B}.{RECEIVER_NS}.svc.cluster.local"]
    identity_ok=(len(receivers)==2 and [r.get("host") for r in receivers]==expected_hosts
                 and all(r.get("post_status")==202 and r.get("ack_matches") and r.get("san_matches") for r in receivers))
    readbacks_ok=(len(receivers)==2 and all(r.get("receipt_count")==1 and r.get("receipt_digest_matches_payload") for r in receivers)
                  and deliveries.get("payload_digests_equal") is True)
    # Save only minimized receiver observations; omit run-specific digest and certificate fingerprints.
    minimized={"receiver_count":len(receivers),"each_tls_san_verified":identity_ok,
               "each_post_accepted":len(receivers)==2 and all(r.get("post_status")==202 for r in receivers),
               "each_independent_readback_once":readbacks_ok,
               "same_event_id_at_both":len(receivers)==2 and all(r.get("ack_matches") for r in receivers),
               "same_payload_digest_at_both":deliveries.get("payload_digests_equal") is True,
               "receiver_certificates_distinct":deliveries.get("receiver_certificates_distinct") is True}
    delivery_ok=rule_ok and identity_ok and readbacks_ok and minimized["receiver_certificates_distinct"]
    (lab.evidence/"receiver-delivery-observations.json").write_text(json.dumps(minimized,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    lab.check("green","The single synthetic alert is independently received by two trusted TLS endpoints",
        delivery_ok,{"single_alert_exists":rule_ok,
                     "both_receiver_sans_verified":identity_ok,
                     "both_independent_receipts_match_once":readbacks_ok,
                     "distinct_trusted_receiver_certificates":minimized["receiver_certificates_distinct"]})

    # Actual Hubble source events retained separately from the stable result details.
    raw_records=[]
    for phase,flows in (("notebook-pipeline-allowed",allowed_flows),("notebook-inference-denied",denied_flows)):
        for flow in flows:
            raw_records.append({"phase":phase,"flow":flow})
    (lab.evidence/"notebook-hubble-events.json").write_text(json.dumps(raw_records,indent=2,sort_keys=True)+"\n",encoding="utf-8")
