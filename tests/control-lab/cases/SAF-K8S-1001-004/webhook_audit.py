"""Bounded Kubernetes audit webhook delivery and native metric fixture."""

import base64
from datetime import datetime
import json
from pathlib import Path
import re
import time


CASE_DIR = Path(__file__).resolve().parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
RECEIVER_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
SERVICE = "audit-webhook-sink"
SERVICE_IP = "10.96.42.26"
POD = "audit-webhook-sink"
TLS_SECRET = "audit-webhook-tls"
CODE_SECRET = "audit-webhook-code"
FIXTURE_PREFIX = "saf10010041"
MEASURED_OPERATIONS = 5
WEBHOOK_FLAGS = {
    "audit-webhook-mode": "batch",
    "audit-webhook-initial-backoff": "250ms",
    "audit-webhook-batch-buffer-size": "16",
    "audit-webhook-batch-max-size": "1",
    "audit-webhook-batch-max-wait": "500ms",
    "audit-webhook-batch-throttle-enable": "true",
    "audit-webhook-batch-throttle-qps": "10",
    "audit-webhook-batch-throttle-burst": "2",
}
SCOPE = (
    "One fresh single-node Kind Kubernetes v1.36.1 cluster. Exactly five measured, "
    "inert ConfigMap creates in saf-test are selected by the audit policy. A case-owned "
    "TLS receiver gets an injected one-request HTTP 503, then recovers on retry. The case "
    "delays one exact fixture event's receiver acknowledgement by 200ms, and matches every returned Audit-Id "
    "to exactly one retained ResponseComplete Metadata "
    "event and records native API-server audit metric samples. No host ports, external "
    "audit destinations, throughput measurement, or production capacity conclusion."
)


def prepare_kind(_lab, temporary):
    policy = temporary / "audit-policy.yaml"
    policy.write_bytes((CASE_DIR / "audit-policy.yaml").read_bytes())
    (temporary / "receiver.py").write_bytes((CASE_DIR / "receiver.py").read_bytes())

    ca = temporary / "receiver-ca.crt"
    ca_key = temporary / "receiver-ca.key"
    request = temporary / "receiver.csr"
    ca_config = temporary / "ca.cnf"
    ca_config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\n"
        "[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
    )
    extensions = temporary / "tls.cnf"
    dns_name = f"{SERVICE}.{NAMESPACE}.svc"
    extensions.write_text(
        f"subjectAltName=DNS:{dns_name}\n"
        "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
    )
    _lab.command(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "2", "-config", str(ca_config), "-subj", "/CN=SAF audit fixture CA",
        "-keyout", str(ca_key), "-out", str(ca),
    )
    _lab.command(
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-subj", f"/CN={dns_name}", "-keyout", str(temporary / "receiver-server.key"),
        "-out", str(request),
    )
    _lab.command(
        "openssl", "x509", "-req", "-in", str(request), "-CA", str(ca),
        "-CAkey", str(ca_key), "-set_serial", "1", "-days", "2", "-sha256",
        "-extfile", str(extensions), "-out", str(temporary / "receiver-server.crt"),
    )
    ca_key.unlink()

    webhook = temporary / "audit-webhook.kubeconfig"
    webhook.write_text(json.dumps({
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "case-receiver", "cluster": {
            "server": f"https://{SERVICE_IP}:8443", "tls-server-name": dns_name,
            "certificate-authority-data": base64.b64encode(ca.read_bytes()).decode("ascii"),
        }}],
        "users": [{"name": "webhook", "user": {}}],
        "contexts": [{"name": "webhook", "context": {
            "cluster": "case-receiver", "user": "webhook",
        }}],
        "current-context": "webhook",
    }), encoding="utf-8")

    extra_args = "".join(
        f"        - name: {name}\n          value: {json.dumps(value)}\n"
        for name, value in {
            "audit-policy-file": "/etc/kubernetes/audit-policy.yaml",
            "audit-webhook-config-file": "/etc/kubernetes/audit-webhook.kubeconfig",
            **WEBHOOK_FLAGS,
            "audit-webhook-version": "audit.k8s.io/v1",
        }.items()
    )
    config = temporary / "kind.yaml"
    config.write_text(
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n"
        "  - role: control-plane\n    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(webhook))}\n"
        "        containerPath: /etc/kubernetes/audit-webhook.kubeconfig\n        readOnly: true\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n    kind: ClusterConfiguration\n"
        "    apiServer:\n      extraArgs:\n" + extra_args +
        "      extraVolumes:\n"
        "        - name: audit-policy\n"
        "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n          pathType: File\n"
        "        - name: audit-webhook\n"
        "          hostPath: /etc/kubernetes/audit-webhook.kubeconfig\n"
        "          mountPath: /etc/kubernetes/audit-webhook.kubeconfig\n"
        "          readOnly: true\n          pathType: File\n",
        encoding="utf-8",
    )
    return config


def receiver_pod():
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": POD, "namespace": NAMESPACE,
                     "labels": {"app": SERVICE}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                 "runAsGroup": 10001, "fsGroup": 10001,
                                 "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "receiver", "image": RECEIVER_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-u", "/app/receiver.py"],
                "ports": [{"name": "https", "containerPort": 8443}],
                "readinessProbe": {"httpGet": {"path": "/healthz", "port": "https",
                                                   "scheme": "HTTPS"},
                                   "periodSeconds": 1, "failureThreshold": 30},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [
                    {"name": "code", "mountPath": "/app", "readOnly": True},
                    {"name": "tls", "mountPath": "/tls", "readOnly": True},
                    {"name": "data", "mountPath": "/data"},
                ],
            }],
            "volumes": [
                {"name": "code", "secret": {"secretName": CODE_SECRET}},
                {"name": "tls", "secret": {"secretName": TLS_SECRET}},
                {"name": "data", "emptyDir": {}},
            ],
        },
    }


def kubectl_create_configmap(lab, name, fixture_index):
    resource = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf.synthetic/audit-fixture": "true"}},
        "data": {"fixture": f"inert-synthetic-value-{fixture_index}"},
    }
    result = lab.kubectl(
        "create", "--raw", f"/api/v1/namespaces/{NAMESPACE}/configmaps", "-f", "-",
        "--v=8", payload=json.dumps(resource),
    )
    audit_ids = set(re.findall(r"(?i)\baudit-id\s*:\s*([a-f0-9-]{36})", result.stderr))
    returned = json.loads(result.stdout)
    if len(audit_ids) != 1 or returned.get("metadata", {}).get("name") != name:
        lab.block(f"Create for {name} did not return its unique expected object and Audit-Id")
    return audit_ids.pop()


def metric_family(text, name):
    lines = text.splitlines()
    family_lines = []
    family_found = False
    for line in lines:
        if line.startswith(f"# HELP {name} ") or line.startswith(f"# TYPE {name} "):
            family_found = True
            family_lines.append(line)
        elif line.startswith(name + " ") or line.startswith(name + "{"):
            family_found = True
            family_lines.append(line)
    samples = [line for line in family_lines if not line.startswith("#")]
    return family_found, samples


def metric_value(samples, *, required_label=None):
    candidates = []
    for sample in samples:
        labels = sample.split("}", 1)[0] if "{" in sample else ""
        if required_label and required_label not in labels:
            continue
        try:
            candidates.append(float(sample.rsplit(" ", 1)[1]))
        except (IndexError, ValueError):
            continue
    return sum(candidates) if candidates else None


def capture_metrics(lab, label):
    raw = lab.kubectl("get", "--raw", "/metrics").stdout
    names = (
        "apiserver_audit_event_total", "apiserver_audit_error_total",
        "apiserver_audit_requests_rejected_total",
    )
    evidence = {"endpoint": "kube-apiserver /metrics via local kubectl raw request",
                "families": {}, "selected_raw_lines": []}
    for name in names:
        found, samples = metric_family(raw, name)
        if found:
            evidence["selected_raw_lines"].extend(
                line for line in raw.splitlines()
                if line.startswith(f"# HELP {name} ") or line.startswith(f"# TYPE {name} ")
                or line.startswith(name + " ") or line.startswith(name + "{")
            )
        evidence["families"][name] = {"present": found, "samples": samples}
    (lab.evidence / f"audit-metrics-{label}.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def metric_counter(metrics, name, required_label=None):
    return metric_value(metrics["families"][name]["samples"], required_label=required_label)


def exec_script(lab, script, *args, timeout=45):
    result = lab.kubectl("exec", f"pod/{POD}", "--", "python", "-c", script,
                         *args, timeout=timeout)
    return result.stdout.strip()


SNAPSHOT_SCRIPT = r'''import http.client, json, socket, ssl
address, server_name = __import__("sys").argv[1:]
context = ssl.create_default_context(cafile="/tls/ca.crt")
with socket.create_connection((address, 8443), timeout=3) as raw:
    with context.wrap_socket(raw, server_hostname=server_name) as tls:
        tls.sendall(("GET /__case/snapshot HTTP/1.1\r\nHost: " + server_name +
                     "\r\nConnection: close\r\n\r\n").encode())
        response = http.client.HTTPResponse(tls)
        response.begin()
        if response.status != 200:
            raise SystemExit("snapshot returned HTTP " + str(response.status))
        print(response.read().decode())
'''

ARM_FAIL_SCRIPT = r'''import http.client, json, socket, ssl, sys
context = ssl.create_default_context(cafile="/tls/ca.crt")
with socket.create_connection(("127.0.0.1", 8443), timeout=3) as raw:
    with context.wrap_socket(raw, server_hostname=sys.argv[1]) as tls:
        tls.sendall(("POST /__case/fail-next HTTP/1.1\r\nHost: " + sys.argv[1] +
                     "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").encode())
        response = http.client.HTTPResponse(tls)
        response.begin()
        if response.status != 200:
            raise SystemExit("could not arm single transient failure")
        response.read()
'''


def snapshot(lab):
    return json.loads(exec_script(lab, SNAPSHOT_SCRIPT, SERVICE_IP,
                                  f"{SERVICE}.{NAMESPACE}.svc"))


def wait_snapshot(lab, expected_ids, timeout=45):
    deadline = time.monotonic() + timeout
    last = {"events": [], "attempts": []}
    while time.monotonic() < deadline:
        last = snapshot(lab)
        ids = {event.get("auditID") for event in last["events"]}
        attempts = last["attempts"]
        has_failure_and_recovery = (
            any(attempt.get("status") == 503 for attempt in attempts)
            and any(attempt.get("status") == 200 for attempt in attempts)
        )
        if expected_ids.issubset(ids) and has_failure_and_recovery:
            return last
        time.sleep(0.5)
    return last


def exact_fixture_events(events, expected):
    by_id = {}
    for event in events:
        by_id.setdefault(event.get("auditID"), []).append(event)
    expected_ids = set(expected.values())
    names = set(expected)
    matching_names = {}
    for event_id in expected_ids:
        records = by_id.get(event_id, [])
        if len(records) != 1:
            return False, {"expected_audit_id_count": len(expected_ids),
                           "duplicate_or_missing_audit_ids": True}
        event = records[0]
        obj = event.get("objectRef") or {}
        name = obj.get("name")
        matching_names.setdefault(name, []).append(event)
        if (event.get("stage") != "ResponseComplete" or event.get("level") != "Metadata"
                or event.get("verb") != "create" or obj.get("resource") != "configmaps"
                or obj.get("namespace") != NAMESPACE
                or event.get("responseStatus", {}).get("code") != 201
                or "requestObject" in event or "responseObject" in event):
            return False, {"expected_audit_id_count": len(expected_ids),
                           "fixture_fields_match": False}
    names_once = set(matching_names) == names and all(len(value) == 1 for value in matching_names.values())
    fixture_records = [event for event in events
                       if (event.get("objectRef") or {}).get("name", "").startswith(FIXTURE_PREFIX)]
    no_extra_fixture_records = len(fixture_records) == len(expected_ids)
    return names_once and no_extra_fixture_records, {
        "expected_audit_id_count": len(expected_ids),
        "delivered_fixture_event_count": len(fixture_records),
        "fixture_names_match": names_once,
        "no_extra_fixture_events": no_extra_fixture_records,
        "metadata_only": all("requestObject" not in event and "responseObject" not in event
                              for event in fixture_records),
    }


def run(lab):
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server_version = version.get("serverVersion", {}).get("gitVersion")
    if server_version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server_version}")

    apiserver = json.loads(lab.kubectl("-n", "kube-system", "get", "pod",
                                       "-l", "component=kube-apiserver", "-o", "json").stdout)
    containers = [container for pod in apiserver.get("items", [])
                  for container in pod.get("spec", {}).get("containers", [])
                  if container.get("name") == "kube-apiserver"]
    args = containers[0].get("command", []) if containers else []
    observed_flags = {}
    arg_index = 0
    while arg_index < len(args):
        item = args[arg_index]
        if item.startswith("--"):
            name, separator, value = item[2:].partition("=")
            if separator:
                observed_flags[name] = value
            elif arg_index + 1 < len(args) and not args[arg_index + 1].startswith("--"):
                observed_flags[name] = args[arg_index + 1]
                arg_index += 1
        arg_index += 1
    flag_record = {"selected": WEBHOOK_FLAGS,
                   "observed": {name: observed_flags.get(name) for name in WEBHOOK_FLAGS}}
    (lab.evidence / "selected-webhook-flags.json").write_text(
        json.dumps(flag_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lab.check("positive", "Pinned API server exposes the selected webhook batch and throttle flags",
              all(observed_flags.get(name) == value for name, value in WEBHOOK_FLAGS.items()), flag_record)

    receiver_code = lab.kubeconfig.with_name("receiver.py")
    lab.kubectl("create", "secret", "generic", CODE_SECRET,
                f"--from-file=receiver.py={receiver_code}")
    lab.kubectl("create", "secret", "generic", TLS_SECRET,
                f"--from-file=tls.crt={lab.kubeconfig.with_name('receiver-server.crt')}",
                f"--from-file=tls.key={lab.kubeconfig.with_name('receiver-server.key')}",
                f"--from-file=ca.crt={lab.kubeconfig.with_name('receiver-ca.crt')}")
    lab.kubectl("apply", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": NAMESPACE},
        "spec": {"type": "ClusterIP", "clusterIP": SERVICE_IP,
                 "selector": {"app": SERVICE},
                 "ports": [{"name": "https", "port": 8443, "targetPort": 8443}]},
    }))
    lab.kubectl("apply", "-f", "-", payload=json.dumps(receiver_pod()))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{POD}", "--timeout=90s", timeout=100)

    metrics_before = capture_metrics(lab, "before")
    for name in ("apiserver_audit_event_total", "apiserver_audit_requests_rejected_total"):
        family = metrics_before["families"][name]
        lab.check("positive", f"Native metric family {name} is exposed by v1.36.1",
                  family["present"], {"native_family_present": family["present"]})

    server_name = f"{SERVICE}.{NAMESPACE}.svc"
    exec_script(lab, ARM_FAIL_SCRIPT, server_name)
    expected = {}
    for i in range(1, MEASURED_OPERATIONS + 1):
        name = f"{FIXTURE_PREFIX}-{i:02d}"
        expected[name] = kubectl_create_configmap(lab, name, i)

    final = wait_snapshot(lab, set(expected.values()))
    exact_ok, exact_result = exact_fixture_events(final["events"], expected)
    attempts = final["attempts"]
    first_attempt = next((a for a in attempts if a.get("status") == 503), None)
    retry_attempt = next((a for a in attempts if a.get("status") == 200
                          and first_attempt and a.get("audit_ids") == first_attempt.get("audit_ids")), None)
    fault_ok = (first_attempt is not None and retry_attempt is not None
                and len(first_attempt.get("audit_ids", [])) == 1)
    audit_id_to_name = {audit_id: name for name, audit_id in expected.items()}
    fault_name = audit_id_to_name.get(first_attempt.get("audit_ids", [None])[0]) if first_attempt else None
    fault_ok = fault_ok and fault_name is not None and retry_attempt.get("audit_ids") == [expected[fault_name]]
    (lab.evidence / "fixture-audit-ids.json").write_text(
        json.dumps({"expected_by_configmap": expected,
                    "receiver_events": final["events"],
                    "receiver_attempts": attempts}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    lab.check("red", "Receiver observed the single injected 503 for a measured webhook batch",
              first_attempt is not None and len(first_attempt.get("audit_ids", [])) == 1,
              {"scoped_initial_503": first_attempt is not None and fault_name is not None})
    lab.check("green", "One bounded HTTP 503 is followed by a successful retry of the same event",
              fault_ok, {"same_event_receives_successful_retry": bool(fault_ok)})
    lab.check("positive", "All five exact synthetic Audit-IDs arrive once as scoped metadata events",
              exact_ok, exact_result)

    delayed_name = f"{FIXTURE_PREFIX}-01"
    delayed_audit_id = expected[delayed_name]
    delayed_event = next((event for event in final["events"]
                          if event.get("auditID") == delayed_audit_id), None)
    delayed_attempts = [attempt for attempt in attempts
                        if attempt.get("audit_ids") == [delayed_audit_id]]
    delayed_failure = next((attempt for attempt in delayed_attempts
                            if attempt.get("status") == 503), None)
    delayed_success = next((attempt for attempt in delayed_attempts
                            if attempt.get("status") == 200), None)
    source_timestamp = (delayed_event or {}).get("requestReceivedTimestamp")
    try:
        source_epoch_ns = int(datetime.fromisoformat(
            source_timestamp.replace("Z", "+00:00")).timestamp() * 1_000_000_000)
    except (AttributeError, ValueError, OverflowError):
        source_epoch_ns = None
    receiver_hold_ms = (
        (delayed_success["response_at_unix_ns"] - delayed_success["received_at_unix_ns"]) / 1_000_000
        if delayed_success else None
    )
    source_to_ack_ms = (
        (delayed_success["response_at_unix_ns"] - source_epoch_ns) / 1_000_000
        if delayed_success and source_epoch_ns is not None else None
    )
    delay_observation = {
        "configmap_name": delayed_name,
        "audit_id_matches_requested_operation": bool(delayed_event)
        and (delayed_event.get("objectRef") or {}).get("name") == delayed_name,
        "request_timestamp_present": source_epoch_ns is not None,
        "same_event_received_503_then_200": (
            delayed_failure is not None and delayed_success is not None
            and delayed_failure.get("controlled_delay_applied") is True
            and delayed_success.get("controlled_delay_applied") is True
            and delayed_failure["response_at_unix_ns"] <= delayed_success["received_at_unix_ns"]),
        "receiver_controlled_delay_ms": receiver_hold_ms,
        "source_request_to_receiver_ack_ms": source_to_ack_ms,
        "delayed_retry_delivery_exactly_once": sum(
            event.get("auditID") == delayed_audit_id for event in final["events"]) == 1,
    }
    delay_ok = (
        delay_observation["audit_id_matches_requested_operation"]
        and delay_observation["request_timestamp_present"]
        and delay_observation["same_event_received_503_then_200"]
        and receiver_hold_ms is not None and 150 <= receiver_hold_ms <= 2000
        and source_to_ack_ms is not None and 0 <= source_to_ack_ms <= 5000
        and delay_observation["delayed_retry_delivery_exactly_once"]
    )
    (lab.evidence / "bounded-delivery-delay.json").write_text(
        json.dumps(delay_observation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    stable = {key: value for key, value in delay_observation.items()
              if key not in {"receiver_controlled_delay_ms", "source_request_to_receiver_ack_ms"}}
    stable["local_timing_bounds_met"] = (receiver_hold_ms is not None and 150 <= receiver_hold_ms <= 2000
                                         and source_to_ack_ms is not None and 0 <= source_to_ack_ms <= 5000)
    lab.check("positive", "One exact synthetic Audit-ID survives an injected receiver delay and retry within the local observation bound",
              delay_ok, stable)

    metrics_after = capture_metrics(lab, "after")
    event_before = metric_counter(metrics_before, "apiserver_audit_event_total")
    event_after = metric_counter(metrics_after, "apiserver_audit_event_total")
    error_before = metric_counter(metrics_before, "apiserver_audit_error_total", 'plugin="webhook"')
    error_after = metric_counter(metrics_after, "apiserver_audit_error_total", 'plugin="webhook"')
    rejected_before = metric_counter(metrics_before, "apiserver_audit_requests_rejected_total")
    rejected_after = metric_counter(metrics_after, "apiserver_audit_requests_rejected_total")
    metric_result = {
        "event_total_before": event_before, "event_total_after": event_after,
        "event_total_delta": (event_after - event_before
                              if event_before is not None and event_after is not None else None),
        "webhook_error_total_before": error_before, "webhook_error_total_after": error_after,
        "requests_rejected_total_before": rejected_before,
        "requests_rejected_total_after": rejected_after,
        "receiver_http_503_then_200": fault_ok,
    }
    metric_delta_ok = (event_before is not None and event_after is not None
                       and event_after - event_before == MEASURED_OPERATIONS)
    (lab.evidence / "webhook-metric-comparison.json").write_text(
        json.dumps(metric_result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lab.check("positive", "Native event counter delta matches the five delivered events",
              metric_delta_ok, {"fixture_event_counter_delta": metric_result["event_total_delta"]})
    no_terminal_drop = (error_before == error_after and rejected_before is not None
                        and rejected_before == rejected_after)
    lab.check("positive", "The recovered attempt records no additional terminal webhook drop or rejected request",
              no_terminal_drop, {"webhook_drop_counter_unchanged": error_before == error_after,
                                 "rejected_request_counter_unchanged": rejected_before == rejected_after})
