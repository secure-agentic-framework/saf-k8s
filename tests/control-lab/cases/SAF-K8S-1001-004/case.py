"""Compare finite synthetic Kubernetes audit fixtures under two policies."""
from pathlib import Path
import json
import runpy
from tempfile import TemporaryDirectory
import time
from urllib.parse import parse_qs, urlsplit

NODE_IMAGE = ("kindest/node:v1.36.1@sha256:"
              "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5")
NAMESPACE = "saf-test"
AUDIT_DIR = "/var/log/kubernetes/audit"
AUDIT_FILE = f"{AUDIT_DIR}/audit.jsonl"
LOW_OPS = 5
HIGH_MARKER = "saf1001-004-rbac-high-fidelity"
DENIED_MARKER = "saf1001-004-denied-write"
IDENTITY_POD = "saf-audit-identity-reader"
ACCOUNT = "audit-identity-reader"
USERNAME = f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}"
GROUP = f"system:serviceaccounts:{NAMESPACE}"
READ_IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
              "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
IDENTITY_READS = ("audit-poll-a", "audit-poll-b")
READ_SCRIPT = """import json, pathlib, socket, ssl, sys, time, urllib.error, urllib.request
root = pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount')
context = ssl.create_default_context(cafile=str(root / 'ca.crt'))
token = (root / 'token').read_text().strip()
for name in sys.argv[1:]:
    request = urllib.request.Request(
        f'https://kubernetes.default.svc/api/v1/namespaces/saf-test/configmaps/{name}',
        headers={'Authorization': 'Bearer ' + token},
    )
    deadline = time.monotonic() + 18
    while True:
        try:
            with urllib.request.urlopen(request, timeout=8, context=context) as reply:
                actual = json.load(reply)
                print(json.dumps({'name': name, 'status': reply.status,
                                  'fixture_matches': actual['data']['fixture'] == 'owned-synthetic-value'}))
                break
        except urllib.error.URLError as error:
            transient_dns = isinstance(error.reason, socket.gaierror) and error.reason.errno == socket.EAI_AGAIN
            if not transient_dns or time.monotonic() >= deadline:
                raise
            time.sleep(0.5)
"""
SCOPE = (
    "Two fresh, single-control-plane Kind Kubernetes v1.36.1 clusters. Both receive the same "
    "seven measured API operations: five small ConfigMap LIST polls, one synthetic RoleBinding "
    "create, and one denied synthetic ConfigMap create. Red uses RequestResponse for both fixture resource types. "
    "Green omits RequestReceived, records ConfigMap LIST polls at Metadata, and retains both "
    "security-relevant writes at RequestResponse. Matching raw lines and file byte counts are "
    "saved. This finite fixture does not model sustained workload, production capacity, drops, "
    "backpressure, real AI traffic, or cluster-wide coverage."
)


def service_account_audit_rules():
    rules = [
        ("None", "users", f"system:serviceaccount:{NAMESPACE}:*", IDENTITY_READS[0]),
        ("Metadata", "users", USERNAME, IDENTITY_READS[0]),
        ("Metadata", "userGroups", GROUP, IDENTITY_READS[1]),
    ]
    return "".join(
        f"  - level: {level}\n    {field}: [{json.dumps(value)}]\n"
        f"    verbs: [get]\n    namespaces: [{NAMESPACE}]\n"
        f"    resources:\n      - group: \"\"\n        resources: [configmaps]\n"
        f"        resourceNames: [{name}]\n"
        for level, field, value, name in rules
    )


def policy_text(phase):
    group_rules = (
        "      - group: \"\"\n"
        "        resources: [configmaps]\n"
        "      - group: rbac.authorization.k8s.io\n"
        "        resources: [rolebindings]\n"
    )
    high_fidelity = (
        "  - level: RequestResponse\n"
        f"    namespaces: [{NAMESPACE}]\n"
        "    resources:\n"
        + group_rules
    )
    policy = "apiVersion: audit.k8s.io/v1\nkind: Policy\n"
    if phase == "red":
        return policy + "rules:\n" + high_fidelity + "  - level: None\n"
    return (
        policy
        + "omitStages: [RequestReceived]\nrules:\n"
        + service_account_audit_rules()
        + "  - level: Metadata\n"
        + "    verbs: [list]\n"
        + f"    namespaces: [{NAMESPACE}]\n"
        + "    resources:\n"
        + "      - group: \"\"\n"
        + "        resources: [configmaps]\n"
        + high_fidelity
        + "  - level: None\n"
    )


def kind_config(policy, audit_dir):
    return (
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n"
        "  - role: control-plane\n    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(audit_dir))}\n"
        f"        containerPath: {AUDIT_DIR}\n        readOnly: false\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n    kind: ClusterConfiguration\n"
        "    apiServer:\n      extraArgs:\n"
        "        - name: audit-policy-file\n          value: /etc/kubernetes/audit-policy.yaml\n"
        f"        - name: audit-log-path\n          value: {AUDIT_FILE}\n"
        "        - name: audit-log-format\n          value: json\n"
        "        - name: audit-log-mode\n          value: blocking\n"
        "        - name: audit-log-maxsize\n          value: \"10\"\n"
        "        - name: audit-log-maxbackup\n          value: \"2\"\n"
        "        - name: audit-log-maxage\n          value: \"7\"\n"
        "      extraVolumes:\n"
        "        - name: audit-policy\n"
        "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n          pathType: File\n"
        "        - name: audit-log\n"
        f"          hostPath: {AUDIT_DIR}\n          mountPath: {AUDIT_DIR}\n"
        "          readOnly: false\n          pathType: DirectoryOrCreate\n"
    )


def prepare_kind(lab, temporary):
    audit_dir = temporary / "audit-red"
    audit_dir.mkdir()
    policy = temporary / "audit-policy-red.yaml"
    policy.write_text(policy_text("red"))
    config = temporary / "kind-audit-red.yaml"
    config.write_text(kind_config(policy, audit_dir))
    return config


def kubectl(lab, kubeconfig, *args, allow_failure=False, payload=None, timeout=45):
    return lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", NAMESPACE, "--request-timeout=35s", *args,
        allow_failure=allow_failure, payload=payload, timeout=timeout,
    )


def selected_records(path, offset):
    raw = path.read_bytes()[offset:]
    result = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        query = parse_qs(urlsplit(event.get("requestURI", "")).query)
        if (query.get("labelSelector") == ["audit.saf.test/poll=true"] or
                HIGH_MARKER in query.get("fieldManager", []) or
                DENIED_MARKER in query.get("fieldManager", [])):
            result.append((line.decode("utf-8"), event))
    return result


def wait_records(path, offset, count):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        records = selected_records(path, offset)
        if len(records) >= count:
            return records
        time.sleep(0.2)
    return selected_records(path, offset)


def run_operations(lab, kubeconfig, audit_path, phase):
    for name in ("audit-poll-a", "audit-poll-b"):
        obj = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": NAMESPACE,
                         "labels": {"audit.saf.test/poll": "true"}},
            "data": {"fixture": "owned-synthetic-value"},
        }
        kubectl(lab, kubeconfig, "create", "-f", "-", payload=json.dumps(obj))
    offset = audit_path.stat().st_size if audit_path.exists() else 0

    # A fixed five read polls models finite controller inventory traffic.
    for _ in range(LOW_OPS):
        kubectl(lab, kubeconfig, "get", "--raw",
                f"/api/v1/namespaces/{NAMESPACE}/configmaps?labelSelector=audit.saf.test%2Fpoll%3Dtrue")
    kubectl(lab, kubeconfig, "create", "rolebinding", "saf-audit-fixture-binding",
            "--clusterrole=view", "--user=saf-synthetic:workload",
            f"--field-manager={HIGH_MARKER}")
    denied = kubectl(
        lab, kubeconfig, "--as=saf-synthetic:unprivileged", "create", "configmap",
        "saf-denied-fixture", "--from-literal=fixture=synthetic",
        f"--field-manager={DENIED_MARKER}", allow_failure=True,
    )
    if denied.returncode != 1 or "is forbidden" not in denied.stderr or "saf-synthetic:unprivileged" not in denied.stderr:
        lab.block(f"{phase}: expected synthetic unauthorized create to be Forbidden")

    # Red retains RequestReceived and ResponseComplete. Green omits the former.
    expected_audit_events = (LOW_OPS + 2) * (2 if phase == "red" else 1)
    records = wait_records(audit_path, offset, expected_audit_events)
    lines = [line for line, _event in records]
    (lab.evidence / f"{phase}-selected-audit.jsonl").write_text("\n".join(lines) + "\n")
    (lab.evidence / f"{phase}-backend-observation.json").write_text(json.dumps({
        "backend": "kube-apiserver file audit backend",
        "policy": phase,
        "selected_event_count": len(records),
        "selected_raw_line_bytes": sum(len(line.encode()) + 1 for line in lines),
        "audit_file_bytes_after_fixture": audit_path.stat().st_size,
        "rotation_flags": {"audit-log-maxsize-MiB": 10, "audit-log-maxbackup": 2,
                           "audit-log-maxage-days": 7},
    }, indent=2) + "\n")
    return records


def verify_service_account_audit(lab, kubeconfig, audit_path):
    rules = [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": list(IDENTITY_READS),
              "verbs": ["get"]}]
    objects = [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
         "metadata": {"name": ACCOUNT}, "rules": rules},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
         "metadata": {"name": ACCOUNT}, "subjects": [{"kind": "ServiceAccount", "name": ACCOUNT,
                                                            "namespace": NAMESPACE}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACCOUNT}},
        {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": IDENTITY_POD}, "spec": {
            "serviceAccountName": ACCOUNT, "automountServiceAccountToken": True, "restartPolicy": "Never",
            "containers": [{"name": "reader", "image": READ_IMAGE,
                            "command": ["python", "-c", "import time; time.sleep(300)"]}],
        }},
    ]
    kubectl(lab, kubeconfig, "create", "-f", "-", payload=json.dumps(
        {"apiVersion": "v1", "kind": "List", "items": objects}))
    kubectl(lab, kubeconfig, "wait", "--for=condition=Ready", f"pod/{IDENTITY_POD}",
            "--timeout=75s", timeout=85)
    offset = audit_path.stat().st_size
    reply = kubectl(lab, kubeconfig, "exec", IDENTITY_POD, "--", "python", "-c", READ_SCRIPT, *IDENTITY_READS)
    readback = [json.loads(line) for line in reply.stdout.splitlines()]
    expected = [{"name": name, "status": 200, "fixture_matches": True} for name in IDENTITY_READS]
    audit = []
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        audit = [event for event in map(json.loads, audit_path.read_bytes()[offset:].splitlines())
                 if event.get("user", {}).get("username") == USERNAME
                 and event.get("verb") == "get"
                 and event.get("objectRef", {}).get("name") in IDENTITY_READS]
        if len(audit) >= 2:
            break
        time.sleep(0.2)
    expected_names = {event.get("objectRef", {}).get("name") for event in audit} == set(IDENTITY_READS)
    audit_matches = len(audit) == 2 and expected_names and all(
        event.get("stage") == "ResponseComplete" and event.get("level") == "Metadata"
        and event.get("objectRef", {}).get("namespace") == NAMESPACE
        and event.get("objectRef", {}).get("resource") == "configmaps"
        and event.get("responseStatus", {}).get("code") == 200
        and GROUP in event.get("user", {}).get("groups", [])
        and "requestObject" not in event and "responseObject" not in event for event in audit
    )
    (lab.evidence / "service-account-audit-matching.json").write_text(json.dumps(audit, indent=2) + "\n")
    lab.check("selector", "A prefix-star audit username does not match; exact user and group selectors do",
              audit_matches and readback == expected, {"authenticated_reads_match": readback == expected,
              "exact_metadata_records_match": audit_matches, "metadata_records": len(audit)})


def has_marker(event, marker):
    query = parse_qs(urlsplit(event.get("requestURI", "")).query)
    return marker in query.get("fieldManager", [])


def binding_signature(event):
    request, response = event.get("requestObject", {}), event.get("responseObject", {})
    return {
        "level": event.get("level"), "verb": event.get("verb"),
        "username": event.get("user", {}).get("username"),
        "response_code": event.get("responseStatus", {}).get("code"),
        "request_role_ref": request.get("roleRef"), "request_subjects": request.get("subjects"),
        "response_role_ref": response.get("roleRef"), "response_subjects": response.get("subjects"),
    }


def run(lab):
    root = lab.kubeconfig.parent
    red_path = root / "audit-red" / "audit.jsonl"
    red = run_operations(lab, lab.kubeconfig, red_path, "red")
    def poll_records(records):
        return [(line, event) for line, event in records
                if parse_qs(urlsplit(event.get("requestURI", "")).query).get("labelSelector")]
    red_low = poll_records(red)
    red_complete = [(line, event) for line, event in red
                    if event.get("stage") == "ResponseComplete"]
    red_high = next((event for _line, event in red if has_marker(event, HIGH_MARKER)
                     and event.get("stage") == "ResponseComplete"), None)
    red_denied = next((event for _line, event in red if has_marker(event, DENIED_MARKER)
                       and event.get("stage") == "ResponseComplete"), None)
    red_ok = (len(red_complete) == LOW_OPS + 2 and len(red) == 2 * (LOW_OPS + 2)
              and len(red_low) == 2 * LOW_OPS
              and all(event.get("level") == "RequestResponse" for _line, event in red)
              and red_high is not None and "requestObject" in red_high
              and "responseObject" in red_high)
    lab.check("red", "Broad baseline records all seven operations at RequestResponse",
              red_ok, {"selected_audit_events": len(red),
                       "response_complete_operations": len(red_complete),
                       "poll_audit_events": len(red_low),
                       "request_received_events": sum(event.get("stage") == "RequestReceived"
                                                      for _line, event in red),
                       "levels": sorted({event.get("level") for _line, event in red}),
                       "high_fidelity_binding": bool(red_high and "requestObject" in red_high
                                                       and "responseObject" in red_high)})

    green_name = f"{lab.cluster}-green"
    green_kubeconfig = root / "green.kubeconfig"
    green_dir = root / "audit-green"
    green_dir.mkdir()
    green_policy = root / "audit-policy-green.yaml"
    green_policy.write_text(policy_text("green"))
    green_config = root / "kind-audit-green.yaml"
    green_config.write_text(kind_config(green_policy, green_dir))
    try:
        lab.command("kind", "create", "cluster", "--name", green_name, "--image", NODE_IMAGE,
                    "--kubeconfig", str(green_kubeconfig), "--wait", "90s",
                    "--config", str(green_config), timeout=480)
        kube = ("kubectl", "--kubeconfig", str(green_kubeconfig), "--context", f"kind-{green_name}")
        green_version = json.loads(lab.command(*kube, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
        if green_version != "v1.36.1":
            lab.block(f"Expected Kubernetes v1.36.1 for selective audit, got {green_version}")
        lab.command(*kube, "create", "namespace", NAMESPACE)
        lab.command(*kube, "-n", "kube-system", "rollout", "status", "deployment/coredns",
                    "--timeout=80s", timeout=90)
        # Use the cluster's real name for every kubectl context after creation.
        original_cluster = lab.cluster
        lab.cluster = green_name
        try:
            green = run_operations(lab, green_kubeconfig, green_dir / "audit.jsonl", "green")
            verify_service_account_audit(lab, green_kubeconfig, green_dir / "audit.jsonl")
        finally:
            lab.cluster = original_cluster

        green_low = poll_records(green)
        green_high = next((event for _line, event in green if has_marker(event, HIGH_MARKER)
                           and event.get("stage") == "ResponseComplete"), None)
        green_denied = next((event for _line, event in green if has_marker(event, DENIED_MARKER)
                             and event.get("stage") == "ResponseComplete"), None)
        green_complete = [(line, event) for line, event in green
                          if event.get("stage") == "ResponseComplete"]
        green_ok = (len(green) == LOW_OPS + 2 and len(green_complete) == LOW_OPS + 2
                    and len(green_low) == LOW_OPS
                    and all(event.get("level") == "Metadata" for _line, event in green_low)
                    and all("requestObject" not in event and "responseObject" not in event
                            for _line, event in green_low)
                    and green_high is not None and green_high.get("level") == "RequestResponse"
                    and "requestObject" in green_high and "responseObject" in green_high
                    and green_denied is not None and green_denied.get("level") == "RequestResponse"
                    and green_denied.get("responseStatus", {}).get("code") == 403)
        lab.check("green", "Selective policy reduces poll payloads and retains both security writes",
                  green_ok, {"selected_audit_events": len(green),
                             "response_complete_operations": len(green_complete),
                             "poll_audit_events": len(green_low),
                             "request_received_events": sum(event.get("stage") == "RequestReceived"
                                                            for _line, event in green),
                             "poll_levels": sorted({event.get("level") for _line, event in green_low}),
                             "high_fidelity_binding": bool(green_high and
                                 green_high.get("level") == "RequestResponse" and
                                 "requestObject" in green_high and "responseObject" in green_high),
                             "denied_status": green_denied.get("responseStatus", {}).get("code")
                             if green_denied else None})
        same_binding = (red_high is not None and green_high is not None and
                        binding_signature(red_high) == binding_signature(green_high))
        same_denial = (red_denied is not None and green_denied is not None and
                       red_denied.get("level") == green_denied.get("level") == "RequestResponse" and
                       red_denied.get("responseStatus", {}).get("code") ==
                       green_denied.get("responseStatus", {}).get("code") == 403)
        lab.check("positive", "Synthetic RBAC details and denied-write decision remain unchanged",
                  same_binding and same_denial,
                  {"rolebinding_signature_equal": same_binding, "denial_equal": same_denial,
                   "rolebinding_signature": binding_signature(green_high) if green_high else None})
        red_bytes = sum(len(line.encode()) + 1 for line, _event in red_low)
        green_bytes = sum(len(line.encode()) + 1 for line, _event in green_low)
        lab.check("green", "The finite inventory probes consume fewer raw audit log bytes",
                  0 < green_bytes < red_bytes, {"selective_bytes_below_baseline": 0 < green_bytes < red_bytes})
        summary = {
            "identical_api_operations_per_cluster": LOW_OPS + 2,
            "poll_operations_per_cluster": LOW_OPS,
            "red_selected_event_count": len(red), "green_selected_event_count": len(green),
            "red_poll_raw_line_bytes": red_bytes, "green_poll_raw_line_bytes": green_bytes,
            "poll_line_byte_reduction_percent": round((1 - green_bytes / red_bytes) * 100, 2)
            if red_bytes else None,
            "security_events": ["RoleBinding create", "forbidden ConfigMap create"],
            "claim_boundary": "finite owned synthetic fixture only; no capacity or loss-rate claim",
        }
        (lab.evidence / "comparison-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    finally:
        lab.command("kind", "delete", "cluster", "--name", green_name,
                    "--kubeconfig", str(green_kubeconfig), timeout=90)
        clusters = lab.command("kind", "get", "clusters").stdout.splitlines()
        if green_name in clusters:
            lab.block("The separate audit comparison cluster was not removed")


    runtime = runpy.run_path(str(Path(__file__).with_name("webhook_audit.py")))
    with TemporaryDirectory(prefix="audit-webhook-", dir=root) as scratch:
        temporary = Path(scratch)
        additional = type(lab)(lab.evidence, lab.context, temporary / "kubeconfig")
        additional.check = lab.check
        config = runtime["prepare_kind"](additional, temporary)
        try:
            additional.command("kind", "create", "cluster", "--name", additional.cluster,
                               "--image", NODE_IMAGE, "--kubeconfig", str(additional.kubeconfig),
                               "--wait", "90s", "--config", str(config), timeout=480)
            additional.kubectl("create", "namespace", NAMESPACE)
            runtime["run"](additional)
        finally:
            additional.command("kind", "delete", "cluster", "--name", additional.cluster,
                               "--kubeconfig", str(additional.kubeconfig), timeout=90)
        remaining = lab.command("kind", "get", "clusters").stdout.splitlines()
        lab.check("positive", "The independent webhook fixture cluster is deleted",
                  additional.cluster not in remaining, {"additional_fixture_cluster_deleted": additional.cluster not in remaining})


SCOPE += " A separate Kind v1.36.1 cluster verifies TLS webhook delivery, one transient retry and native audit counters."
