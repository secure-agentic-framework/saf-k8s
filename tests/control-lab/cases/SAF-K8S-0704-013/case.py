"""Verify collection and local receipt separately from an enabled audit producer."""

import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from delivery_supplement import run_supplement

SCOPE = ("Actual metadata-only Kubernetes API audit producer forwarded by a case-owned in-cluster source reader "
         "over fixture mTLS to an independent local receiver, plus one clearly synthetic provider fixture record. "
         "Managed provider configuration, external delivery security, coverage and retention remain adopter evidence.")
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
MARKER = "audit-receipt-marker"
LOG = "/var/log/kubernetes/saf-receipt-audit.log"


def prepare_kind(_lab, temporary):
    policy = temporary / "receipt-policy.json"
    policy.write_text(json.dumps({"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "Metadata", "verbs": ["patch"], "namespaces": ["saf-test"],
                   "resources": [{"group": "", "resources": ["configmaps"], "resourceNames": [MARKER]}]}, {"level": "None"}]}))
    config = temporary / "kind-receipt.yaml"
    config.write_text(f'''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-receipt-policy.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-receipt-policy.json
        - name: audit-log-path
          value: {LOG}
      extraVolumes:
        - name: saf-fixture-policy
          hostPath: /etc/kubernetes/saf-receipt-policy.json
          mountPath: /etc/kubernetes/saf-receipt-policy.json
          readOnly: true
          pathType: File
        - name: saf-fixture-audit
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
''')
    return config

def read_audit(lab):
    result = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat", LOG, allow_failure=True)
    if result.returncode:
        return []
    events = [json.loads(line) for line in result.stdout.splitlines()]
    return [event for event in events if event.get("stage") == "ResponseComplete"
            and event.get("verb") == "patch"
            and event.get("level") == "Metadata"
            and event.get("objectRef", {}).get("name") == MARKER
            and event.get("objectRef", {}).get("namespace") == "saf-test"
            and event.get("responseStatus", {}).get("code") == 200
            and "requestObject" not in event and "responseObject" not in event]


def collect(streams, enrolled, destination):
    rows = []
    for producer, records in streams.items():
        if producer not in enrolled:
            continue
        for record in records:
            rows.append({"source": producer, **record})
    destination.write_text("".join(json.dumps(row) + "\n" for row in rows))


def received(destination):
    return [json.loads(line) for line in destination.read_text().splitlines()]


def run(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": MARKER}, "data": {"marker": "starting"}})
    lab.kubectl("patch", "configmap", MARKER, "--type=merge", "-p", '{"data":{"marker":"public-receipt-marker"}}')
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        events = read_audit(lab)
        if events:
            break
        time.sleep(1)
    else:
        lab.block("The scoped audit backend did not provide a successful, metadata-only fixture event")
    if len(events) != 1:
        lab.block("Expected exactly one scoped API audit event")
    event = events[0]
    kubernetes_record = {"receipt_id": event["auditID"], "event_time": event["stageTimestamp"],
                         "cluster": lab.cluster, "category": "apiserver-metadata", "synthetic": False}
    provider_record = {"receipt_id": "synthetic-provider-marker", "event_time": event["stageTimestamp"],
                       "cluster": "synthetic-provider-cluster", "category": "synthetic-provider-audit", "synthetic": True}
    streams = {"kubernetes-apiserver": [kubernetes_record], "provider-fixture": [provider_record]}
    destination = lab.evidence / "audit-receipts.jsonl"

    collect(streams, {"provider-fixture"}, destination)
    initial = received(destination)
    lab.check("red", "The API producer has a valid event but the enrolled provider route alone does not deliver it",
              bool(event["auditID"]) and initial == [{"source": "provider-fixture", **provider_record}],
              {"actual_producer_events": len(events), "kubernetes_receipts_before_enrollment": 0})

    collect(streams, {"provider-fixture", "kubernetes-apiserver"}, destination)
    actual = received(destination)
    fields = {row["source"]: row for row in actual}
    authoritative = fields.get("kubernetes-apiserver") == {"source": "kubernetes-apiserver", **kubernetes_record}
    lab.check("green", "The enrolled local collector writes a receipt for the exact observed API event",
              authoritative, {"exact_kubernetes_receipt": authoritative, "collector_is_local": True})

    fixture_distinct = fields.get("provider-fixture") == {"source": "provider-fixture", **provider_record}
    lab.check("positive", "The same local sink keeps source identities distinct and the provider record labeled synthetic",
              len(actual) == 2 and fixture_distinct, {"receipts": len(actual), "provider_input_is_synthetic": fixture_distinct})
    summary = {"producer_events": len(events), "pre_enrollment_sources": [row["source"] for row in initial],
               "receipt_sources": [row["source"] for row in actual], "exact_kubernetes_receipt": authoritative,
               "provider_input_is_synthetic": fixture_distinct, "receipt_file": destination.name}
    (lab.evidence / "audit-delivery-observations.json").write_text(json.dumps(summary, indent=2) + "\n")
    run_supplement(lab, event, read_audit)
