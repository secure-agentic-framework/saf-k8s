"""Correlate owned Kubernetes audit events with controlled synthetic provider rows."""

from datetime import datetime
import json
import time

SCOPE = "Actual Kubernetes metadata audit events and synthetic cloud rows and identity links."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
MARKER = "correlation-marker"
ACTOR = "system:serviceaccount:saf-test:correlation-writer"
LOG = "/var/log/kubernetes/saf-correlation-audit.log"


def prepare_kind(_lab, temporary):
    policy = temporary / "correlation-policy.json"
    policy.write_text(json.dumps({"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "Metadata", "verbs": ["patch"], "namespaces": ["saf-test"],
                   "resources": [{"group": "", "resources": ["configmaps"], "resourceNames": [MARKER]}]}, {"level": "None"}]}))
    config = temporary / "kind-correlation.yaml"
    config.write_text(f'''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-correlation-policy.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-correlation-policy.json
        - name: audit-log-path
          value: {LOG}
      extraVolumes:
        - name: saf-fixture-policy
          hostPath: /etc/kubernetes/saf-correlation-policy.json
          mountPath: /etc/kubernetes/saf-correlation-policy.json
          readOnly: true
          pathType: File
        - name: saf-fixture-audit
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
''')
    return config


def grant(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "correlation-writer"},
                "automountServiceAccountToken": False})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "correlation-writer"},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [MARKER], "verbs": ["get", "patch"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "correlation-writer"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "correlation-writer"},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": "correlation-writer"}]})


def observed_rows(lab):
    raw = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat", LOG, allow_failure=True)
    if raw.returncode:
        return []
    rows = []
    for line in raw.stdout.splitlines():
        entry = json.loads(line)
        ref = entry.get("objectRef", {})
        if (entry.get("stage") == "ResponseComplete" and entry.get("verb") == "patch" and ref.get("name") == MARKER
                and ref.get("namespace") == "saf-test" and entry.get("responseStatus", {}).get("code") == 200
                and entry.get("impersonatedUser", {}).get("username") == ACTOR):
            rows.append({"audit_id": entry["auditID"], "principal": ACTOR, "scope": f"saf-test/configmaps/{MARKER}",
                         "time": entry["stageTimestamp"], "audit_level": entry.get("level"),
                         "body_omitted": "requestObject" not in entry and "responseObject" not in entry})
    return rows


def seconds(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def correlate(record, candidates, principals):
    mapped = principals.get(record["principal"])
    pool = [row for row in candidates if row["principal"] == mapped and row["scope"] == record["scope"]
            and abs(seconds(row["time"]) - seconds(record["time"])) <= 30]
    if "audit_reference" in record:
        pool = [row for row in pool if row["audit_id"] == record["audit_reference"]]
    if len(pool) == 1:
        return {"status": "matched", "audit_id": pool[0]["audit_id"]}
    return {"status": "ambiguous" if pool else "unmatched", "candidate_count": len(pool)}


def run(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": MARKER}, "data": {"marker": "initial"}})
    grant(lab)
    for marker in ("first-public-audit-marker", "second-public-audit-marker"):
        lab.kubectl("--as", ACTOR, "patch", "configmap", MARKER, "--type=merge", "-p", json.dumps({"data": {"marker": marker}}))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        observed = observed_rows(lab)
        if len(observed) >= 2:
            break
        time.sleep(1)
    else:
        lab.block("Two exact metadata audit events were not observed")
    distinct = len(observed) == 2 and len({row["audit_id"] for row in observed}) == 2
    scoped = all(row["audit_level"] == "Metadata" and row["body_omitted"] for row in observed)
    first = observed[0]
    rows = {"link": {"principal": "fixture-cloud-actor", "scope": first["scope"], "time": first["time"],
                     "audit_reference": first["audit_id"]},
            "multiple": {"principal": "fixture-cloud-actor", "scope": first["scope"], "time": first["time"]},
            "outside": {"principal": "fixture-unmapped-actor", "scope": first["scope"], "time": first["time"]}}
    naive = sum(abs(seconds(row["time"]) - seconds(rows["outside"]["time"])) <= 30 for row in observed)
    lab.check("red", "A timestamp-only join offers matches even for an unmapped synthetic principal",
              distinct and naive == 2, {"different_audit_ids": distinct, "time_only_false_candidates": naive})
    outcomes = {name: correlate(value, observed, {"fixture-cloud-actor": ACTOR}) for name, value in rows.items()}
    labels = {name: result["status"] for name, result in outcomes.items()}
    lab.check("green", "Explicit correlation keeps a many-candidate time window and an unmapped event unresolved",
              labels == {"link": "matched", "multiple": "ambiguous", "outside": "unmatched"}, {"dispositions": labels})
    exact = outcomes["link"].get("audit_id") == first["audit_id"]
    lab.check("positive", "The explicit fixture reference selects the exact metadata-only audit event",
              exact and scoped, {"exact_event_matched": exact, "metadata_only": scoped})
    (lab.evidence / "correlation-observations.json").write_text(json.dumps({
        "cloud_rows_are_synthetic": True, "kubernetes_events": observed, "results": outcomes,
        "bounded_candidate_window_seconds": 30,
    }, indent=2) + "\n")
