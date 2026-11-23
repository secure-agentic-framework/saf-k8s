"""Observe attributable emergency API requests and an independent review record."""
import importlib.util
import json
from pathlib import Path
import time

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
AUDIT = "/etc/kubernetes/saf-emergency-audit"
DIRECTORY = "fixture-emergency-audit"
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
CALLER = "fixture-emergency-operator"
REVIEWER = "fixture-review-owner"
ALLOWED = "fixture-covered-record"
DENIED = "fixture-covered-unrelated"
GAP = "fixture-outside-audit-rule"
QUEUE = "fixture-emergency-review-record"
SCOPE = (
    "The actual Kubernetes API records the authenticated fixture service account, resource, verb, "
    "status and audit ID for a selected permitted and denied emergency request. A real request "
    "outside the policy is absent. A separate authorized reviewer reads the sanitized correlation "
    "record. This proves the tested API path and selected policy rules."
)


def prepare_kind(lab, temporary):
    destination = temporary / DIRECTORY
    destination.mkdir()
    policy = {"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
              "rules": [{"level": "Metadata", "namespaces": [NS], "verbs": ["get"],
                         "resources": [{"group": "", "resources": ["configmaps"],
                                       "resourceNames": [ALLOWED, DENIED]}]},
                        {"level": "None"}]}
    (destination / "policy.json").write_text(json.dumps(policy))
    profile = temporary / "fixture-emergency-audit-kind.yaml"
    profile.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(destination))}
    containerPath: {AUDIT}
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: audit-policy-file
      value: {AUDIT}/policy.json
    - name: audit-log-path
      value: {AUDIT}/events.jsonl
    - name: audit-log-mode
      value: blocking
    extraVolumes:
    - name: saf-fixture-emergency-audit
      hostPath: {AUDIT}
      mountPath: {AUDIT}
      pathType: Directory
""")
    return profile


def recovery_fixture():
    path = Path(__file__).resolve().parents[1] / "SAF-K8S-0405-020" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_fixture_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def grant(lab, fixture, actor, resources):
    group = "rbac.authorization.k8s.io"
    fixture.put(lab, "Role", actor, RBAC,
                rules=[{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"],
                        "resourceNames": resources}])
    fixture.put(lab, "RoleBinding", actor, RBAC, roleRef={"apiGroup": group, "kind": "Role", "name": actor},
                subjects=[{"kind": "ServiceAccount", "name": actor, "namespace": NS}])


def observe(lab, profile, name):
    return lab.command("kubectl", "--kubeconfig", str(profile), "--context", "fixture",
                       "--request-timeout=6s", "get",
                       f"--raw=/api/v1/namespaces/{NS}/configmaps/{name}",
                       allow_failure=True, timeout=12)


def selected_events(lab):
    log = lab.kubeconfig.parent / DIRECTORY / "events.jsonl"
    if not log.exists():
        return []
    events = []
    expected = f"system:serviceaccount:{NS}:{CALLER}"
    for row in log.read_text().splitlines():
        event = json.loads(row)
        if event.get("user", {}).get("username") == expected and event.get("stage") == "ResponseComplete":
            events.append(event)
    return events


def run(lab):
    fixture = recovery_fixture()
    for actor in (CALLER, REVIEWER):
        fixture.put(lab, "ServiceAccount", actor, automountServiceAccountToken=False)
    for record in (ALLOWED, DENIED, GAP):
        fixture.put(lab, "ConfigMap", record, data={"marker": "owned-fixture-only"})
    grant(lab, fixture, CALLER, [ALLOWED, GAP])
    grant(lab, fixture, REVIEWER, [QUEUE])
    caller = fixture.identity(lab, CALLER, "audit-emergency")
    reviewer = fixture.identity(lab, REVIEWER, "audit-review")

    outside = observe(lab, caller, GAP)
    baseline = {"real_request_outside_policy_succeeded": outside.returncode == 0,
                "no_selected_events_for_excluded_request": not selected_events(lab)}
    lab.check("red", "A successful real call can be missing from metadata when outside policy coverage",
              all(baseline.values()), baseline)

    accepted = observe(lab, caller, ALLOWED)
    rejected = observe(lab, caller, DENIED)
    for _ in range(8):
        events = selected_events(lab)
        if len(events) >= 2:
            break
        time.sleep(.25)
    records = sorted(
        [{"resource": e.get("objectRef", {}).get("name", ""),
          "status": e.get("responseStatus", {}).get("code"),
          "principal": e.get("user", {}).get("username"), "verb": e.get("verb")} for e in events],
        key=lambda row: row["resource"],
    )
    statuses = {row["resource"]: row["status"] for row in records}
    evidence = {"actual_allow_and_forbidden": accepted.returncode == 0 and "(Forbidden)" in rejected.stderr,
                "matching_named_resource_and_status": statuses == {ALLOWED: 200, DENIED: 403},
                "operations_have_distinct_attribution_ids": len({e.get("auditID") for e in events}) == 2
                and all(e.get("auditID") and e.get("verb") == "get" for e in events),
                "metadata_did_not_retain_bodies": all(e.get("level") == "Metadata"
                    and "requestObject" not in e and "responseObject" not in e for e in events)}
    lab.check("green", "The API records attributable allow and deny events under the effective rule",
              all(evidence.values()), evidence)

    fixture.put(lab, "ConfigMap", QUEUE, data={"findings": json.dumps(records)})
    visible = observe(lab, reviewer, QUEUE)
    hidden = observe(lab, caller, QUEUE)
    positive = {"separate_reviewer_reads_attributed_decisions": visible.returncode == 0
                and json.loads(json.loads(visible.stdout)["data"]["findings"]) == records,
                "operator_cannot_read_review_record": "(Forbidden)" in hidden.stderr,
                "uncovered_request_remains_absent": GAP not in statuses}
    lab.check("positive", "The independent reviewer can inspect only the sanitized correlated result",
              all(positive.values()), positive)
    (lab.evidence / "emergency-audit-observations.json").write_text(json.dumps({
        "baseline": baseline, "native_audit": evidence, "review": positive, "events": records,
    }, indent=2) + "\n")
