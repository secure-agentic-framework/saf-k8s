"""Observe native impersonation audit attribution and scoped alert delivery."""
import json
from pathlib import Path
import subprocess
import time

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
AUDIT = "/etc/kubernetes/saf-impersonation-audit"
DIRECTORY = "fixture-impersonation-audit"
CONFIG = "fixture-audit-public-data"
QUEUE = "fixture-impersonation-alerts"
MARKER = "owned-public-audit-marker"
APPROVED = "fixture-audited-reviewer"
REVIEWED = "fixture-audited-secondary"
DELEGATE = "fixture-audit-readonly"
CALLERS = (APPROVED, REVIEWED)
SCOPE = (
    "Real metadata-only API audit records identify the authenticated and impersonated principals "
    "for successful reads of a case-owned public ConfigMap. An independent fixture allowlist "
    "classifies the authorized caller pairs and persists one unexpected-use alert. The test "
    "covers a disposable cluster and fixture queue; retention, incident response and deployed "
    "audit pipelines require separate evidence."
)


def prepare_kind(lab, temporary):
    destination = temporary / DIRECTORY
    destination.mkdir()
    policy = {"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
              "rules": [{"level": "Metadata", "namespaces": [NS], "verbs": ["get"],
                         "resources": [{"group": "", "resources": ["configmaps"],
                                       "resourceNames": [CONFIG]}]},
                        {"level": "None"}]}
    (destination / "policy.json").write_text(json.dumps(policy))
    profile = temporary / "fixture-audit-kind.yaml"
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
    - name: saf-fixture-impersonation-audit
      hostPath: {AUDIT}
      mountPath: {AUDIT}
      pathType: Directory
""")
    return profile


def put(lab, kind, name, api="v1", **fields):
    lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def rule(resource, verb, name):
    return {"apiGroups": [""], "resources": [resource], "verbs": [verb], "resourceNames": [name]}


def ref(kind, name):
    return {"apiGroup": "rbac.authorization.k8s.io", "kind": kind, "name": name}


def authenticate(lab, caller):
    token_cmd = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", NS, "create", "token", caller, "--duration=10m",
    ]
    issued = subprocess.run(token_cmd, env=lab.env, capture_output=True, text=True, timeout=20)
    if issued.returncode or len(issued.stdout.strip().split(".")) != 3:
        lab.block("Could not issue the temporary caller identity")
    parent = lab.kubeconfig.parent
    token = parent / f"{caller}.token"
    token.touch(mode=0o600, exist_ok=False)
    token.write_text(issued.stdout.strip())
    config = parent / f"{caller}.json"
    config.touch(mode=0o600, exist_ok=False)
    fields = ("server", "certificate-authority-data")
    cluster = {
        field: lab.kubectl("config", "view", "--minify", "--raw", "-o",
                           "jsonpath={.clusters[0].cluster." + field + "}").stdout.strip()
        for field in fields
    }
    config.write_text(json.dumps({
        "apiVersion": "v1", "kind": "Config", "current-context": "fixture",
        "clusters": [{"name": "fixture", "cluster": cluster}],
        "users": [{"name": caller, "user": {"tokenFile": str(token)}}],
        "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": caller}}],
    }))
    return config


def request(lab, config):
    result = lab.command("kubectl", "--kubeconfig", str(config), "--context", "fixture",
                         "--request-timeout=7s", "--as=" + DELEGATE, "get",
                         f"--raw=/api/v1/namespaces/{NS}/configmaps/{CONFIG}", timeout=12)
    return json.loads(result.stdout)["data"]["marker"]


def identity(caller):
    return f"system:serviceaccount:{NS}:{caller}"


def records(lab):
    path = lab.kubeconfig.parent / DIRECTORY / "events.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def observed_event(event):
    reference = event.get("objectRef") or {}
    origin = event.get("user") or {}
    acted_as = event.get("impersonatedUser") or {}
    if (event.get("stage"), event.get("verb"), reference.get("namespace"),
            reference.get("resource"), reference.get("name")) != (
                "ResponseComplete", "get", NS, "configmaps", CONFIG):
        return None
    if (event.get("responseStatus") or {}).get("code") != 200:
        return None
    if not event.get("auditID") or not origin.get("username") or not acted_as.get("username"):
        return None
    return origin["username"], acted_as["username"]


def classify(events):
    allowlist = {(identity(APPROVED), DELEGATE)}
    pairs = {observed_event(event) for event in events} - {None}
    expected = sorted(pairs & allowlist)
    alerts = [{"from": origin, "as": delegate, "reason": "outside-approved-pair"}
              for origin, delegate in sorted(pairs - allowlist)]
    return expected, alerts


def queue(lab):
    raw = lab.kubectl("get", "configmap", QUEUE, "-o", "jsonpath={.data.alerts}").stdout
    return json.loads(raw)


def run(lab):
    for caller in CALLERS:
        put(lab, "ServiceAccount", caller, automountServiceAccountToken=False)
    put(lab, "ConfigMap", CONFIG, data={"marker": MARKER})
    put(lab, "ConfigMap", QUEUE, data={"alerts": "[]"})
    put(lab, "Role", CONFIG, RBAC, rules=[rule("configmaps", "get", CONFIG)])
    put(lab, "RoleBinding", CONFIG, RBAC, roleRef=ref("Role", CONFIG),
        subjects=[{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": DELEGATE}])
    put(lab, "ClusterRole", CONFIG, RBAC, rules=[rule("users", "impersonate", DELEGATE)])
    put(lab, "ClusterRoleBinding", CONFIG, RBAC, roleRef=ref("ClusterRole", CONFIG),
        subjects=[{"kind": "ServiceAccount", "name": caller, "namespace": NS} for caller in CALLERS])

    credentials = {caller: authenticate(lab, caller) for caller in CALLERS}
    reads = {caller: request(lab, credentials[caller]) == MARKER for caller in CALLERS}
    raw = []
    for _ in range(10):
        raw = records(lab)
        if sum(observed_event(event) is not None for event in raw) >= len(CALLERS):
            break
        time.sleep(.25)
    pairs = {(identity(caller), DELEGATE) for caller in CALLERS}
    events = [event for event in raw if observed_event(event) in pairs]
    baseline = {"separate_reads_reached_resource": all(reads.values()),
                "selected_events_emitted": {observed_event(event) for event in events} == pairs,
                "audit_without_detector_leaves_queue_empty": queue(lab) == []}
    lab.check("red", "Real audit records do not themselves deliver a policy alert",
              all(baseline.values()), baseline)

    approved, alerts = classify(events)
    patch = json.dumps({"data": {"alerts": json.dumps(alerts)}})
    lab.kubectl("patch", "configmap", QUEUE, "--type=merge", "-p", patch, "-o", "name")
    result = {"two_distinct_audit_requests": len({event["auditID"] for event in events}) == len(CALLERS),
              "record_both_principals_and_object": baseline["selected_events_emitted"],
              "metadata_without_object_bodies": all(
                  event.get("level") == "Metadata" and "requestObject" not in event and "responseObject" not in event
                  for event in events),
              "approved_pair_separate": approved == [(identity(APPROVED), DELEGATE)],
              "unexpected_attributed_pair_reaches_queue": queue(lab) == [
                  {"from": identity(REVIEWED), "as": DELEGATE, "reason": "outside-approved-pair"}]}
    lab.check("green", "Observe exact attribution and route the unexpected pair without payload capture",
              all(result.values()), result)

    marker = request(lab, credentials[APPROVED])
    repeated = [event for event in records(lab) if observed_event(event) in pairs]
    final = {"existing_approved_use_still_works": marker == MARKER,
             "another_approved_audit_event_was_emitted": len(repeated) == len(CALLERS) + 1,
             "same_unexpected_pair_only": classify(repeated) == (approved, alerts) and queue(lab) == alerts}
    lab.check("positive", "Repeated approved use stays observable and generates no additional alert",
              all(final.values()), final)
    (lab.evidence / "impersonation-audit-observations.json").write_text(json.dumps({
        "baseline": baseline, "audit_and_alert": result, "positive": final,
        "observed_principal_pairs": sorted(pairs), "delivered_alerts": alerts,
    }, indent=2) + "\n")
