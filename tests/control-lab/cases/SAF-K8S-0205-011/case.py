"""Reconcile a live case-owned kernel rule table to an immutable approved baseline."""

from datetime import datetime, timezone
from hashlib import sha256
import json
import time

SCOPE = "A detached Kind nftables baseline with periodic collection, immutable approval and independent Kubernetes audit events."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
TABLE = "saf_fixture_011"
LOG = "/var/log/kubernetes/saf-change-audit.ndjson"
NAMESPACE = "saf-test"
REVIEWER = "fixture-firewall-reviewer"
COLLECTOR = "fixture-firewall-reader"
INITIAL = "fixture-firewall-v1"
UPDATED = "fixture-firewall-v2"
INTERVAL = 1
RBAC = "rbac.authorization.k8s.io"
CHAIN = "fixture_unhooked"
PREVIEW = "saf_preview_011"
VALUES = {"approved-initial": 18084, "observed-unapproved": 18085, "approved-change": 18086}


def prepare_kind(_lab, temporary):
    policy = temporary / "saf-change-audit.json"
    policy.write_text(json.dumps({
        "apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "Metadata", "verbs": ["get", "create", "patch"], "namespaces": [NAMESPACE],
                   "resources": [{"group": "", "resources": ["configmaps"]}]}, {"level": "None"}],
    }))
    config = temporary / "kind-change-audit.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-change-audit.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-change-audit.json
        - name: audit-log-path
          value: {LOG}
      extraVolumes:
        - name: saf-change-audit-policy
          hostPath: /etc/kubernetes/saf-change-audit.json
          mountPath: /etc/kubernetes/saf-change-audit.json
          readOnly: true
          pathType: File
        - name: saf-change-audit-log
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
""")
    return config



def command(lab, node, *argv, **kwargs):
    return lab.command("docker", "exec", "-i", node, "nft", *argv, **kwargs)


def program(revision, previous_exists, table=TABLE, packets=0):
    port = VALUES[revision]
    remove = f"delete table ip {table}\n" if previous_exists else ""
    return remove + f"""table ip {table} {{
    chain {CHAIN} {{
        tcp dport {port} counter packets {packets} bytes {packets * 64} comment "owned-fixture-rule"
    }}
}}
"""


def snapshot(lab, node, name=TABLE):
    result = command(lab, node, "-j", "list", "table", "ip", name, allow_failure=True)
    timestamp = datetime.now(timezone.utc).isoformat()
    if result.returncode:
        return {"at": timestamp, "status": "unavailable", "detail": result.stderr.strip()}
    items = json.loads(result.stdout)["nftables"]
    canonical = []
    for row in items:
        if "metainfo" in row:
            continue
        (kind, obj), = row.items()
        properties = {key: value for key, value in obj.items() if key != "handle"}
        if kind == "table":
            properties["name"] = TABLE if obj["name"] == name else obj["name"]
        if properties.get("table") == name:
            properties["table"] = TABLE
        if kind == "rule":
            properties["expr"] = [{**expr, "counter": {}} if "counter" in expr else expr
                                  for expr in properties["expr"]]
        canonical.append({kind: properties})
    chain, = (item["chain"] for item in canonical if "chain" in item)
    if "hook" in chain or chain["name"] != CHAIN:
        lab.block("The governance fixture may only use a detached chain")
    data = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return {"at": timestamp, "status": "observed", "sha256": sha256(data).hexdigest(),
            "raw": items, "normalized": canonical}


def grant(lab, user, verbs):
    lab.create({"apiVersion": RBAC + "/v1", "kind": "Role", "metadata": {"name": user},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": verbs}]})
    lab.create({"apiVersion": RBAC + "/v1", "kind": "RoleBinding", "metadata": {"name": user},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": user},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": user}]})


def approve(lab, name, observed, change, *, actor=REVIEWER):
    records = {"ruleset_sha256": observed["sha256"], "approval_id": name, "scope": "owned detached table",
               "observed_at": observed["at"], "change": change, "reviewer": REVIEWER, "observer": COLLECTOR}
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
           "immutable": True, "data": records}
    return lab.kubectl(f"--as={actor}", "create", "-f", "-", "-o", "json",
                       payload=json.dumps(obj), allow_failure=True)


def read_approval(lab, name):
    return json.loads(lab.kubectl(f"--as={COLLECTOR}", "get", "configmap", name, "-o", "json").stdout)


def audit(lab, node):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        events = {}
        raw = lab.command("docker", "exec", node, "cat", LOG).stdout
        for row in raw.splitlines():
            event = json.loads(row)
            ref = event.get("objectRef") or {}
            actor = (event.get("impersonatedUser") or {}).get("username")
            if event["stage"] != "ResponseComplete" or ref.get("namespace") != NAMESPACE or ref.get("resource") != "configmaps":
                continue
            code = event["responseStatus"]["code"]
            verb = event["verb"]
            key = None
            if actor == REVIEWER and verb == "create" and code == 201 and ref.get("name") in (INITIAL, UPDATED):
                key = "approved-" + ref["name"]
            if actor == COLLECTOR and verb == "get" and code == 200 and ref.get("name") == UPDATED:
                key = "observer-read"
            if actor == COLLECTOR and verb == "create" and code == 403:
                key = "observer-create-denied"
            if key:
                events[key] = {"event_id": event["auditID"], "actor": actor, "verb": verb, "code": code,
                               "name": ref.get("name"), "at": event["stageTimestamp"]}
        if len(events) == 4:
            return events
        time.sleep(0.4)
    lab.block("Expected independent approval and observer audit events are unavailable")


def matches(current, approved):
    return current.get("sha256") == approved["data"]["ruleset_sha256"] and approved["immutable"]


def run(lab):
    node = lab.cluster + "-control-plane"
    if lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines() != [node]:
        lab.block("The audit fixture requires one known disposable Kind node")
    grant(lab, REVIEWER, ["create", "get", "patch"])
    grant(lab, COLLECTOR, ["get"])
    command(lab, node, "-f", "-", payload=program("approved-initial", False))
    try:
        initial = snapshot(lab, node)
        initial_write = approve(lab, INITIAL, initial, "initial baseline")
        if initial_write.returncode:
            lab.block("The approved writer could not create the initial record")
        baseline = read_approval(lab, INITIAL)
        version = lab.command("docker", "exec", node, "nft", "--version").stdout.strip()
        command(lab, node, "-f", "-", payload=program("approved-initial", True, packets=11))
        time.sleep(INTERVAL)
        counter_sample = snapshot(lab, node)
        ignore_counters = (initial["raw"] != counter_sample["raw"] and matches(initial, baseline)
                           and matches(counter_sample, baseline))
        lab.check("positive", "A fresh read keeps the same baseline for an actual counter-only update",
                  ignore_counters, {"raw_changed_and_normalized_matched": ignore_counters})

        command(lab, node, "-f", "-", payload=program("observed-unapproved", True))
        periodic = []
        for _ in range(2):
            time.sleep(INTERVAL)
            periodic.append(snapshot(lab, node))
        drift = periodic[-1]
        stamps = [datetime.fromisoformat(row["at"]) for row in periodic]
        interval = (stamps[1] - stamps[0]).total_seconds()
        detected = (periodic[0]["sha256"] == drift["sha256"]
                    and all(not matches(item, baseline) for item in periodic) and interval >= INTERVAL)
        lab.check("red", "Two timed reads detect the same effective port drift while the comment stays constant",
                  detected, {"independent_drift_samples_match": detected, "cadence_observed": interval >= INTERVAL})

        refused = approve(lab, UPDATED, drift, "unapproved baseline", actor=COLLECTOR)
        denied = refused.returncode != 0 and "cannot create resource" in refused.stderr
        patch = json.dumps({"data": {"ruleset_sha256": drift["sha256"]}})
        rewrite = lab.kubectl(f"--as={REVIEWER}", "patch", "configmap", INITIAL, "--type=merge", "-p", patch,
                             allow_failure=True)
        stable = rewrite.returncode != 0 and "immutable" in rewrite.stderr.lower() and read_approval(lab, INITIAL) == baseline
        lab.check("green", "A read-only observer cannot approve and the approved writer cannot overwrite the baseline",
                  denied and stable, {"observer_create_denied": denied, "baseline_protected": stable})

        approved_change = program("approved-change", True)
        command(lab, node, "-c", "-f", "-", payload=approved_change)
        after_check = snapshot(lab, node)
        command(lab, node, "-f", "-", payload=program("approved-change", False, PREVIEW))
        try:
            preview = snapshot(lab, node, PREVIEW)
        finally:
            command(lab, node, "delete", "table", "ip", PREVIEW)
        accepted = approve(lab, UPDATED, preview, "replace the approved TCP selector")
        if accepted.returncode:
            lab.block("The approved writer could not create the preview record")
        approved = read_approval(lab, UPDATED)
        since_preview = snapshot(lab, node)
        untouched = after_check["sha256"] == since_preview["sha256"] == drift["sha256"]
        lab.check("green", "Syntax check and detached preview leave live state unchanged until approved apply",
                  untouched, {"check_and_preview_did_not_apply": untouched})
        command(lab, node, "-f", "-", payload=approved_change)
        applied = snapshot(lab, node)
        command(lab, node, "-f", "-", payload=program("approved-initial", True))
        rollback = snapshot(lab, node)
        recovered = matches(applied, approved) and not matches(applied, baseline) and matches(rollback, baseline)
        lab.check("positive", "Observed change and rollback match their respective immutable approvals",
                  recovered, {"new_approval_matched": matches(applied, approved), "rollback_matches_initial": matches(rollback, baseline)})

        events = audit(lab, node)
        dated = (datetime.fromisoformat(events["approved-" + UPDATED]["at"].replace("Z", "+00:00"))
                 <= datetime.fromisoformat(applied["at"]))
        roles = all(event["actor"] == REVIEWER for key, event in events.items() if key.startswith("approved-"))
        lab.check("positive", "Separate API audit records attribute both approvals and the denied observer request",
                  dated and roles and len({event["event_id"] for event in events.values()}) == 4,
                  {"attributed_records": True, "approval_preceded_apply": dated})
        result = {"scope": "live detached table, no packet hook", "nft_version": version, "cadence_seconds": INTERVAL,
                  "baseline": baseline["data"], "approved_change": approved["data"], "observations": {
                      "initial": initial, "counter_changed": counter_sample, "drift_collections": periodic,
                      "post_syntax_check": after_check, "preview": preview, "pre_apply": since_preview,
                      "applied": applied, "roll_back": rollback}, "audit_events": events}
        (lab.evidence / "firewall-governance-observations.json").write_text(json.dumps(result, indent=2) + "\n")
    finally:
        command(lab, node, "delete", "table", "ip", TABLE)
