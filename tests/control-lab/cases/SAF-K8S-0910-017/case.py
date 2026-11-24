"""Collect live Kubernetes audit events from two owned Kind sources."""
from datetime import datetime, timedelta
import importlib.util
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit
from uuid import UUID

HERE = Path(__file__).resolve().parent
SOURCE_POLICY = HERE.parent / "SAF-K8S-1001-004" / "case.py"
NODE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
PLAN = "fixture-cross-cluster-placement"
WRITER = "fixture-orchestration-actor"
COLLECTOR = "fixture-audit-collector"
READER = "fixture-audit-reader"
OUTSIDER = "fixture-audit-unapproved"
RECORDS = "fixture-central-audit-records"
SCOPE = (
    "One isolated collector cluster and two distinct, auditable disposable Kubernetes source clusters. "
    "The sources emit real Metadata-level audit events for a named placement marker update. The case "
    "transfers only allowlisted event fields and verifies the exact central read under scoped RBAC "
    "after both source clusters are removed. It does not set up a continuous production aggregator."
)
POLICY = """apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
  - level: Metadata
    verbs: [patch]
    namespaces: [saf-test]
    resources:
      - group: ""
        resources: [configmaps]
        resourceNames: [fixture-cross-cluster-placement]
  - level: None
"""


def configure(path, audit):
    spec = importlib.util.spec_from_file_location("saf_audit_kind_config", SOURCE_POLICY)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load the reviewed audit Kind configuration helper")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    policy = path / "policy.yaml"
    policy.write_text(POLICY)
    config = path / "kind.yaml"
    config.write_text(helper.kind_config(policy, audit))
    return config, audit / Path(helper.AUDIT_FILE).name


def principal(account):
    return f"system:serviceaccount:{NS}:{account}"


def identity(value):
    return str(UUID(value)) == value


def source_cli(lab, cluster, kubeconfig, *args, payload=None):
    return lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context", "kind-" + cluster,
                       "--namespace", NS, "--request-timeout=12s", *args, payload=payload, timeout=17)


def body(kind, name, api="v1", **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def account_rules(account, rules):
    return (
        body("ServiceAccount", account, automountServiceAccountToken=False),
        body("Role", account, RBAC, rules=rules),
        body("RoleBinding", account, RBAC,
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": account},
             subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}]),
    )


def event_from_log(lab, location, uid, source):
    deadline = time.monotonic() + 12
    while True:
        if location.is_file():
            for line in location.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ref = event.get("objectRef", {})
                if (event.get("stage") == "ResponseComplete" and event.get("verb") == "patch"
                        and ref.get("resource") == "configmaps" and ref.get("namespace") == NS
                        and ref.get("name") == PLAN
                        and event.get("impersonatedUser", {}).get("username") == principal(WRITER)):
                    return {"source": source, "cluster_uid": uid, "audit_id": event["auditID"],
                            "timestamp": event["stageTimestamp"], "verb": event["verb"],
                            "object": ref["name"], "actor": event["impersonatedUser"]["username"],
                            "status": event["responseStatus"]["code"]}
        if time.monotonic() >= deadline:
            lab.block("The source audit backend did not emit the expected placement event")
        time.sleep(0.25)


def collect(lab, stem, names):
    source = lab.cluster + "-src-" + stem
    root = lab.kubeconfig.parent / ("audit-source-" + stem)
    root.mkdir()
    audit = root / "audit"
    audit.mkdir()
    config, record_file = configure(root, audit)
    kubeconfig = root / "kubeconfig"
    names.append((source, kubeconfig))
    lab.command("kind", "create", "cluster", "--name", source, "--image", NODE, "--config", str(config),
                "--kubeconfig", str(kubeconfig), "--wait", "120s", timeout=200)

    def call(*args, **kwargs):
        return source_cli(lab, source, kubeconfig, *args, **kwargs)

    endpoint = json.loads(call("config", "view", "--minify", "-o", "json").stdout)["clusters"][0]["cluster"]["server"]
    owned = lab.command("docker", "port", source + "-control-plane", "6443/tcp", timeout=15).stdout.strip()
    if not re.fullmatch(r"127\.0\.0\.1:\d+", owned) or urlsplit(endpoint).netloc != owned:
        lab.block("The nested Kubernetes context does not identify its expected owned loopback endpoint")
    uid = call("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
    if not identity(uid):
        lab.block("The source API did not provide an independently observed cluster UID")
    call("create", "namespace", NS)
    for resource in (body("ConfigMap", PLAN, data={"action": "pending"}),
                     *account_rules(WRITER, [{"apiGroups": [""], "resources": ["configmaps"],
                                              "verbs": ["get", "patch"], "resourceNames": [PLAN]}])):
        call("create", "-f", "-", payload=json.dumps(resource))
    action = f"fixture-approved-placement-{stem}"
    patched = call("patch", "configmap", PLAN, "--type=merge", "-p",
                   json.dumps({"data": {"action": action}}), f"--as={principal(WRITER)}", "-o", "json")
    if json.loads(patched.stdout)["data"]["action"] != action:
        lab.block("The exact synthetic placement action did not persist in its source API")
    return {**event_from_log(lab, record_file, uid, stem), "placement_action": action}


def cleanup(lab, names):
    while names:
        cluster, kubeconfig = names[-1]
        lab.command("kind", "delete", "cluster", "--name", cluster, "--kubeconfig", str(kubeconfig),
                    timeout=75)
        names.pop()


def run(lab):
    names = []
    try:
        events = [collect(lab, marker, names) for marker in ("a", "b")]
        central_uid = lab.kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
        locations = {row["cluster_uid"] for row in events}
        exact_sources = len(locations) == 2 and identity(central_uid) and central_uid not in locations
        for resource in (*account_rules(COLLECTOR, [{"apiGroups": [""], "resources": ["configmaps"],
                                                    "verbs": ["create"]}]),
                         *account_rules(READER, [{"apiGroups": [""], "resources": ["configmaps"],
                                                 "resourceNames": [RECORDS], "verbs": ["get"]}]),
                         body("ServiceAccount", OUTSIDER, automountServiceAccountToken=False)):
            lab.create(resource)

        def retrieve(actor):
            return lab.kubectl("get", "configmap", RECORDS, "-o", "json",
                               f"--as={principal(actor)}", allow_failure=True)

        unforwarded = retrieve(READER)
        lab.check("red", "Both sources emit audit events while the central reader sees a collection gap",
                  exact_sources and unforwarded.returncode != 0 and "NotFound" in unforwarded.stderr,
                  {"source_events_observed": len(events), "distinct_sources_and_collector": exact_sources,
                   "central_record_not_found": "NotFound" in unforwarded.stderr})
        target = body("ConfigMap", RECORDS, immutable=True, data={"events.json": json.dumps(events, sort_keys=True)})
        lab.kubectl("create", "-f", "-", f"--as={principal(COLLECTOR)}", payload=json.dumps(target))
        result = retrieve(READER)
        receipt = json.loads(result.stdout)
        returned = json.loads(receipt["data"]["events.json"])
        unauthorized = retrieve(OUTSIDER)
        event_ids = {e["audit_id"] for e in returned}
        valid_utc = all(datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).utcoffset()
                        == timedelta(0) for e in returned)
        green = {
            "allowlisted_real_audit_records_roundtrip": returned == events and receipt["immutable"] is True,
            "unique_source_and_event_identity": exact_sources and len(event_ids) == 2
            and all(identity(v) for v in event_ids),
            "actor_action_and_timestamp_verified": valid_utc and all(
                row["actor"] == principal(WRITER) and row["status"] == 200 and row["object"] == PLAN
                and row["placement_action"] == f"fixture-approved-placement-{row['source']}"
                for row in returned),
            "unauthorized_identity_denied_central_read": unauthorized.returncode != 0
            and "Forbidden" in unauthorized.stderr,
        }
        lab.check("green", "The collector preserves real source provenance and enforces reader scope",
                  all(green.values()), green)
        cleanup(lab, names)
        after_sources = retrieve(READER)
        retained = json.loads(json.loads(after_sources.stdout)["data"]["events.json"])
        positive = {"both_source_clusters_removed": not names, "central_copy_matches": retained == events}
        lab.check("positive", "Independent central storage stays readable after both source clusters are removed",
                  all(positive.values()), positive)
        (lab.evidence / "cross-cluster-audit.json").write_text(json.dumps({
            "central_api_uid": central_uid, "retained_events": retained, "checks": {**green, **positive},
        }, sort_keys=True, indent=2) + "\n")
    finally:
        cleanup(lab, names)
