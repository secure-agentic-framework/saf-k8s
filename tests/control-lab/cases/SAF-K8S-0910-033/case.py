"""Correlate an observed inter-cluster alert to independently authenticated API evidence."""
from datetime import datetime, timedelta
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import time
from uuid import UUID

from fixtures import ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
REPORTER = "fixture-incident-reporter"
INVESTIGATOR = "fixture-incident-investigator"
OUTSIDER = "fixture-incident-outsider"
DRAFT = "fixture-incomplete-incident"
FINAL = "fixture-correlated-incident"
MARKER = "fixture-investigation-004"
TRACE = "synthetic-telemetry-investigation-004"
RECORDS = [f"synthetic-telemetry-investigation-{number:03d}" for number in range(1, 5)]
SCOPE = (
    "One harmless, threshold-triggering transfer across two owned Kind clusters. A receiver "
    "observer reads the actual mTLS-attributed record. A separate source Kubernetes API provides "
    "a native Metadata audit event of an exact named receipt written by the same bound Pod. "
    "A scoped investigator reads the resulting immutable correlated or incomplete report."
)
AUDIT = f"""apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
  - level: Metadata
    verbs: [patch]
    namespaces: [{NS}]
    resources:
      - group: ""
        resources: [configmaps]
        resourceNames: [{MARKER}]
  - level: None
"""


def load(suffix, filename, name):
    path = HERE.parent / ("SAF-K8S-" + suffix) / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load reviewed fixture {suffix}/{filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_kind(lab, temporary):
    audit = load("1001-004", "case.py", "saf_investigation_audit")
    logs = temporary / "incident-audit"
    logs.mkdir()
    policy = temporary / "incident-policy.yaml"
    policy.write_text(AUDIT)
    config = temporary / "incident-kind.yaml"
    config.write_text(audit.kind_config(policy, logs))
    return config


def obj(kind, name, api="v1", **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def actor(name):
    return f"system:serviceaccount:{NS}:{name}"


def allow(lab, name, verbs, names=None):
    rule = {"apiGroups": [""], "resources": ["configmaps"], "verbs": verbs}
    if names:
        rule["resourceNames"] = names
    lab.create(obj("Role", name, RBAC, rules=[rule]))
    lab.create(obj("RoleBinding", name, RBAC,
                   roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
                   subjects=[{"kind": "ServiceAccount", "name": name, "namespace": NS}]))


def audit_event(lab, path, source_actor, pod_uid):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if path.is_file():
            for line in path.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                user = event.get("user", {})
                ref = event.get("objectRef", {})
                if (event.get("stage") == "ResponseComplete" and event.get("verb") == "patch"
                        and user.get("username") == source_actor
                        and user.get("extra", {}).get("authentication.kubernetes.io/pod-uid") == [pod_uid]
                        and ref.get("resource") == "configmaps" and ref.get("namespace") == NS
                        and ref.get("name") == MARKER and event.get("responseStatus", {}).get("code") == 200):
                    audit_id = str(UUID(event["auditID"]))
                    when = datetime.fromisoformat(event["stageTimestamp"].replace("Z", "+00:00"))
                    if when.utcoffset() != timedelta(0):
                        lab.block("The native receipt timestamp is not UTC")
                    return {"audit_id": audit_id, "event_time": event["stageTimestamp"], "actor": source_actor,
                            "pod_uid": pod_uid, "verb": event["verb"], "resource": MARKER, "status": 200}
        time.sleep(0.25)
    lab.block("The source API did not emit the expected bound-Pod audit event")


def classify(receiver, source, event):
    if not receiver or not source or not event:
        return "unknown-incomplete"
    if (receiver["record_id"] != source["trace"] or receiver["body_sha256"] != source["body_sha256"]
            or event["resource"] != MARKER or source["classification"] != "authorized-fixture"):
        return "unknown-inconsistent"
    return "authorized-fixture-traffic"


def publish_report(lab, name, report):
    resource = obj("ConfigMap", name, immutable=True,
                   data={"incident.json": json.dumps(report, sort_keys=True, separators=(",", ":"))})
    lab.kubectl("create", "-f", "-", f"--as={actor(REPORTER)}", payload=json.dumps(resource))


def read_report(lab, name, reader):
    return lab.kubectl("get", "configmap", name, f"--as={actor(reader)}",
                       "-o", "json", allow_failure=True)


def retrieve(lab, name):
    reply = read_report(lab, name, INVESTIGATOR)
    if reply.returncode:
        lab.block("The scoped investigator did not receive its permitted report")
    stored = json.loads(reply.stdout)
    if stored.get("immutable") is not True:
        lab.block("The stored evidence object is not immutable")
    return json.loads(stored["data"]["incident.json"])


def run(lab):
    runtime = load("0908-001", "case.py", "saf_investigation_runtime")
    peers = load("0910-020", "owned_peer.py", "saf_investigation_peers")
    monitor = load("0910-032", "case.py", "saf_investigation_monitor")
    audit = load("1001-004", "case.py", "saf_investigation_event_name")
    image = runtime.load_runtime(lab)
    pki_dir = lab.kubeconfig.parent / "incident-pki"
    pki_dir.mkdir(mode=0o700)
    root, ca = monitor.pki(lab, pki_dir)
    program = (HERE.parent / "SAF-K8S-0910-032" / "monitor_fixture.py").read_text()
    code = obj("ConfigMap", monitor.CODE, immutable=True, data={"monitor_fixture.py": program})
    trust = obj("ConfigMap", monitor.TRUST, immutable=True, data={"ca.crt": ca.read_text()})

    def credential(call, name):
        call("create", "secret", "tls", name, "--cert=" + str(root / f"{name}.crt"),
             "--key=" + str(root / f"{name}.key"), "-o", "name")

    with peers.owned_peer(lab, image) as (peer, address):
        def peer_create(resource):
            return json.loads(peer("create", "-f", "-", "-o", "json",
                                   payload=json.dumps(resource)).stdout)

        for resource in (code, trust):
            peer_create(resource)
        credential(peer, monitor.COLLECTOR)
        peer_create(monitor.workload(monitor.COLLECTOR, image, credential=True, server=True))
        service = peer_create(obj("Service", monitor.COLLECTOR, spec={
            "type": "NodePort", "selector": {"app": monitor.COLLECTOR},
            "ports": [{"port": 8443, "targetPort": 8443}]}))
        port = service["spec"]["ports"][0]["nodePort"]

        lab.create(trust)
        code["data"]["source_actor.py"] = (HERE / "source_actor.py").read_text()
        lab.create(code)
        lab.create(obj("ConfigMap", MARKER, data={}))
        for name in (monitor.SOURCE, monitor.OBSERVER, REPORTER, INVESTIGATOR, OUTSIDER):
            lab.create(obj("ServiceAccount", name, automountServiceAccountToken=False))
        allow(lab, monitor.SOURCE, ["patch"], [MARKER])
        allow(lab, REPORTER, ["create"])
        allow(lab, INVESTIGATOR, ["get"], [DRAFT, FINAL])
        for name in (monitor.SOURCE, monitor.OBSERVER):
            credential(lab.kubectl, name)
            workload = monitor.workload(name, image, credential=True)
            workload["spec"]["automountServiceAccountToken"] = name == monitor.SOURCE
            lab.create(workload)
            ready(lab, name)
        peer("wait", "--for=condition=Ready", "pod/" + monitor.COLLECTOR, "--timeout=75s", timeout=85)

        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            health = lab.kubectl("exec", monitor.OBSERVER, "--", "python", "/code/monitor_fixture.py",
                                 "health", address, str(port), monitor.SERVER_NAME, timeout=10,
                                 allow_failure=True)
            if health.returncode == 0 and json.loads(health.stdout) == {"ready": True}:
                break
            time.sleep(0.25)
        else:
            lab.block("The exact fixture telemetry route did not become reachable")

        sent = monitor.send(lab, address, port, RECORDS)
        witnessed = monitor.report(lab, monitor.OBSERVER, address, port, "alert", RECORDS)
        if not all(witnessed["checks"].values()) or [item["status"] for item in sent["sent"]] != [202] * 4:
            lab.block("The independent observer did not establish the exact fixture alert")
        observed = witnessed["report"]
        receiver, = (row for row in observed["records"] if row["record_id"] == TRACE)
        alert, = observed["events"]
        before = {"trace": TRACE, "collector": alert, "received": receiver,
                  "native_source_observation": None, "disposition": classify(receiver, None, None)}
        publish_report(lab, DRAFT, before)
        incomplete = retrieve(lab, DRAFT)
        lab.check("red", "The real alert is incomplete without independent source evidence",
                  incomplete == before and before["disposition"] == "unknown-incomplete",
                  {"alert_observed": bool(alert), "receiver_record": receiver,
                   "disposition": incomplete["disposition"]})

        source_pod = json.loads(lab.kubectl("get", "pod", monitor.SOURCE, "-o", "json").stdout)
        if source_pod["spec"]["serviceAccountName"] != monitor.SOURCE:
            lab.block("The source Pod did not use its expected service account")
        expected_body = json.dumps({"id": TRACE, "metric": 7, "synthetic": True},
                                   sort_keys=True, separators=(",", ":")).encode()
        exact_digest = sha256(expected_body).hexdigest()
        emitted = lab.kubectl("exec", monitor.SOURCE, "--", "python", "/code/source_actor.py",
                              exact_digest, timeout=12)
        producer = json.loads(emitted.stdout)
        source = producer["record"]
        marker_raw = json.loads(lab.kubectl("get", "configmap", MARKER, "-o", "json").stdout)
        event = audit_event(lab, lab.kubeconfig.parent / "incident-audit" / Path(audit.AUDIT_FILE).name,
                            actor(monitor.SOURCE), source_pod["metadata"]["uid"])
        api_uids = [command("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
                    for command in (lab.kubectl, peer)]
        complete = {**before, "native_source_observation": event, "source_receipt": source,
                    "member_api_uids": api_uids, "disposition": classify(receiver, source, event)}
        publish_report(lab, FINAL, complete)
        actual = retrieve(lab, FINAL)
        outsider = read_report(lab, FINAL, OUTSIDER)
        writer_denied = lab.kubectl("patch", "configmap", FINAL, f"--as={actor(INVESTIGATOR)}",
                                   "--type=merge", "-p", '{"data":{"unexpected":"write"}}', allow_failure=True)
        altered_receipt = {**source, "body_sha256": "0" * 64}
        green = {
            "actual_source_persisted_marker": marker_raw["data"] == source and producer["status"] == 200,
            "source_and_receiver_content_matches": receiver["body_sha256"] == exact_digest == source["body_sha256"],
            "exact_receiving_identity": receiver["source"] == alert["source"] == (
                f"spiffe://saf.test/ns/{NS}/sa/{monitor.SOURCE}"),
            "different_owned_cluster_identities": len({UUID(value) for value in api_uids}) == 2,
            "separate_bound_pod_audit": event["pod_uid"] == source_pod["metadata"]["uid"],
            "source_timestamp_retained": bool(event["event_time"]),
            "contradictory_input_remains_unknown": classify(receiver, altered_receipt, event) == "unknown-inconsistent",
            "outsider_read_denied": outsider.returncode != 0 and "Forbidden" in outsider.stderr,
            "investigator_write_denied": writer_denied.returncode != 0 and "Forbidden" in writer_denied.stderr,
        }
        lab.check("green", "The investigator correlates actual scoped event sources without trusting absent evidence",
                  all(green.values()), green)
        positive = {"independent_report_matches_complete_evidence": actual == complete,
                    "classification_is_exact_fixture_disposition":
                    actual["disposition"] == "authorized-fixture-traffic"}
        lab.check("positive", "The scoped investigator retrieves the complete bounded attribution",
                  all(positive.values()), positive)
        (lab.evidence / "cross-cluster-investigation.json").write_text(
            json.dumps({"before": incomplete, "after": actual, "checks": {**green, **positive}},
                       indent=2, sort_keys=True) + "\n")
        (lab.evidence / "investigation-normalized.json").write_text(
            json.dumps({"before": incomplete["disposition"], "after": actual["disposition"],
                        "receiving_record": receiver, "checks": {**green, **positive}},
                       indent=2, sort_keys=True) + "\n")
