"""Preserve real member-specific admission and audit evidence in a shared report."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

HERE = Path(__file__).resolve().parent
NS = "saf-test"
CONTROL = "SAF-K8S-0910-028/PSA-RESTRICTED"
POLICY_VERSION = "v1.36"
PROBE_NAME = "fixture-compliance-benign"
CLASSIFICATION = "fixture-owner-classification"
EXCEPTION = "fixture-approved-exception"
REPORT = "fixture-unified-compliance-report"
PRIVATE = "fixture-private-control-record"
PROBER = "fixture-member-prober"
COLLECTOR = "fixture-report-writer"
REVIEWER = "fixture-independent-reviewer"
OUTSIDER = "fixture-unscoped-reviewer"
RBAC = "rbac.authorization.k8s.io/v1"
MAX_AGE_SECONDS = 300

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
PROBE_IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
AUDIT_HELPER = HERE.parent / "SAF-K8S-1001-004" / "case.py"
SCOPE = (
    "Two independently owned Kubernetes API servers report actual Pod Security Admission "
    "and Metadata-level audit events for one harmless dry-run Pod. A protected central report "
    "preserves member and event identities, opposite dispositions, audit coverage and the "
    "approved fixture exception. An independent reviewer retrieves the combined view."
)
AUDIT_POLICY = """
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
  - level: Metadata
    verbs: [create]
    namespaces: [saf-test]
    resources:
      - group: ""
        resources: [pods]
  - level: None
"""
SOURCES = {
    "admission": "https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/",
    "audit": "https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
    "scope": SCOPE,
}


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load published source {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_audit_config(root):
    helper = load_module(AUDIT_HELPER, "saf_compliance_kind_audit")
    root.mkdir()
    logs = root / "logs"
    logs.mkdir()
    policy = root / "policy.yaml"
    policy.write_text(AUDIT_POLICY.lstrip())
    config = root / "kind.yaml"
    config.write_text(helper.kind_config(policy, logs))
    return config, logs / Path(helper.AUDIT_FILE).name


def prepare_kind(lab, temporary):
    config, _ = build_audit_config(temporary / "compliance-local")
    return config


@contextmanager
def owned_audited_peer(lab):
    root = lab.kubeconfig.parent / "compliance-peer"
    config, audit = build_audit_config(root)
    name = lab.cluster + "-compliance-peer"
    kubeconfig = root / "kubeconfig"
    if name in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("The disposable peer name is already in use")

    def kubectl(*args, timeout=45, **kwargs):
        return lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context", "kind-" + name,
                           "--namespace", NS, f"--request-timeout={timeout - 5}s",
                           *args, timeout=timeout, **kwargs)

    try:
        lab.command("kind", "create", "cluster", "--name", name, "--image", NODE_IMAGE,
                    "--config", str(config), "--kubeconfig", str(kubeconfig),
                    "--wait", "100s", timeout=180)
        endpoint = json.loads(kubectl("config", "view", "--minify", "-o", "json").stdout
                              )["clusters"][0]["cluster"]["server"]
        owned = lab.command("docker", "port", name + "-control-plane", "6443/tcp").stdout.strip()
        if not re.fullmatch(r"127\.0\.0\.1:\d+", owned) or urlsplit(endpoint).netloc != owned:
            lab.block("The peer audit API does not identify its expected owned loopback endpoint")
        kubectl("create", "namespace", NS)
        yield kubectl, audit
    finally:
        lab.command("kind", "delete", "cluster", "--name", name, "--kubeconfig", str(kubeconfig),
                    timeout=80)


def expected_audit(lab, path, code):
    deadline = time.monotonic() + 12
    actor = f"system:serviceaccount:{NS}:{PROBER}"
    while time.monotonic() < deadline:
        if path.is_file():
            for line in path.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                route = urlsplit(event.get("requestURI", ""))
                username = event.get("impersonatedUser", {}).get("username")
                if (event.get("stage") == "ResponseComplete" and event.get("verb") == "create"
                        and username == actor and route.path == f"/api/v1/namespaces/{NS}/pods"
                        and parse_qs(route.query).get("dryRun") == ["All"]
                        and event.get("responseStatus", {}).get("code") == code
                        and identity(event.get("auditID"))):
                    return {"audit_id": event["auditID"], "actor": actor, "status": code,
                            "stage": "ResponseComplete", "time": event["stageTimestamp"]}
        time.sleep(0.25)
    lab.block("The owned audit log did not contain the exact fixture dry-run event")


def row(kind, name, api="v1", **fields):
    return {"apiVersion": api, "kind": kind,
            "metadata": {"name": name, "namespace": NS}, **fields}


def create(target, obj):
    result = target("create", "-f", "-", payload=json.dumps(obj, sort_keys=True))
    if result.returncode:
        raise RuntimeError(f"Could not create fixture {obj['kind']}/{obj['metadata']['name']}: {result.stderr}")


def get_json(target, *args):
    result = target(*args, "-o", "json")
    if result.returncode:
        raise RuntimeError(f"Could not observe {' '.join(args)}: {result.stderr}")
    return json.loads(result.stdout)


def identity(value):
    try:
        return str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def probe(target):
    pod = row("Pod", PROBE_NAME, spec={
        "restartPolicy": "Never",
        "containers": [{"name": "fixture", "image": PROBE_IMAGE, "imagePullPolicy": "Never",
                        "command": ["/bin/true"]}],
    })
    result = target("create", "-f", "-", "--dry-run=server", "-o", "json",
                    payload=json.dumps(pod, sort_keys=True), allow_failure=True,
                    *[f"--as=system:serviceaccount:{NS}:{PROBER}"])
    if result.returncode == 0:
        return {"decision": "accepted", "policy_signal": ""}
    if "violates PodSecurity" in result.stderr:
        return {"decision": "denied", "policy_signal": "PodSecurity"}
    raise RuntimeError(f"Admission returned an unclassified error: {result.stderr}")


def owner_record(target, cluster_uid, decision, exception_state, exception_reason):
    classification = {
        "control": CONTROL,
        "cluster_uid": cluster_uid,
        "classification": "compliant" if decision == "pass" else "noncompliant",
        "control_result": decision,
        "evidence_ref": PROBE_NAME,
    }
    create(target, row("ConfigMap", CLASSIFICATION, immutable=True, data={
        "classification.json": json.dumps(classification, sort_keys=True),
    }))
    exception = {
        "control": CONTROL,
        "cluster_uid": cluster_uid,
        "state": exception_state,
        "scope": "fixture-only",
        "reason": exception_reason,
        "expires": "2099-12-31T23:59:59Z" if exception_state == "approved" else "",
    }
    create(target, row("ConfigMap", EXCEPTION, immutable=True, data={
        "exception.json": json.dumps(exception, sort_keys=True),
    }))
    seen_classification = json.loads(
        get_json(target, "get", "configmap", CLASSIFICATION, "-n", NS)["data"]["classification.json"])
    seen_exception = json.loads(
        get_json(target, "get", "configmap", EXCEPTION, "-n", NS)["data"]["exception.json"])
    return seen_classification, seen_exception


def assess(member, now=None, max_age=MAX_AGE_SECONDS):
    """Return a control status only for complete, fresh, identity-matched evidence."""
    now = now or datetime.now(timezone.utc)
    evidence = member.get("evidence")
    if evidence is None:
        return "missing"
    if not evidence.get("observed"):
        return "unobserved"
    try:
        observed_at = datetime.fromisoformat(evidence["observed_at"].replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError):
        return "missing"
    if observed_at.tzinfo is None:
        return "missing"
    age = (now - observed_at).total_seconds()
    if age < 0 or age > max_age:
        return "stale"
    classification = member.get("classification")
    if not classification:
        return "unclassified"
    if classification.get("cluster_uid") != member.get("cluster_uid"):
        return "identity_mismatch"
    if evidence.get("decision") not in {"accepted", "denied"}:
        return "unobserved"
    expected = "pass" if evidence["decision"] == "denied" else "fail"
    if classification.get("control_result") != expected:
        return "classification_mismatch"
    return expected


def read_result(target, name, resource=REPORT):
    return target("get", "configmap", resource, "-n", NS, "-o", "json",
                  f"--as={name}", allow_failure=True)


def run(lab):
    audit_helper = load_module(AUDIT_HELPER, "saf_compliance_audit_filename")
    local_audit = lab.kubeconfig.parent / "compliance-local" / "logs" / Path(audit_helper.AUDIT_FILE).name
    with owned_audited_peer(lab) as (peer_kubectl, peer_audit):
        targets = (("owner-a", lab.kubectl, local_audit), ("owner-b", peer_kubectl, peer_audit))
        members = []
        for member_name, target, audit in targets:
            create(target, row("ServiceAccount", PROBER, automountServiceAccountToken=False))
            create(target, row("Role", PROBER, api=RBAC, rules=[
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]))
            create(target, row("RoleBinding", PROBER, api=RBAC,
                roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": PROBER},
                subjects=[{"kind": "ServiceAccount", "name": PROBER, "namespace": NS}]))
            policy_level = "restricted" if member_name == "owner-a" else "baseline"
            labels = {
                "pod-security.kubernetes.io/enforce": policy_level,
                "pod-security.kubernetes.io/enforce-version": POLICY_VERSION,
            }
            target("label", "namespace", NS, *(f"{key}={value}" for key, value in labels.items()),
                   "--overwrite")
            namespace = get_json(target, "get", "namespace", NS)
            observed_labels = {key: namespace.get("metadata", {}).get("labels", {}).get(key)
                               for key in labels}
            cluster_uid = get_json(target, "get", "namespace", "kube-system")["metadata"]["uid"]
            if not identity(cluster_uid):
                lab.block(f"{member_name} did not provide a Kubernetes cluster UID")
            observed = probe(target)
            if observed_labels != labels:
                lab.block(f"{member_name} policy labels differ from the requested fixture")
            expected_decision = "denied" if policy_level == "restricted" else "accepted"
            if observed["decision"] != expected_decision:
                lab.block(f"{member_name} did not demonstrate the expected Pod Security Admission result")
            event = expected_audit(lab, audit, 403 if expected_decision == "denied" else 201)
            members.append({"name": member_name, "target": target, "uid": cluster_uid,
                            "policy_level": policy_level, "observed": observed, "native_audit": event})

        distinct_members = members[0]["uid"] != members[1]["uid"]
        divergent = members[0]["observed"]["decision"] != members[1]["observed"]["decision"]
        central_identity = lab.kubectl("get", "namespace", "kube-system",
                                       "-o", "jsonpath={.metadata.uid}").stdout.strip()
        if not distinct_members or central_identity != members[0]["uid"]:
            lab.block("The local source identity and separately owned peer identity were not distinct")

        # Each owner publishes one immutable explicit classification and an
        # immutable exception record bound to that owner's observed cluster UID.
        for member in members:
            result = "pass" if member["observed"]["decision"] == "denied" else "fail"
            exception_state = "none" if result == "pass" else "approved"
            reason = "" if exception_state == "none" else "approved fixture-only baseline exception"
            classification, exception = owner_record(
                member["target"], member["uid"], result, exception_state, reason)
            member["classification"] = classification
            member["exception"] = exception
            member["control_result"] = result
            member["observed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            member["audit_coverage"] = {"required": 1, "observed": 1,
                                        "event": member["native_audit"]}

        def reader_rule():
            return [
                row("ServiceAccount", COLLECTOR, automountServiceAccountToken=False),
                row("Role", COLLECTOR, api=RBAC, rules=[
                    {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}]),
                row("RoleBinding", COLLECTOR, api=RBAC,
                    roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": COLLECTOR},
                    subjects=[{"kind": "ServiceAccount", "name": COLLECTOR, "namespace": NS}]),
                row("ServiceAccount", REVIEWER, automountServiceAccountToken=False),
                row("ServiceAccount", OUTSIDER, automountServiceAccountToken=False),
                row("Role", REVIEWER, api=RBAC, rules=[{
                    "apiGroups": [""], "resources": ["configmaps"], "resourceNames": [REPORT],
                    "verbs": ["get"],
                }]),
                row("RoleBinding", REVIEWER, api=RBAC,
                    roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": REVIEWER},
                    subjects=[{"kind": "ServiceAccount", "name": REVIEWER, "namespace": NS}]),
            ]

        for obj in reader_rule():
            create(lab.kubectl, obj)
        # Establish that the central view is absent while each independently
        # owned API server already has differing, observed control evidence.
        missing_report = lab.kubectl("get", "configmap", REPORT, "-n", NS, allow_failure=True)
        fragment = {m["name"]: {"policy_level": m["policy_level"],
                                "decision": m["observed"]["decision"]} for m in members}
        baseline_ok = (distinct_members and divergent and missing_report.returncode != 0
                       and "NotFound" in missing_report.stderr)
        lab.check("red", "Member evidence differs while no unified central report exists",
                  baseline_ok, {"members": fragment, "central_report_missing": baseline_ok})

        now = datetime.now(timezone.utc)
        report_members = []
        for member in members:
            evidence = {"observed": True, "observed_at": member["observed_at"],
                        "decision": member["observed"]["decision"],
                        "policy_level": member["policy_level"]}
            record = {"member": member["name"], "cluster_uid": member["uid"],
                      "control": CONTROL, "classification": member["classification"],
                      "control_result": member["control_result"],
                      "audit_coverage": member["audit_coverage"],
                      "exception": member["exception"], "evidence": evidence}
            record["normalized_status"] = assess(record, now=now)
            report_members.append(record)

        quality_checks = {
            "missing_evidence_is_not_pass": assess({"cluster_uid": "x", "evidence": None}) == "missing",
            "unobserved_evidence_is_not_pass": assess({"cluster_uid": "x", "evidence": {"observed": False}}) == "unobserved",
            "stale_evidence_is_not_pass": assess({"cluster_uid": "x", "classification": {}, "evidence": {
                "observed": True, "observed_at": "2000-01-01T00:00:00Z", "decision": "denied",
            }}, now=now) == "stale",
        }
        source_digest = hashlib.sha256(json.dumps(report_members, sort_keys=True).encode()).hexdigest()
        report = {"control": CONTROL, "source_digest": source_digest,
                  "member_count": len(report_members), "members": report_members,
                  "evidence_quality_checks": quality_checks,
                  "source_attributions": SOURCES}
        report_obj = row("ConfigMap", REPORT, immutable=True, data={
            "report.json": json.dumps(report, sort_keys=True, separators=(",", ":")),
        })
        lab.kubectl("create", "-f", "-", f"--as=system:serviceaccount:{NS}:{COLLECTOR}",
                    payload=json.dumps(report_obj, sort_keys=True))
        create(lab.kubectl, row("ConfigMap", PRIVATE, data={"fixture": "not-for-reviewer"}))

        reviewer = f"system:serviceaccount:{NS}:{REVIEWER}"
        outsider = f"system:serviceaccount:{NS}:{OUTSIDER}"
        retrieved = read_result(lab.kubectl, reviewer)
        denied_private = read_result(lab.kubectl, reviewer, PRIVATE)
        denied_outsider = read_result(lab.kubectl, outsider)
        write_attempt = lab.kubectl("patch", "configmap", REPORT, "-n", NS,
                                    "--type=merge", "-p", '{"data":{"reviewer":"write"}}',
                                    f"--as={reviewer}", allow_failure=True)
        if retrieved.returncode:
            lab.block("The scoped reviewer could not read the unified report")
        central = json.loads(json.loads(retrieved.stdout)["data"]["report.json"])
        explicit_matches = all(
            member["classification"].get("cluster_uid") == member["cluster_uid"]
            and member["classification"].get("control_result") == member["control_result"]
            and member["normalized_status"] == member["control_result"]
            for member in central["members"])
        owner_exceptions = {member["member"]: member["exception"]["state"] for member in central["members"]}
        green = {
            "two_distinct_member_identities_preserved": len({m["cluster_uid"] for m in central["members"]}) == 2,
            "control_results_and_explicit_classifications_match": explicit_matches,
            "native_audit_coverage_preserves_exact_events_per_member": all(
                item["audit_coverage"] == member["audit_coverage"]
                and item["audit_coverage"]["observed"] == item["audit_coverage"]["required"] == 1
                and item["audit_coverage"]["event"]["status"] == (403 if item["member"] == "owner-a" else 201)
                for item, member in zip(central["members"], members)),
            "report_matches_exact_ingested_records": central == report,
            "distinct_audit_event_ids_preserved": len({
                row["audit_coverage"]["event"]["audit_id"] for row in central["members"]}) == 2,
            "owner_specific_approved_exception_preserved": owner_exceptions == {
                "owner-a": "none", "owner-b": "approved"},
            "missing_unobserved_and_stale_are_not_pass": all(quality_checks.values()),
            "reviewer_reads_only_named_report": (denied_private.returncode != 0
                and "Forbidden" in denied_private.stderr),
            "reviewer_cannot_modify_report": write_attempt.returncode != 0
                and "Forbidden" in write_attempt.stderr,
            "unscoped_identity_cannot_read_report": (denied_outsider.returncode != 0
                and "Forbidden" in denied_outsider.stderr),
            "report_is_immutable_and_bounded": len(retrieved.stdout) < 24000
                and json.loads(retrieved.stdout).get("immutable") is True,
        }
        lab.check("green", "Unified report preserves owner, result, coverage, and exception provenance",
                  all(green.values()), green)
        positive = {
            "independent_reviewer_received_both_members": central["member_count"] == 2
                and len(central["members"]) == 2,
            "different_owner_outcomes_remain_distinct": [m["normalized_status"] for m in central["members"]]
                == ["pass", "fail"],
            "approved_exception_does_not_overwrite_control_failure": next(
                m for m in central["members"] if m["member"] == "owner-b")["control_result"] == "fail"
                and next(m for m in central["members"] if m["member"] == "owner-b")["exception"]["state"] == "approved",
        }
        lab.check("positive", "Independent scoped review retains the member-level posture distinction",
                  all(positive.values()), positive)
        (lab.evidence / "unified-compliance-normalized.json").write_text(json.dumps({
            "members": [{k: item[k] for k in ("member", "control", "normalized_status")} |
                        {"exception_state": item["exception"]["state"],
                         "audit_code": item["audit_coverage"]["event"]["status"]}
                        for item in central["members"]],
            "checks": {**green, **positive},
        }, sort_keys=True, indent=2) + "\n")
        (lab.evidence / "unified-compliance-observations.json").write_text(
            json.dumps({"report": central, "checks": {**green, **positive}},
                       sort_keys=True, indent=2) + "\n")
