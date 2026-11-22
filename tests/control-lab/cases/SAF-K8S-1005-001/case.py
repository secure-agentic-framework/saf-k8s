"""Exercise a synthetic Kubernetes incident record and recovery lifecycle."""
import hashlib
import json
from pathlib import Path
import re
import time

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
HERE = Path(__file__).resolve().parent
FIXTURES = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
PREFIX = FIXTURES["case_prefix"]
INCIDENT_ID = FIXTURES["incident_id"]
DEPLOYMENT = f"{PREFIX}-mock-inference"
EVIDENCE = f"{PREFIX}-evidence"
AUDIT_CONFIG = "/etc/kubernetes/saf-1005-001/audit-policy.yaml"
AUDIT_DIR = "/var/log/kubernetes/saf-1005-001"
AUDIT_LOG = f"{AUDIT_DIR}/audit.jsonl"
MOCK_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "Synthetic defensive incident exercise in one fresh Kind v1.36.1 cluster. Checks role ownership, "
    "ordered timeline records, metadata-only Kubernetes audit evidence, pre-containment snapshot, "
    "namespace-scoped mock Deployment containment and recovery, and independent post-exercise review "
    "gates. The mock workload uses a digest-pinned public Python image and performs no network or "
    "application activity. All event, role, incident, and follow-up data is invented. This does not "
    "establish production policy completeness, external escalation or legal decisions, durable evidence "
    "retention, organization-wide readiness, AI-specific response sufficiency, or annual exercise cadence."
)


def prepare_kind(_lab, temporary: Path) -> Path:
    """Enable metadata-only audit records for this case's namespaced mock resources."""
    policy_path = temporary / "saf-1005-001-audit-policy.yaml"
    policy_path.write_text(f"""apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: Metadata
  namespaces: [saf-test]
  resources:
  - group: ""
    resources: [configmaps, events, pods]
  - group: apps
    resources: [deployments, deployments/scale]
- level: None
""", encoding="utf-8")
    audit_dir = temporary / "audit"
    audit_dir.mkdir()
    (audit_dir / "audit.jsonl").touch()
    config = temporary / "kind.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(policy_path))}
    containerPath: {AUDIT_CONFIG}
    readOnly: true
  - hostPath: {json.dumps(str(audit_dir))}
    containerPath: {AUDIT_DIR}
    readOnly: false
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: audit-policy-file
      value: {AUDIT_CONFIG}
    - name: audit-log-path
      value: {AUDIT_LOG}
    - name: audit-log-mode
      value: blocking
    extraVolumes:
    - name: saf-1005-001-audit-policy
      hostPath: {AUDIT_CONFIG}
      mountPath: {AUDIT_CONFIG}
      readOnly: true
      pathType: File
    - name: saf-1005-001-audit-log
      hostPath: {AUDIT_DIR}
      mountPath: {AUDIT_DIR}
      readOnly: false
      pathType: DirectoryOrCreate
""", encoding="utf-8")
    return config


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _timeline_valid(rows):
    try:
        parsed = [time.strptime(row["time"], "%Y-%m-%dT%H:%M:%SZ") for row in rows]
        events = [row["event"] for row in rows]
        return (len(rows) >= 3 and events[:3] == ["signal", "triage", "containment-approved"]
                and parsed == sorted(parsed))
    except (KeyError, TypeError, ValueError):
        return False


def _review_valid(record, digest):
    follow_up = record.get("follow_up") or {}
    return (
        record.get("status") == "reviewed"
        and record.get("reviewer") == "urn:example:saf:role:independent-reviewer"
        and record.get("evidence_digest") == f"sha256:{digest}"
        and bool(follow_up.get("action")) and bool(follow_up.get("owner"))
        and bool(re.fullmatch(r"20\d\d-\d\d-\d\d", str(follow_up.get("due", ""))))
    )


def _audit_records(lab):
    result = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat", AUDIT_LOG)
    selected = []
    for line in result.stdout.splitlines():
        row = json.loads(line)
        ref = row.get("objectRef") or {}
        if ref.get("namespace") == "saf-test" and ref.get("name") in {DEPLOYMENT, EVIDENCE}:
            selected.append(row)
    (lab.evidence / "audit.case.raw.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in selected))
    return selected


def _matching_audit(rows, verbs, resource, name, subresource=None):
    return [row for row in rows
            if row.get("verb") in verbs
            and (row.get("objectRef") or {}).get("resource") == resource
            and (row.get("objectRef") or {}).get("name") == name
            and (row.get("objectRef") or {}).get("subresource") == subresource
            and row.get("stage") == "ResponseComplete"
            and row.get("level") == "Metadata"
            and 200 <= row["responseStatus"]["code"] < 300]


def _workload(lab):
    return json.loads(lab.kubectl("get", "deployment", DEPLOYMENT, "-o", "json").stdout)


def _wait_contained(lab):
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        dep = _workload(lab)
        status = dep["status"]
        if (status.get("observedGeneration") == dep["metadata"]["generation"]
                and dep["spec"]["replicas"] == status.get("availableReplicas", 0) == 0):
            pods = json.loads(lab.kubectl("get", "pods", "-l", f"app={DEPLOYMENT}", "-o", "json").stdout)
            if not pods["items"]:
                return dep
        time.sleep(0.5)
    lab.block("The case-owned Deployment did not scale down and remove all owned Pods")


def _verified(snapshot, approved_digest):
    digest = hashlib.sha256(snapshot["data"]["payload.json"].encode()).hexdigest()
    return snapshot.get("immutable") is True and digest == snapshot["data"]["sha256"] == approved_digest


def run(lab):
    owner = FIXTURES["ownership"]
    red_owner = owner["red"]
    good_owner = owner["green"]
    lab.check("red", "Unassigned incident ownership is identified as incomplete",
              not red_owner["incident_commander"] and not red_owner["handoff_accepted"], red_owner)
    owner_ok = (good_owner["incident_commander"].startswith("urn:example:")
                and len(good_owner["supporting_roles"]) >= 2 and good_owner["handoff_accepted"])
    lab.check("green", "Named synthetic commander, supporting roles, and accepted handoff satisfy ownership",
              owner_ok, good_owner)
    positive_owner = owner["positive"]
    lab.check("positive", "An additional synthetic legal support role preserves the accepted owner record",
              positive_owner["incident_commander"] == good_owner["incident_commander"]
              and positive_owner["handoff_accepted"]
              and "urn:example:saf:role:legal" in positive_owner["supporting_roles"],
              positive_owner)

    timeline = FIXTURES["timeline"]
    lab.check("red", "Out-of-order synthetic incident entries fail the timeline gate",
              not _timeline_valid(timeline["red"]), timeline["red"])
    lab.check("green", "Timestamped signal, triage, and containment approval form an ordered timeline",
              _timeline_valid(timeline["green"]), timeline["green"])
    lab.check("positive", "Timeline accepts a later recovery verification without losing chronology",
              _timeline_valid(timeline["positive"])
              and timeline["positive"][-1]["event"] == "recovery-verified", timeline["positive"])

    evidence_payload = FIXTURES["evidence"]["captured_payload"]
    evidence_bytes = _canonical(evidence_payload)
    evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
    lab.check("red", "A mismatched expected evidence digest is rejected",
              FIXTURES["evidence"]["red_expected_sha256"] != evidence_sha,
              {"expected": FIXTURES["evidence"]["red_expected_sha256"], "actual": evidence_sha})
    lab.check("green", "Synthetic evidence bytes have a reproducible SHA-256 digest and contain no secrets",
              evidence_payload.get("contains_secrets") is False and len(evidence_sha) == 64,
              {"sha256": evidence_sha, "payload": evidence_payload})

    # The baseline workload is a harmless, tokenless sleeping container.
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": DEPLOYMENT, "namespace": "saf-test",
                     "labels": {"saf-k8s.example/fixture": INCIDENT_ID}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": DEPLOYMENT}},
                 "template": {
                     "metadata": {"labels": {"app": DEPLOYMENT,
                                                "saf-k8s.example/fixture": INCIDENT_ID}},
                     "spec": {"automountServiceAccountToken": False, "restartPolicy": "Always",
                              "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                                  "seccompProfile": {"type": "RuntimeDefault"}},
                              "containers": [{"name": "mock", "image": MOCK_IMAGE,
                                              "imagePullPolicy": "IfNotPresent",
                                              "command": ["python", "-c", "import time; time.sleep(3600)"],
                                              "securityContext": {"allowPrivilegeEscalation": False,
                                                                   "readOnlyRootFilesystem": True,
                                                                   "capabilities": {"drop": ["ALL"]}},
                                              "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                            "limits": {"cpu": "100m", "memory": "64Mi"}}}]},
                 }},
    })
    lab.kubectl("rollout", "status", f"deployment/{DEPLOYMENT}", "--timeout=90s", timeout=100)
    baseline = json.loads(lab.kubectl("get", "deployment", DEPLOYMENT, "-o", "json").stdout)
    baseline_generation = baseline["metadata"]["generation"]
    lab.check("positive", "Digest-pinned mock workload reaches one available replica before containment",
              baseline["spec"]["replicas"] == 1 and baseline["status"].get("availableReplicas") == 1
              and baseline["spec"]["template"]["spec"]["containers"][0]["image"] == MOCK_IMAGE,
              {"generation": baseline_generation, "replicas": baseline["status"].get("availableReplicas"),
               "image": MOCK_IMAGE})

    # Preserve only the deliberately synthetic workload metadata before applying containment.
    evidence_bytes = _canonical({
        "incident_evidence": evidence_payload,
        "capture": {"deployment": DEPLOYMENT, "generation": baseline_generation,
                    "replicas": baseline["spec"]["replicas"],
                    "image": baseline["spec"]["template"]["spec"]["containers"][0]["image"]},
    })
    evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
    evidence_object = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "immutable": True,
        "metadata": {"name": EVIDENCE, "namespace": "saf-test",
                     "labels": {"saf-k8s.example/incident": INCIDENT_ID}},
        "data": {"payload.json": evidence_bytes.decode("utf-8"), "sha256": evidence_sha,
                 "source_generation": str(baseline_generation)},
    }
    lab.create(evidence_object)
    lab.check("green", "Immutable evidence snapshot is committed before namespace workload containment",
              json.loads(lab.kubectl("get", "configmap", EVIDENCE, "-o", "json").stdout)
              ["immutable"] is True,
              {"evidence_name": EVIDENCE, "sha256": evidence_sha,
               "source_generation": baseline_generation})
    evidence_readback = json.loads(lab.kubectl("get", "configmap", EVIDENCE, "-o", "json").stdout)
    positive_evidence_ok = (
        hashlib.sha256(evidence_readback["data"]["payload.json"].encode("utf-8")).hexdigest() == evidence_sha
        and evidence_readback["data"]["source_generation"] == str(baseline_generation)
        and evidence_readback["immutable"] is True
    )
    lab.check("positive", "Independent API readback preserves the exact immutable pre-containment evidence bytes",
              positive_evidence_ok, {"sha256": evidence_sha,
                                     "source_generation": evidence_readback["data"]["source_generation"],
                                     "immutable": evidence_readback["immutable"]})

    # Containment changes only this named mock Deployment in the disposable cluster.
    lab.kubectl("scale", f"deployment/{DEPLOYMENT}", "--replicas=0")
    contained = _wait_contained(lab)
    lab.check("green", "Containment scales the exact mock Deployment and removes its Pods",
              contained["spec"]["replicas"] == 0,
              {"desired_replicas": 0, "available_replicas": 0, "observed_pods": 0})

    saved = json.loads(lab.kubectl("get", "configmap", EVIDENCE, "-o", "json").stdout)
    bad_digest = FIXTURES["evidence"]["red_expected_sha256"]
    lab.check("red", "The recovery gate rejects a mismatched approval digest while replicas remain zero",
              not _verified(saved, bad_digest) and _workload(lab)["spec"]["replicas"] == 0,
              {"invalid_digest_rejected": True, "desired_replicas": 0})
    saved_digest_ok = _verified(saved, evidence_sha) and saved["data"]["payload.json"].encode() == evidence_bytes
    if not saved_digest_ok:
        lab.block("The approved snapshot did not match the persisted evidence")
    lab.kubectl("scale", f"deployment/{DEPLOYMENT}", "--replicas=1")
    lab.kubectl("rollout", "status", f"deployment/{DEPLOYMENT}", "--timeout=90s", timeout=100)
    recovered = _workload(lab)
    recovery_ok = (recovered["spec"]["replicas"] == 1
                   and recovered["status"].get("availableReplicas") == 1
                   and recovered["spec"]["template"]["spec"]["containers"][0]["image"] == MOCK_IMAGE
                   and saved["immutable"] is True and saved_digest_ok)
    lab.check("green", "Recovery restores the pinned mock workload and preserves verified pre-containment evidence",
              recovery_ok, {"available_replicas": recovered["status"].get("availableReplicas"),
                            "image": recovered["spec"]["template"]["spec"]["containers"][0]["image"],
                            "evidence_sha256": saved["data"]["sha256"], "immutable": saved["immutable"]})
    lab.check("positive", "Recovered mock Pod is API-observable and retains the original pre-containment generation",
              recovery_ok and saved["data"]["source_generation"] == str(baseline_generation)
              and recovered["metadata"]["generation"] > baseline_generation,
              {"baseline_generation": baseline_generation,
               "recovered_generation": recovered["metadata"]["generation"],
               "available_replicas": recovered["status"].get("availableReplicas"),
               "evidence_generation": saved["data"]["source_generation"]})

    review = FIXTURES["review"]
    lab.check("red", "A closed record without independent review, evidence digest, or follow-up fails review gate",
              not _review_valid(review["red"], evidence_sha), review["red"])
    green_review = dict(review["green"])
    green_review["evidence_digest"] = f"sha256:{evidence_sha}"
    lab.check("green", "Independent post-exercise review names its evidence and an owned due-dated follow-up",
              _review_valid(green_review, evidence_sha), green_review)
    positive_review = dict(review["positive"])
    positive_review["evidence_digest"] = f"sha256:{evidence_sha}"
    lab.check("positive", "Review leaves unverified production validation visible instead of asserting coverage",
              _review_valid(positive_review, evidence_sha)
              and positive_review.get("production_validation") == "unverified", positive_review)

    raw_audit = _audit_records(lab)
    created = _matching_audit(raw_audit, {"create"}, "deployments", DEPLOYMENT)
    captured = _matching_audit(raw_audit, {"create"}, "configmaps", EVIDENCE)
    scales = _matching_audit(raw_audit, {"patch", "update"}, "deployments", DEPLOYMENT, "scale")
    ordered = created[:1] + captured[:1] + scales
    times = [row["stageTimestamp"] for row in ordered]
    audit_checks = {
        "workload_created": len(created) == 1,
        "evidence_created": len(captured) == 1,
        "two_exact_scale_operations": len(scales) == 2,
        "ordered_distinct_successful_operations": len(ordered) == 4 and times == sorted(set(times)),
        "metadata_only": all("requestObject" not in row and "responseObject" not in row for row in ordered),
    }
    (lab.evidence / "audit.summary.json").write_text(json.dumps({
        "origin": "kube-apiserver audit log backend",
        "policy_level": "Metadata",
        "incident_id": INCIDENT_ID,
        "matched_record_count": len(raw_audit),
        "checks": audit_checks,
        "records": [{"auditID": row.get("auditID"), "requestReceivedTimestamp": row.get("requestReceivedTimestamp"),
                     "stageTimestamp": row.get("stageTimestamp"), "verb": row.get("verb"),
                     "user": (row.get("user") or {}).get("username"),
                     "objectRef": row.get("objectRef"),
                     "response_code": (row.get("responseStatus") or {}).get("code")}
                    for row in raw_audit],
    }, indent=2) + "\n", encoding="utf-8")
    lab.check("positive", "Native API audit metadata contains the mock workload and evidence operations",
              all(audit_checks.values()), audit_checks)
