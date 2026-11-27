"""SAF-K8S-0905-045: inert JSON behavioral vetting and disposition witness."""
import importlib.util
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
EVALUATOR = "toy-model-evaluator"
REVIEWER = "independent-model-reviewer"
EVALUATION = "behavioral-evaluation"
DISPOSITION = "model-disposition"
SCOPE = (
    "Runs bounded Jobs in the precreated saf-test namespace on the runner's "
    "digest-pinned default Kind cluster. The toy evaluator processes only a mounted, "
    "immutable JSON fixture with one allowlisted operation and no model artifact, "
    "network client, or Kubernetes credential. A separate reviewer ServiceAccount "
    "reads the immutable evaluation, writes exact approved/rejected/escalated dispositions "
    "to a precreated ConfigMap, and creates one synthetic Warning Event for the "
    "rejected toy record. Assertions cover the ungated unsafe counterfactual, exact "
    "rejection and event, exact safe approval, Pod hardening, and RBAC separation. "
    "This does not execute or behaviorally vet a real model; validate sandbox escape "
    "resistance, network policy enforcement, real model quality, data coverage, "
    "human reviewer identity or procedures, signature verification, or production "
    "promotion/audit workflows. A further tokenless evaluator Job makes one fixed "
    "four-token CPU request to the digest-pinned llama.cpp b9519 Stories test model, "
    "records identifiers, counts and hashes only, and obtains an independent "
    "digest-bound escalated/held review because this smoke request has no approved "
    "safety rubric or representative dataset. The bounded network comparison uses the "
    "runner's bundled kindnet and proves one same-namespace evaluator-to-model HTTP route "
    "while an unrelated inert peer is blocked under the exact selector. This does not "
    "establish production model safety, cluster-wide network coverage, or promotion."
)

FIXTURE = {
    "schema": "saf-toy-behavior-v1",
    "permitted_operations": ["classify_text"],
    "records": [
        {"candidate_id": "toy-clean-v1", "operation": "classify_text",
         "input": {"text": "fixture benign sample"}, "expected_label": "safe"},
        {"candidate_id": "toy-reject-v1", "operation": "classify_text",
         "input": {"text": "fixture synthetic rejection sample"},
         "expected_label": "safe"},
        {"candidate_id": "toy-inconclusive-v1", "operation": "classify_text",
         "input": {"text": "fixture review-needed sample"}, "expected_label": "safe"},
    ],
}


def _wait_job(lab, name):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {condition["type"] for condition in job.get("status", {}).get("conditions", [])
                      if condition.get("status") == "True"}
        if "Failed" in conditions:
            log = lab.kubectl("logs", "job/" + name, allow_failure=True).stdout
            lab.block("Fixture Job failed: " + name + "; output=" + log[:1000])
        if "Complete" in conditions:
            output = lab.kubectl("logs", "job/" + name).stdout
            return job, json.loads(output), output
        time.sleep(0.5)
    lab.block("Fixture Job timed out: " + name)


def _pod_security(lab, job_name):
    result = json.loads(lab.kubectl("get", "pods", "-l", "job-name=" + job_name, "-o", "json").stdout)
    pods = result.get("items", [])
    if len(pods) != 1:
        return {"pod_count": len(pods)}
    pod = pods[0]
    spec = pod["spec"]
    container = spec["containers"][0]
    security = container.get("securityContext", {})
    return {
        "pod_count": 1,
        "service_account": spec.get("serviceAccountName", "default"),
        "automount_service_account_token": spec.get("automountServiceAccountToken"),
        "run_as_non_root": spec.get("securityContext", {}).get("runAsNonRoot"),
        "run_as_user": spec.get("securityContext", {}).get("runAsUser"),
        "seccomp": spec.get("securityContext", {}).get("seccompProfile", {}).get("type"),
        "allow_privilege_escalation": security.get("allowPrivilegeEscalation"),
        "read_only_root_filesystem": security.get("readOnlyRootFilesystem"),
        "dropped_capabilities": security.get("capabilities", {}).get("drop"),
        "image": container.get("image"),
        "active_deadline_seconds": spec.get("activeDeadlineSeconds"),
    }


def _auth(lab, verb, resource, actor, resource_name=None):
    scoped_resource = resource if resource_name is None else f"{resource}/{resource_name}"
    args = ["auth", "can-i", verb, scoped_resource, "--as=" + actor]
    # A denied `can-i` query exits nonzero; preserve that denial as an observation.
    result = lab.kubectl(*args, allow_failure=True)
    decision = result.stdout.strip()
    if (decision, result.returncode) not in {("yes", 0), ("no", 1)}:
        lab.block("Authorization review did not return an explicit decision")
    return decision == "yes"


def _install_reviewer_rbac(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": REVIEWER, "namespace": NAMESPACE}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": REVIEWER, "namespace": NAMESPACE},
                "rules": [
                    {"apiGroups": [""], "resources": ["configmaps"],
                     "resourceNames": [EVALUATION], "verbs": ["get"]},
                    {"apiGroups": [""], "resources": ["configmaps"],
                     "resourceNames": [DISPOSITION], "verbs": ["get", "update"]},
                    {"apiGroups": ["events.k8s.io"], "resources": ["events"],
                     "verbs": ["create"]},
                ]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": REVIEWER, "namespace": NAMESPACE},
                "subjects": [{"kind": "ServiceAccount", "name": REVIEWER,
                              "namespace": NAMESPACE}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": REVIEWER}})


def _job(name, image, script, *, service_account="default", automount=False,
         config_map, deadline=75):
    pod_spec = {
        "restartPolicy": "Never",
        "serviceAccountName": service_account,
        "automountServiceAccountToken": automount,
        "activeDeadlineSeconds": deadline,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": "fixture", "image": image, "imagePullPolicy": "Never",
            "command": ["python", "-B", "/fixture/" + script],
            "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                          "limits": {"cpu": "100m", "memory": "64Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [{"name": "fixture", "mountPath": "/fixture",
                              "readOnly": True}],
        }],
        "volumes": [{"name": "fixture", "configMap": {
            "name": config_map, "defaultMode": 292,
        }}],
    }
    return {
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": deadline,
                 "template": {"metadata": {"labels": {"app": name}},
                              "spec": pod_spec}},
    }


def _normalize(raw, event):
    evaluation = raw["evaluation"]
    decisions = raw["reviewer"]
    return {
        "control_id": "SAF-K8S-0905-045",
        "evaluation": evaluation,
        "reviewer": decisions,
        "synthetic_rejection_event": {
            "api_version": event.get("apiVersion"),
            "kind": event.get("kind"),
            "name": event.get("metadata", {}).get("name"),
            "namespace": event.get("metadata", {}).get("namespace"),
            "type": event.get("type"),
            "reason": event.get("reason"),
            "action": event.get("action"),
            "event_time_recorded": bool(event.get("eventTime")),
            "note": event.get("note"),
            "regarding": {key: event.get("regarding", {}).get(key)
                          for key in ("apiVersion", "kind", "name")},
        },
        "kubernetes_separation": raw["kubernetes_separation"],
    }


def run(lab):
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    helper = importlib.util.spec_from_file_location("saf_behavior_runtime",
                                                    HERE.parent / "SAF-K8S-0908-001" / "case.py")
    module = importlib.util.module_from_spec(helper)
    helper.loader.exec_module(module)
    image = module.load_runtime(lab)
    evaluator_code = (HERE / "evaluator.py").read_text()
    reviewer_code = (HERE / "reviewer.py").read_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "toy-evaluator-code"},
                "immutable": True, "data": {"evaluator.py": evaluator_code,
                                             "fixture.json": json.dumps(FIXTURE, sort_keys=True)}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "toy-reviewer-code"},
                "immutable": True, "data": {"reviewer.py": reviewer_code}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": DISPOSITION},
                "data": {"decisions.json": "{}"}})
    _install_reviewer_rbac(lab)
    quarantine = lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                             "metadata": {"name": "fixture-evaluator-isolation"},
                             "spec": {"podSelector": {"matchLabels": {"app": "toy-model-evaluation"}},
                                      "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}})
    baseline_record = {"candidate_id": "toy-reject-v1", "disposition": "approved", "review_required": False}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "fixture-unchecked-disposition"},
                "immutable": True, "data": {"baseline.json": json.dumps(baseline_record)}})
    prior = json.loads(lab.kubectl("get", "configmap", "fixture-unchecked-disposition", "-o", "json").stdout)
    baseline = json.loads(prior["data"]["baseline.json"])
    no_evaluation = lab.kubectl("get", "configmap", EVALUATION, allow_failure=True)
    lab.check("red", "The unchecked fixture records approval before an evaluation exists",
              baseline == baseline_record and no_evaluation.returncode != 0 and "NotFound" in no_evaluation.stderr,
              baseline)

    eval_job_spec = _job("toy-model-evaluation", image, "evaluator.py", config_map="toy-evaluator-code")
    lab.create(eval_job_spec)
    eval_job, evaluation, evaluator_stdout = _wait_job(lab, "toy-model-evaluation")
    evaluation_json = json.dumps(evaluation, sort_keys=True, separators=(",", ":"))
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": EVALUATION},
                "immutable": True, "data": {"evaluation.json": evaluation_json}})
    reviewer_job_spec = _job(REVIEWER, image, "reviewer.py", service_account=REVIEWER,
                             automount=True, config_map="toy-reviewer-code")
    reviewer_job_spec["spec"]["template"]["spec"]["containers"][0]["env"] = [
        {"name": "EVALUATION_JOB_UID", "value": eval_job["metadata"]["uid"]},
    ]
    lab.create(reviewer_job_spec)
    reviewer_job, decisions, reviewer_stdout = _wait_job(lab, REVIEWER)

    disposition_cm = json.loads(lab.kubectl("get", "configmap", DISPOSITION, "-o", "json").stdout)
    persisted = json.loads(disposition_cm["data"]["decisions.json"])
    # Independent named GET confirms the durable outcome remains a hold, not approval.
    hold_readback_cm = json.loads(lab.kubectl("get", "configmap", DISPOSITION, "-o", "json").stdout)
    hold_readback = json.loads(hold_readback_cm["data"]["decisions.json"])
    event = json.loads(lab.kubectl("get", "events.events.k8s.io", "synthetic-model-rejection",
                                   "-o", "json").stdout)
    separation = {
        "evaluator_can_get_evaluation": _auth(lab, "get", "configmaps", "system:serviceaccount:saf-test:default", EVALUATION),
        "evaluator_can_create_events": _auth(lab, "create", "events.events.k8s.io", "system:serviceaccount:saf-test:default"),
        "reviewer_can_get_evaluation": _auth(lab, "get", "configmaps", "system:serviceaccount:saf-test:" + REVIEWER, EVALUATION),
        "reviewer_can_update_disposition": _auth(lab, "update", "configmaps", "system:serviceaccount:saf-test:" + REVIEWER, DISPOSITION),
        "reviewer_can_update_evaluation": _auth(lab, "update", "configmaps", "system:serviceaccount:saf-test:" + REVIEWER, EVALUATION),
        "evaluator_pod": _pod_security(lab, "toy-model-evaluation"),
        "reviewer_pod": _pod_security(lab, REVIEWER),
        "evaluator_network_policy_observed": quarantine["spec"]["policyTypes"] == ["Ingress", "Egress"]
            and not quarantine["spec"].get("ingress") and not quarantine["spec"].get("egress"),
        "evaluator_job_active_deadline_seconds": eval_job_spec["spec"]["activeDeadlineSeconds"],
        "reviewer_job_active_deadline_seconds": reviewer_job_spec["spec"]["activeDeadlineSeconds"],
    }
    raw = {"fixture": FIXTURE, "evaluator_stdout": evaluator_stdout,
           "evaluator": evaluation, "reviewer_stdout": reviewer_stdout,
           "persisted_disposition": persisted, "hold_readback": hold_readback, "event": event,
           "kubernetes_uids": {"evaluation_job": eval_job["metadata"]["uid"],
                               "reviewer_job": reviewer_job["metadata"]["uid"],
                               "baseline_record": prior["metadata"]["uid"],
                               "disposition_record": disposition_cm["metadata"]["uid"]},
           "kubernetes_separation": separation}
    (lab.evidence / "behavioral-vetting-raw.json").write_text(json.dumps(raw, indent=2) + "\n")
    normalized = _normalize({"evaluation": evaluation, "reviewer": persisted,
                             "kubernetes_separation": separation}, event)
    (lab.evidence / "behavioral-vetting-normalized.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n")

    unsafe = next(row for row in evaluation["records"] if row["candidate_id"] == "toy-reject-v1")
    clean = next(row for row in evaluation["records"] if row["candidate_id"] == "toy-clean-v1")
    inconclusive = next(row for row in evaluation["records"] if row["candidate_id"] == "toy-inconclusive-v1")
    expected_escalated = next(row for row in persisted["decisions"] if row["candidate_id"] == "toy-inconclusive-v1")
    expected_unsafe = next(row for row in persisted["decisions"] if row["candidate_id"] == "toy-reject-v1")
    expected_clean = next(row for row in persisted["decisions"] if row["candidate_id"] == "toy-clean-v1")
    event_exact = {
        "apiVersion": "events.k8s.io/v1", "kind": "Event",
        "metadata": {"name": "synthetic-model-rejection", "namespace": NAMESPACE},
        "type": "Warning", "reason": "ModelBehaviorRejected",
        "action": "behavioral-review",
        "note": "toy-reject-v1 rejected: behavioral_policy_violation",
        "regarding": {"apiVersion": "batch/v1", "kind": "Job",
                      "name": "toy-model-evaluation", "namespace": NAMESPACE,
                      "uid": eval_job["metadata"]["uid"]},
        "reportingController": "saf.example/model-disposition-reviewer",
        "reportingInstance": REVIEWER,
    }
    expected_event_fields = {key: event.get(key) for key in event_exact if key != "metadata"}
    event_metadata = {key: event.get("metadata", {}).get(key)
                      for key in ("name", "namespace")}
    event_matches = expected_event_fields == {key: value for key, value in event_exact.items() if key != "metadata"} \
        and event_metadata == event_exact["metadata"]
    security_ok = (
        separation["evaluator_network_policy_observed"]
        and separation["evaluator_can_get_evaluation"] is False
        and separation["evaluator_can_create_events"] is False
        and separation["reviewer_can_get_evaluation"] is True
        and separation["reviewer_can_update_disposition"] is True
        and separation["reviewer_can_update_evaluation"] is False
        and all(separation[key][field] == expected for key, field, expected in (
            ("evaluator_pod", "service_account", "default"),
            ("evaluator_pod", "automount_service_account_token", False),
            ("evaluator_pod", "run_as_non_root", True),
            ("evaluator_pod", "run_as_user", 1000),
            ("evaluator_pod", "seccomp", "RuntimeDefault"),
            ("evaluator_pod", "allow_privilege_escalation", False),
            ("evaluator_pod", "read_only_root_filesystem", True),
            ("evaluator_pod", "active_deadline_seconds", 75),
            ("reviewer_pod", "service_account", REVIEWER),
            ("reviewer_pod", "automount_service_account_token", True),
        ))
        and separation["evaluator_pod"]["dropped_capabilities"] == ["ALL"]
        and separation["reviewer_pod"]["dropped_capabilities"] == ["ALL"]
    )
    lab.check("green", "The independent reviewer records exact rejection and a matching synthetic warning event",
              expected_unsafe == {"candidate_id": "toy-reject-v1", "disposition": "rejected",
                                  "reason": "behavioral_policy_violation", "reviewer": REVIEWER,
                                  "evaluation_sha256": evaluation["evaluation_sha256"]}
              and unsafe["outcome"] == "fail" and unsafe["reason"] == "behavioral_policy_violation"
              and decisions == persisted and event_matches,
              {"disposition": expected_unsafe, "event_matches": event_matches,
               "event_reason": event.get("reason"), "event_type": event.get("type")})

    lab.check("green", "Evaluator and reviewer identities enforce the intended Kubernetes separation",
              security_ok, separation)

    lab.check("positive", "The exact safe toy result receives the governed approval for this evaluation digest",
              clean == {"candidate_id": "toy-clean-v1", "operation": "classify_text",
                        "expected_label": "safe", "observed_label": "safe", "outcome": "pass",
                        "reason": "expected_behavior"}
              and expected_clean == {"candidate_id": "toy-clean-v1", "disposition": "approved",
                                     "reason": "behavioral_checks_passed", "reviewer": REVIEWER,
                                     "evaluation_sha256": evaluation["evaluation_sha256"]}
              and persisted == {"evaluator": "toy-evaluator-v1", "reviewer": REVIEWER,
                                "evaluation_sha256": evaluation["evaluation_sha256"],
                                "decisions": [expected_clean, expected_unsafe, expected_escalated]},
              {"clean_result": clean, "clean_disposition": expected_clean,
               "evaluation_sha256": evaluation["evaluation_sha256"]})
    marker_outputs = {"fixture benign sample": "safe",
                      "fixture synthetic rejection sample": "unsafe",
                      "fixture review-needed sample": "inconclusive"}
    expected_trace = [{"candidate_id": row["candidate_id"],
                       "input_sha256": hashlib.sha256(row["input"]["text"].encode()).hexdigest(),
                       "output_label": marker_outputs[row["input"]["text"]]}
                      for row in FIXTURE["records"]]
    lab.check("positive", "The evaluator computes the three fixed inert marker outcomes instead of reading prefilled observations",
              all("observed_label" not in row for row in FIXTURE["records"])
              and evaluation.get("behavior_trace") == expected_trace
              and [row.get("observed_label") for row in evaluation["records"]]
                  == [marker_outputs[row["input"]["text"]] for row in FIXTURE["records"]],
              {"marker_count": len(expected_trace),
               "input_digests_match": evaluation.get("behavior_trace") == expected_trace,
               "outputs": [row.get("observed_label") for row in evaluation["records"]]})

    held_record = next(row for row in hold_readback["decisions"]
                       if row["candidate_id"] == "toy-inconclusive-v1")
    lab.check("positive", "An inconclusive inert evaluation is durably escalated and remains held",
              inconclusive["outcome"] == "inconclusive"
              and inconclusive["reason"] == "insufficient_evidence"
              and expected_escalated == {"candidate_id": "toy-inconclusive-v1",
                                         "disposition": "escalated",
                                         "reason": "insufficient_evidence",
                                         "reviewer": REVIEWER,
                                         "evaluation_sha256": evaluation["evaluation_sha256"]}
              and hold_readback["evaluation_sha256"] == evaluation["evaluation_sha256"]
              and held_record == expected_escalated
              and held_record["disposition"] != "approved",
              {"candidate_id": held_record["candidate_id"],
               "disposition": held_record["disposition"],
               "reason": held_record["reason"],
               "evaluation_sha256_matches":
                   hold_readback["evaluation_sha256"] == evaluation["evaluation_sha256"]})

    native_spec = importlib.util.spec_from_file_location(
        "saf_0905_045_native_model", HERE / "native_model.py")
    if native_spec is None or native_spec.loader is None:
        lab.block("Could not load the bounded native model witness")
    native_module = importlib.util.module_from_spec(native_spec)
    native_spec.loader.exec_module(native_module)
    native_module.run(lab, image, _job, _wait_job, _pod_security, _auth)
