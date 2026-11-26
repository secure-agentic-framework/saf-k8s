"""Exercise stage integrity gates on a local, synthetic Kubernetes pipeline."""
import importlib.util
import json
import time
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
NS = "saf-test"
APPROVED = {
    "input": "08a362b6a4f86ca8e61c2b7bccd4dca72c731af1338dfd796bb6d8871d2e8a0e",
    "stage1": "332ef3e0470b05b5d95355b9a838b6ee42b5e11c7fac6e36b21944fdbf4b5c6b",
    "stage2": "928f96382e91d258b9902faaf75a5475385d59eb112f18c80e0d4680379758b2",
}
VERSIONS = {"stage1": "fixture-transform-one/v1", "stage2": "fixture-transform-two/v1"}
SCOPE = (
    "Two deterministic transformations of benign synthetic JSON run in local Kind. SHA-256 stage "
    "digests are locked in the fixture and immutable trust ConfigMap; a Kubernetes Validating "
    "Admission Policy gates persisted stage records. Two synthetic ServiceAccount Job identities "
    "create the records through the in-cluster API; a separate Pod consumes the approved final "
    "artifact. This does not assess production identities, external trust roots, data, or systems."
)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load runtime helper: {path}")
    item = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(item)
    return item


def create(lab, kind, name, api="v1", **fields):
    metadata = {"name": name}
    if kind not in {"Namespace", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}:
        metadata["namespace"] = NS
    return lab.create({"apiVersion": api, "kind": kind, "metadata": metadata, **fields})


def command(lab, target, *args):
    result = lab.kubectl("exec", "-n", NS, target, "--", "python", "/fixture/pipeline.py", *args, timeout=20)
    return json.loads(result.stdout)


def wait_policy_ready(lab, name):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        response = lab.kubectl("get", "validatingadmissionpolicy", name, "-o", "json")
        checking = json.loads(response.stdout).get("status", {}).get("typeChecking")
        if checking is not None:
            if checking.get("expressionWarnings"):
                lab.block(f"Stage policy {name} has Kubernetes CEL expression warnings")
            return
        time.sleep(0.25)
    lab.block(f"Stage policy {name} did not report CEL type-check results")


def policy(lab, stage1, stage2):
    rules = []
    for stage, checksum, parent, version, payload in (
            ("stage1", APPROVED["stage1"], APPROVED["input"], VERSIONS["stage1"], stage1),
            ("stage2", APPROVED["stage2"], APPROVED["stage1"], VERSIONS["stage2"], stage2)):
        rules.append(f'(object.data["stage"] == "{stage}" && object.data["sha256"] == "{checksum}" '
                     f'&& object.data["input_sha256"] == "{parent}" '
                     f'&& object.data["stage_version"] == "{version}" '
                     f'&& object.data["payload.json"] == \'{payload}\')')
    expression = "has(object.data) && object.data.size() == 5 && (" + " || ".join(rules) + ")"
    create(lab, "ValidatingAdmissionPolicy", "fixture-stage-integrity", "admissionregistration.k8s.io/v1",
           spec={"failurePolicy": "Fail",
                 "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                     "operations": ["CREATE", "UPDATE"], "resources": ["configmaps"]}]},
                 "matchConditions": [{"name": "stage-record", "expression":
                     f'request.namespace == "{NS}" && ('
                     'object.metadata.name in ["fixture-approved-stage1", "fixture-approved-stage2"] || '
                     '(has(object.metadata.labels) && "saf.example/stage-record" in object.metadata.labels && '
                     'object.metadata.labels["saf.example/stage-record"] == "true"))' }],
                 "validations": [{"expression": expression,
                                  "message": "stage record does not match locked approved bytes"}]})
    wait_policy_ready(lab, "fixture-stage-integrity")
    create(lab, "ValidatingAdmissionPolicyBinding", "fixture-stage-integrity", "admissionregistration.k8s.io/v1",
           spec={"policyName": "fixture-stage-integrity", "validationActions": ["Deny"]})

    # The second conjunctive policy binds each record to a distinct authenticated
    # Kubernetes ServiceAccount. The original policy above continues to validate
    # exact approved content; this policy validates producer identity and lineage.
    stage1_rule = (
        'request.userInfo.username == "system:serviceaccount:saf-test:fixture-stage1-producer" '
        '&& object.metadata.name == "fixture-approved-stage1" '
        '&& object.data["stage"] == "stage1" '
        f'&& object.data["sha256"] == "{APPROVED["stage1"]}" '
        f'&& object.data["input_sha256"] == "{APPROVED["input"]}" '
        f'&& object.data["stage_version"] == "{VERSIONS["stage1"]}"'
    )
    stage2_rule = (
        'request.userInfo.username == "system:serviceaccount:saf-test:fixture-stage2-producer" '
        '&& object.metadata.name == "fixture-approved-stage2" '
        '&& object.data["stage"] == "stage2" '
        f'&& object.data["sha256"] == "{APPROVED["stage2"]}" '
        f'&& object.data["input_sha256"] == "{APPROVED["stage1"]}" '
        f'&& object.data["stage_version"] == "{VERSIONS["stage2"]}"'
    )
    create(lab, "ValidatingAdmissionPolicy", "fixture-stage-producer-identity",
           "admissionregistration.k8s.io/v1",
           spec={"failurePolicy": "Fail",
                 "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                     "operations": ["CREATE", "UPDATE"], "resources": ["configmaps"]}]},
                 "matchConditions": [{"name": "stage-record", "expression":
                     f'request.namespace == "{NS}" && ('
                     'object.metadata.name in ["fixture-approved-stage1", "fixture-approved-stage2"] || '
                     '(has(object.metadata.labels) && "saf.example/stage-record" in object.metadata.labels && '
                     'object.metadata.labels["saf.example/stage-record"] == "true"))' }],
                 "validations": [{"expression":
                     "(has(object.data) && object.data.size() == 5) && (" + stage1_rule + " || " + stage2_rule + ")",
                     "message": "stage record producer identity or lineage not approved"}]})
    wait_policy_ready(lab, "fixture-stage-producer-identity")
    create(lab, "ValidatingAdmissionPolicyBinding", "fixture-stage-producer-identity",
           "admissionregistration.k8s.io/v1",
           spec={"policyName": "fixture-stage-producer-identity", "validationActions": ["Deny"]})


def service_account(lab, name, role_name, rules):
    create(lab, "ServiceAccount", name, automountServiceAccountToken=True)
    create(lab, "Role", role_name, "rbac.authorization.k8s.io/v1", rules=rules)
    create(lab, "RoleBinding", role_name, "rbac.authorization.k8s.io/v1",
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role_name},
           subjects=[{"kind": "ServiceAccount", "name": name, "namespace": NS}])


def job(lab, image, name, account, mode):
    mounts = [{"name": "source", "mountPath": "/fixture", "readOnly": True},
              {"name": "trust", "mountPath": "/trust", "readOnly": True}]
    volumes = [{"name": "source", "configMap": {"name": "fixture-pipeline-source"}},
               {"name": "trust", "configMap": {"name": "fixture-pipeline-trust"}}]
    if mode == "stage2":
        mounts.append({"name": "work", "mountPath": "/pipeline", "readOnly": False})
        volumes.append({"name": "work", "persistentVolumeClaim": {"claimName": "fixture-pipeline-work"}})
    create(lab, "Job", name, "batch/v1", spec={
        "backoffLimit": 0,
        "template": {"metadata": {"labels": {"saf.example/stage-producer-job": name}},
            "spec": {"serviceAccountName": account, "automountServiceAccountToken": True,
                "restartPolicy": "Never",
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "fsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "producer", "image": image, "imagePullPolicy": "Never",
                    "command": ["python", "-B", "/fixture/identity_producer.py", mode],
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}},
                    "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                  "limits": {"cpu": "100m", "memory": "64Mi"}},
                    "volumeMounts": mounts}], "volumes": volumes}}})


def job_result(lab, name):
    lab.kubectl("wait", "-n", NS, "--for=condition=Complete", f"job/{name}", "--timeout=90s", timeout=100)
    output = lab.kubectl("logs", "-n", NS, f"job/{name}").stdout.strip()
    return json.loads(output)


def run_identity_jobs(lab, image):
    create_rules = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}]
    service_account(lab, "fixture-stage1-producer", "fixture-stage1-producer", [
        *create_rules,
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["fixture-approved-stage1"],
         "verbs": ["get"]},
    ])
    service_account(lab, "fixture-stage2-producer", "fixture-stage2-producer", [
        {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]},
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["fixture-approved-stage1", "fixture-approved-stage2"],
         "verbs": ["get"]},
    ])
    service_account(lab, "fixture-alternate-producer", "fixture-alternate-producer", create_rules)

    # The source ConfigMap is immutable. Each stage's projected bearer token is
    # read only inside its Job process and never appears in argv or output.

    job(lab, image, "fixture-stage1-producer-job", "fixture-stage1-producer", "stage1")
    stage1 = job_result(lab, "fixture-stage1-producer-job")
    job(lab, image, "fixture-stage2-producer-job", "fixture-stage2-producer", "stage2")
    stage2 = job_result(lab, "fixture-stage2-producer-job")
    before_alternate = lab.kubectl("get", "-n", NS, "configmap/fixture-approved-stage1", "-o",
                                   "jsonpath={.metadata.uid}:{.metadata.resourceVersion}").stdout.strip()
    job(lab, image, "fixture-alternate-producer-job", "fixture-alternate-producer", "alternate")
    alternate = job_result(lab, "fixture-alternate-producer-job")
    after_alternate = lab.kubectl("get", "-n", NS, "configmap/fixture-approved-stage1", "-o",
                                  "jsonpath={.metadata.uid}:{.metadata.resourceVersion}").stdout.strip()
    return {"stage1": stage1, "stage2": stage2, "alternate": alternate,
            "approved_record_unchanged": bool(before_alternate) and before_alternate == after_alternate}


def run(lab):
    runtime = module(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_fixture_runtime")
    image = runtime.load_runtime(lab)
    approved = {"schema": "fixture-v1", "examples": [
        {"text": "  Apple  ", "label": "fruit"}, {"text": "pear", "label": "fruit"}]}
    alternate = {"schema": "fixture-v1", "examples": [
        {"text": "plum", "label": "fruit"}, {"text": "pear", "label": "fruit"}]}
    approved_input = json.dumps(approved, sort_keys=True, separators=(",", ":"))
    alternate_input = json.dumps(alternate, sort_keys=True, separators=(",", ":"))
    create(lab, "ConfigMap", "fixture-pipeline-source", immutable=True,
           data={"approved.json": approved_input, "alternate.json": alternate_input,
                 "pipeline.py": (HERE / "pipeline.py").read_text(),
                 "identity_producer.py": (HERE / "identity_producer.py").read_text()})
    create(lab, "ConfigMap", "fixture-pipeline-trust", immutable=True,
           data={key + "_sha256": value for key, value in APPROVED.items()})
    create(lab, "PersistentVolumeClaim", "fixture-pipeline-work", spec={
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}})
    for name in ("fixture-pipeline", "fixture-downstream"):
        unit = container("fixture", image=image, imagePullPolicy="Never", command=["sleep", "3600"],
                         volumeMounts=[{"name": "source", "mountPath": "/fixture", "readOnly": True},
                                       {"name": "work", "mountPath": "/pipeline",
                                     "readOnly": name == "fixture-downstream"}])
        workload = pod(name, [unit], automountServiceAccountToken=False,
                       volumes=[{"name": "source", "configMap": {"name": "fixture-pipeline-source"}},
                                {"name": "trust", "configMap": {"name": "fixture-pipeline-trust"}},
                                {"name": "work", "persistentVolumeClaim": {"claimName": "fixture-pipeline-work"}}],
                       securityContext={"fsGroup": 65534})
        workload["metadata"]["namespace"] = NS
        workload["spec"]["containers"][0]["volumeMounts"].append(
            {"name": "trust", "mountPath": "/trust", "readOnly": True})
        lab.create(workload)
    # Both PVC consumers exist before waiting, so WaitForFirstConsumer can bind the claim.
    lab.kubectl("wait", "-n", NS, "--for=jsonpath={.status.phase}=Bound",
                "pvc/fixture-pipeline-work", "--timeout=90s")
    for name in ("fixture-pipeline", "fixture-downstream"):
        lab.kubectl("wait", "-n", NS, "--for=condition=Ready", f"pod/{name}", "--timeout=95s")

    red_advancement = command(lab, "fixture-pipeline", "unchecked", "alternate")
    red = {"alternate_is_valid_format": json.loads(alternate_input)["schema"] == "fixture-v1",
           "checks_removed_advance_both_transforms": red_advancement == {
               "fixture": "alternate", "mode": "unchecked", "stages": 2,
               "stage1_sha256": "2d99e4e4cf1707bfbbf3b9a3a3085b9c17a76f408b74a5c6e34ba3b9f08eae8a",
               "stage2_sha256": "55af542038050a34a07e00aba3a2589790a87df316b078333ace01734e056e3e",
               "advanced": True, "published": True}}
    lab.check("red", "A valid alternate fixture advances when stage checks are removed",
              all(red.values()), red)
    baseline_files = [lab.kubectl("exec", "-n", NS, "fixture-pipeline", "--", "cat",
                                  f"/pipeline/alternate-stage{stage}.json").stdout for stage in (1, 2)]
    checked_alternate = command(lab, "fixture-pipeline", "checked", "alternate")
    after_rejection = [lab.kubectl("exec", "-n", NS, "fixture-pipeline", "--", "cat",
                                   f"/pipeline/alternate-stage{stage}.json").stdout for stage in (1, 2)]

    approved_stage1 = ("{\"examples\":[{\"label\":\"fruit\",\"text\":\"apple\"},"
                       "{\"label\":\"fruit\",\"text\":\"pear\"}],\"schema\":\"fixture-v1\"}")
    approved_stage2 = ("{\"rows\":[{\"label\":\"fruit\",\"tokens\":[\"apple\"]},"
                       "{\"label\":\"fruit\",\"tokens\":[\"pear\"]}],\"schema\":\"features-v1\"}")
    policy(lab, approved_stage1, approved_stage2)
    # Real producer Jobs exercise admission under their distinct ServiceAccount
    # principals. Their altered-content requests are server-side dry runs.
    producer_results = run_identity_jobs(lab, image)
    approved_records = [item["create_status"] == 201
                        for item in (producer_results["stage1"], producer_results["stage2"])]
    stage2_job_consumer = command(lab, "fixture-downstream", "decide")
    green_gate = {
        "both_altered_stages_denied_even_with_approved_digest_labels": all(
            producer_results[stage].get("altered_dry_run_denied") is True
            for stage in ("stage1", "stage2")
        ),
        "denied_transitions_leave_approved_configmaps_unchanged": all(
            producer_results[stage].get("record_unchanged_by_denials") is True
            for stage in ("stage1", "stage2")),
        "worker_stops_at_first_bad_stage_without_writes": checked_alternate == {
            "decision": "rejected", "transition": "input", "writes": 0
        } and baseline_files == after_rejection,
    }
    checked = command(lab, "fixture-pipeline", "checked", "approved")
    published = command(lab, "fixture-pipeline", "publish", "approved")
    observed = command(lab, "fixture-downstream", "decide")
    stage1_readback = json.loads(lab.kubectl("get", "-n", NS, "configmap",
                                            "fixture-approved-stage1", "-o", "json").stdout)
    stage2_readback = json.loads(lab.kubectl("get", "-n", NS, "configmap",
                                            "fixture-approved-stage2", "-o", "json").stdout)
    green = {**green_gate,
             "locked_stage_records_admitted": all(approved_records),
             "checked_exact_approved_bytes_reach_stage_two": checked == {
                 "fixture": "approved", "mode": "checked", "stages": 2,
                 "stage1_sha256": APPROVED["stage1"], "stage2_sha256": APPROVED["stage2"],
                 "advanced": True, "published": False},
             "approved_artifacts_published_only_after_admission": published == {
                 "fixture": "approved", "mode": "publish", "stages": 2,
                 "stage1_sha256": APPROVED["stage1"], "stage2_sha256": APPROVED["stage2"],
                 "advanced": True, "published": True},
             "separate_downstream_consumer_accepts_stage2_job_artifact":
                 stage2_job_consumer["decision"] == "accept"}
    lab.check("green", "Admission refuses alternate stage bytes without writes and admits locked records",
              all(green.values()), green)
    lineage = {
        "stage1_identity_created_exact_record_and_rejected_stale_parent":
            producer_results["stage1"].get("create_status") == 201
            and producer_results["stage1"].get("stale_parent_denied") is True
            and producer_results["stage1"].get("record_unchanged_by_denials") is True,
        "stage2_identity_read_parent_created_record_and_rejected_stale_version":
            producer_results["stage2"].get("parent_read_status") == 200
            and producer_results["stage2"].get("create_status") == 201
            and producer_results["stage2"].get("stale_version_denied") is True
            and producer_results["stage2"].get("record_unchanged_by_denials") is True,
        "alternate_identity_denied_without_persistence":
            producer_results["alternate"].get("exact_record_denied") is True
            and producer_results["approved_record_unchanged"] is True,
        "admitted_parent_and_version_match_actual_checked_output":
            all(approved_records)
            and checked["stage1_sha256"] == stage1_readback["data"]["sha256"] == APPROVED["stage1"]
            and stage1_readback["data"]["input_sha256"] == APPROVED["input"]
            and stage1_readback["data"]["stage_version"] == VERSIONS["stage1"]
            and checked["stage2_sha256"] == stage2_readback["data"]["sha256"] == APPROVED["stage2"]
            and stage2_readback["data"]["input_sha256"] == stage1_readback["data"]["sha256"]
            and stage2_readback["data"]["stage_version"] == VERSIONS["stage2"],
        "published_outputs_repeat_admitted_digests_and_consumer_reads_stage2":
            published["stage1_sha256"] == stage1_readback["data"]["sha256"]
            and published["stage2_sha256"] == stage2_readback["data"]["sha256"]
            and stage2_job_consumer["stage2_sha256"] == stage2_readback["data"]["sha256"]
            and observed["stage2_sha256"] == stage2_readback["data"]["sha256"]
            and observed["decision"] == "accept",
    }
    lab.check("positive", "Native admission rejects stale lineage/version and release readback matches admitted outputs",
              all(lineage.values()), lineage)
    positive = {"approved_input_digest_matches_lock": APPROVED["input"] ==
                "08a362b6a4f86ca8e61c2b7bccd4dca72c731af1338dfd796bb6d8871d2e8a0e",
                "downstream_decision_is_independently_observed": observed == {
                    "consumer": "fixture-downstream", "decision": "accept", "stage2_sha256": APPROVED["stage2"]}}
    lab.check("positive", "The exact approved synthetic bytes complete both stages and the consumer accepts",
              all(positive.values()), positive)
    (lab.evidence / "training-integrity-observations.json").write_text(json.dumps({
        "scope": "synthetic-local-fixture", "baseline": red, "governed": green,
        "lineage": lineage, "downstream": observed, "expected_sha256": APPROVED,
    }, sort_keys=True, indent=2) + "\n")
