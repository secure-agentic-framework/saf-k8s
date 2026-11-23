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
SCOPE = (
    "Two deterministic transformations of benign synthetic JSON run in local Kind. SHA-256 stage "
    "digests are locked in the fixture and immutable trust ConfigMap; a Kubernetes Validating "
    "Admission Policy gates persisted stage records. A separate Pod consumes the approved final "
    "artifact and emits its decision. This does not assess production data, pipeline identities, "
    "or external systems."
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


def stage_record(name, stage, payload, checksum):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": NS,
                         "labels": {"saf.example/stage-record": "true", "saf.example/stage": stage}},
            "immutable": True,
            "data": {"stage": stage, "sha256": checksum, "payload.json": payload}}


def submit(lab, record, dry=False):
    flags = ("--dry-run=server",) if dry else ()
    return lab.kubectl("create", "-f", "-", "-o", "name", *flags,
                       payload=json.dumps(record, sort_keys=True), allow_failure=True)


def policy(lab, stage1, stage2):
    rules = []
    for stage, checksum, payload in (("stage1", APPROVED["stage1"], stage1),
                                     ("stage2", APPROVED["stage2"], stage2)):
        rules.append(f'(object.data["stage"] == "{stage}" && object.data["sha256"] == "{checksum}" '
                     f'&& object.data["payload.json"] == \'{payload}\')')
    expression = "has(object.data) && object.data.size() == 3 && (" + " || ".join(rules) + ")"
    create(lab, "ValidatingAdmissionPolicy", "fixture-stage-integrity", "admissionregistration.k8s.io/v1",
           spec={"failurePolicy": "Fail",
                 "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                     "operations": ["CREATE", "UPDATE"], "resources": ["configmaps"]}]},
                 "matchConditions": [{"name": "stage-record", "expression":
                     f'request.namespace == "{NS}" && has(object.metadata.labels) && '
                     'object.metadata.labels["saf.example/stage-record"] == "true"'}],
                 "validations": [{"expression": expression,
                                  "message": "stage record does not match locked approved bytes"}]})
    create(lab, "ValidatingAdmissionPolicyBinding", "fixture-stage-integrity", "admissionregistration.k8s.io/v1",
           spec={"policyName": "fixture-stage-integrity", "validationActions": ["Deny"]})


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
                 "pipeline.py": (HERE / "pipeline.py").read_text()})
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
    rejected = [
        stage_record(f"fixture-alternate-stage{index}", f"stage{index}", payload,
                     APPROVED[f"stage{index}"])
        for index, payload in enumerate(baseline_files, start=1)
    ]
    deadline = time.monotonic() + 12
    while True:
        dry = submit(lab, rejected[0], dry=True)
        if "stage record does not match locked approved bytes" in dry.stderr:
            break
        if time.monotonic() >= deadline:
            lab.block("Stage integrity policy did not become ready in 12 seconds")
        time.sleep(0.25)
    denied = [submit(lab, record) for record in rejected]
    missing = [lab.kubectl("get", "-n", NS, "configmap", record["metadata"]["name"], "-o", "name",
                          allow_failure=True) for record in rejected]
    green_gate = {
        "both_altered_stages_denied_even_with_approved_digest_labels": all(
            result.returncode != 0 and "stage record does not match locked approved bytes" in result.stderr
            for result in denied
        ),
        "denied_transitions_created_no_configmaps": all(
            result.returncode != 0 and "NotFound" in result.stderr for result in missing
        ),
        "worker_stops_at_first_bad_stage_without_writes": checked_alternate == {
            "decision": "rejected", "transition": "input", "writes": 0
        } and baseline_files == after_rejection,
    }

    checked = command(lab, "fixture-pipeline", "checked", "approved")
    approved_records = [submit(lab, stage_record("fixture-approved-stage1", "stage1", approved_stage1,
                                                APPROVED["stage1"])),
                       submit(lab, stage_record("fixture-approved-stage2", "stage2", approved_stage2,
                                                APPROVED["stage2"]))]
    published = command(lab, "fixture-pipeline", "publish", "approved")
    observed = command(lab, "fixture-downstream", "decide")
    green = {**green_gate,
             "locked_stage_records_admitted": all(item.returncode == 0 for item in approved_records),
             "checked_exact_approved_bytes_reach_stage_two": checked == {
                 "fixture": "approved", "mode": "checked", "stages": 2,
                 "stage1_sha256": APPROVED["stage1"], "stage2_sha256": APPROVED["stage2"],
                 "advanced": True, "published": False},
             "approved_artifacts_published_only_after_admission": published == {
                 "fixture": "approved", "mode": "publish", "stages": 2,
                 "stage1_sha256": APPROVED["stage1"], "stage2_sha256": APPROVED["stage2"],
                 "advanced": True, "published": True},
             "separate_downstream_consumer_accepts_expected_artifact": observed["decision"] == "accept"}
    lab.check("green", "Admission refuses alternate stage bytes without writes and admits locked records",
              all(green.values()), green)
    positive = {"approved_input_digest_matches_lock": APPROVED["input"] ==
                "08a362b6a4f86ca8e61c2b7bccd4dca72c731af1338dfd796bb6d8871d2e8a0e",
                "downstream_decision_is_independently_observed": observed == {
                    "consumer": "fixture-downstream", "decision": "accept", "stage2_sha256": APPROVED["stage2"]}}
    lab.check("positive", "The exact approved synthetic bytes complete both stages and the consumer accepts",
              all(positive.values()), positive)
    (lab.evidence / "training-integrity-observations.json").write_text(json.dumps({
        "scope": "synthetic-local-fixture", "baseline": red, "governed": green,
        "downstream": observed, "expected_sha256": APPROVED,
    }, sort_keys=True, indent=2) + "\n")
