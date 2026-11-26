"""Record authenticated synthetic annotations and independently verify label release."""
import importlib.util
import json
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
NAME = "fixture-annotation"
CODE = NAME + "-code"
REVIEWS = NAME + "-review-bundle"
PVC = NAME + "-release"
SCOPE = (
    "Live Kubernetes service-account impersonation exercises named RBAC on benign synthetic reviewer "
    "and curator records. A workload compares an unchecked release with a governed decision for the exact "
    "dataset version. An independent read-only Pod confirms the persisted release and which rows are held."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def store_reviews(lab, records):
    custody = {}
    for row in records:
        for review in row["reviews"]:
            custody[review["review_id"]] = (review["reviewer"], review)
        if row["correction"]:
            record_id = "correction-" + row["asset_id"]
            custody[record_id] = (row["correction"]["actor"], row["correction"])
    by_actor = {}
    for name, (actor, _) in custody.items():
        by_actor.setdefault(actor, []).append(name)
        create(lab, "ConfigMap", name, data={"record.json": "{}"})
    for actor, names in by_actor.items():
        create(lab, "ServiceAccount", actor, automountServiceAccountToken=False)
        create(lab, "Role", actor, RBAC, rules=[{
            "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "patch"], "resourceNames": names,
        }])
        create(lab, "RoleBinding", actor, RBAC, subjects=[
            {"kind": "ServiceAccount", "name": actor, "namespace": NS}
        ], roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": actor})
    def patch(name, actor, record, allow_failure=False):
        return lab.kubectl("patch", "configmap", name, "--type=merge", "-p",
                           json.dumps({"data": {"record.json": json.dumps(record, sort_keys=True)}}),
                           f"--as=system:serviceaccount:{NS}:{actor}", allow_failure=allow_failure)
    curator_denial = patch("correction-card-02", "reviewer-amber", custody["correction-card-02"][1],
                           allow_failure=True)
    observed = {}
    for name, (actor, record) in custody.items():
        patch(name, actor, record)
        lab.kubectl("patch", "configmap", name, "--type=merge", "-p", '{"immutable":true}')
        current = json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout)
        if current.get("immutable") is not True:
            lab.block("Review was not sealed after collection")
        observed[name] = json.loads(current["data"]["record.json"])
    for row in records:
        row["reviews"] = [observed[review["review_id"]] for review in row["reviews"]]
        if row["correction"]:
            row["correction"] = observed["correction-" + row["asset_id"]]
    return curator_denial.returncode != 0 and "Forbidden" in curator_denial.stderr, len(observed), records


def workload(lab, image, name, operation, read_only):
    unit = container("fixture", image=image, imagePullPolicy="Never",
                     command=["python", "/code/annotation_fixture.py", operation], volumeMounts=[
        {"name": "code", "mountPath": "/code", "readOnly": True},
        {"name": "reviews", "mountPath": "/reviews", "readOnly": True},
        {"name": "release", "mountPath": "/release", "readOnly": read_only},
    ])
    lab.create(pod(name, [unit], automountServiceAccountToken=False,
                   securityContext={"fsGroup": 65534}, volumes=[
        {"name": "code", "configMap": {"name": CODE}},
        {"name": "reviews", "configMap": {"name": REVIEWS}},
        {"name": "release", "persistentVolumeClaim": {"claimName": PVC}},
    ]))
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=80s", timeout=90)
    return json.loads(lab.kubectl("logs", f"pod/{name}").stdout)


def run(lab):
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_annotations_runtime")
    fixture = load(HERE / "annotation_fixture.py", "saf_annotations_policy")
    image = runtime.load_runtime(lab)
    protected, count, observed = store_reviews(lab, fixture.demo_records())
    create(lab, "ConfigMap", CODE, immutable=True, data={
        "annotation_fixture.py": (HERE / "annotation_fixture.py").read_text()
    })
    create(lab, "ConfigMap", REVIEWS, immutable=True,
           data={"records.json": json.dumps(observed, sort_keys=True)})
    create(lab, "PersistentVolumeClaim", PVC, spec={
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}
    })
    decision = workload(lab, image, NAME + "-write", "publish", False)
    released = workload(lab, image, NAME + "-read", "inspect", True)
    red = released["unchecked"]["labels"] == {
        "card-01": "sprout", "card-02": "stone", "card-03": "stone", "card-04": "stone", "card-05": "sprout",
    }
    lab.check("red", "Unchecked intake releases records with unresolved QA or custody",
              red, released["unchecked"])
    rows = {r["asset_id"]: r for r in decision["rows"]}
    green = {
        "reviewer_could_not_write_authorized_correction": protected and count == 11,
        "wrong_administrative_reference_is_held": rows["card-03"]["hold_reason"]
        == "administrative_qa_reference_mismatch",
        "prior_dataset_version_is_held": rows["card-04"]["hold_reason"] == "dataset_binding_mismatch",
        "one_reviewer_cannot_fill_both_slots": rows["card-05"]["hold_reason"]
        == "minimum_independent_review_not_met",
        "only_two_approved_rows_enter_the_release": set(released["governed"]["labels"]) == {"card-01", "card-02"},
    }
    lab.check("green", "Actor, version and QA checks hold the affected annotations",
              all(green.values()), green)
    metric = decision["historical_distribution_priority"]
    metric_check = {
        "synthetic_historical_shift_prioritizes_independent_review": metric == {
            "baseline_version": "v3", "current_version": fixture.EXPECTED_BATCH["version"],
            "sample_count": 5, "max_absolute_share_shift": 0.4,
            "fixture_threshold": 0.2, "priority": "independent_quality_review",
            "decision_effect": "advisory_only",
        },
        "adjudication_and_release_authority_remain_unchanged": protected
            and rows["card-02"]["authorized_correction"]
            and rows["card-02"]["correction_audit"]["actor"] == "curator-1"
            and {key: row["status"] for key, row in rows.items()} == {
                "card-01": "approved", "card-02": "approved", "card-03": "held",
                "card-04": "held", "card-05": "held",
            }
            and released["governed"] == {
                "dataset": fixture.EXPECTED_BATCH,
                "labels": {"card-01": "sprout", "card-02": "sprout"},
            },
    }
    lab.check("positive", "Historical label shift prioritizes review without changing approval or release",
              all(metric_check.values()), metric_check)
    positive = {
        "agreement_and_independent_adjudication_pass": rows["card-01"]["review_agreement"]
        and rows["card-02"]["authorized_correction"] and rows["card-02"]["correction_audit"]["actor"] == "curator-1",
        "independent_consumer_verifies_approved_labels_and_dataset":
            released["governed"] == {"dataset": fixture.EXPECTED_BATCH,
                                     "labels": {"card-01": "sprout", "card-02": "sprout"}},
    }
    lab.check("positive", "Independently approved labels reach the exact dataset release",
              all(positive.values()), positive)
    (lab.evidence / "annotation-approval-observations.json").write_text(json.dumps({
        "sealed_reviews": count, "reviewer_cannot_patch_curator_record": protected,
        "decision": decision, "independent_reader": released,
        "checks": {"red": red, "green": green, "metric": metric_check, "positive": positive},
    }, indent=2, sort_keys=True) + "\n")
