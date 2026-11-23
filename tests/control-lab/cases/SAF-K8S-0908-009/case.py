"""Verify approved parameter admission and an exact finite mechanism in Kind."""
import importlib.util
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
NAME = "fixture-privacy-parameters"
SERVER = "fixture-privacy-verified-release"
CODE = "fixture-privacy-code"
VAP = "admissionregistration.k8s.io/v1"
DENY = "the exact reviewed privacy parameter record is required"
SCOPE = (
    "Native Kubernetes admission rejects unapproved binary randomized-response parameters "
    "for one named fixture deployment. Its actual worker validates the mounted approval and "
    "the case enumerates the executed mechanism's finite outcomes for replacing one bit. "
    "The running loopback service returns only a sampled bit. This tests the declared pure "
    "local differential privacy bound for this mechanism and neighbor relation."
)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    item = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(item)
    return item


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def submit(lab, data, dry=False):
    record = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME}, "data": data}
    flags = ("--dry-run=server",) if dry else ()
    return lab.kubectl("create", "-f", "-", "-o", "name", *flags,
                       payload=json.dumps(record), allow_failure=True)


def enforce(lab, approved):
    conditions = " && ".join(f"'{key}' in object.data && object.data['{key}'] == '{value}'"
                             for key, value in approved.items())
    create(lab, "ValidatingAdmissionPolicy", NAME, VAP, spec={
        "failurePolicy": "Fail",
        "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                "operations": ["CREATE", "UPDATE"], "resources": ["configmaps"]}]},
        "matchConditions": [{"name": "named-parameters",
                             "expression": f"request.namespace == '{NS}' && object.metadata.name == '{NAME}'"}],
        "validations": [{"expression": f"has(object.data) && object.data.size() == {len(approved)} && {conditions}",
                         "message": DENY}],
    })
    create(lab, "ValidatingAdmissionPolicyBinding", NAME, VAP,
           spec={"policyName": NAME, "validationActions": ["Deny"]})


def launch(lab, image):
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"mechanism.py": (HERE/"mechanism.py").read_text()})
    component = container("release", image=image, imagePullPolicy="Never",
                          command=["python", "/fixture/mechanism.py", "serve"],
                          volumeMounts=[{"name": "source", "mountPath": "/fixture", "readOnly": True},
                                        {"name": "policy", "mountPath": "/policy", "readOnly": True}])
    component["readinessProbe"] = {"exec": {"command": ["python", "-c",
        "import socket; socket.create_connection(('127.0.0.1', 8080), 2).close()"]}, "periodSeconds": 1}
    lab.create(pod(SERVER, [component], automountServiceAccountToken=False, volumes=[
        {"name": "source", "configMap": {"name": CODE}},
        {"name": "policy", "configMap": {"name": NAME}},
    ]))
    ready(lab, SERVER)


def run(lab):
    runtime = module(HERE.parent/"SAF-K8S-0908-001"/"case.py", "saf_fixture_runtime")
    image = runtime.load_runtime(lab)
    mechanism = module(HERE/"mechanism.py", "saf_binary_randomized_response")
    approved = mechanism.REGISTRY
    weaker = dict(approved, epsilonRatioBound="15", truthfulOutcomes="15", totalOutcomes="16")
    initial = submit(lab, weaker, dry=True)
    red = {"unreviewed_configuration_admitted_without_policy": initial.returncode == 0}
    lab.check("red", "The cluster alone admits a parameter configuration outside the approved bound",
              all(red.values()), red)

    enforce(lab, approved)
    for _ in range(15):
        refused = submit(lab, weaker, dry=True)
        if DENY in refused.stderr:
            break
        time.sleep(.5)
    wrong_unit = submit(lab, dict(approved, unit="different-privacy-unit"), dry=True)
    unknown = submit(lab, dict(approved, mechanism="unreviewed-mechanism"), dry=True)
    without_review = submit(lab, {name:value for name,value in approved.items() if name != "review"}, dry=True)
    admissible = submit(lab, approved)
    gate = {"weaker_bound_denied": DENY in refused.stderr,
            "different_privacy_unit_denied": DENY in wrong_unit.stderr,
            "unapproved_mechanism_denied": DENY in unknown.stderr,
            "missing_review_denied": DENY in without_review.stderr,
            "exact_reviewed_configuration_persisted": admissible.returncode == 0}
    lab.check("green", "The live gate requires the approved mechanism, unit, bound and review",
              all(gate.values()), gate)

    launch(lab, image)
    check = lab.kubectl("exec", SERVER, "--", "python", "/fixture/mechanism.py", "review", timeout=12)
    observed = json.loads(check.stdout)
    query = lab.kubectl("exec", SERVER, "--", "python", "-c",
                        "from urllib.request import urlopen; "
                        "print(urlopen('http://127.0.0.1:8080/release',timeout=5).read().decode())", timeout=14)
    response = json.loads(query.stdout)
    valid = {"known_counts": observed["counts"] == [{"0":3,"1":1},{"0":1,"1":3}],
             "exact_common_support_and_approved_ratio": observed["common_support"]
             and observed["approved_likelihood_bound"] and observed["bound_is_tight_on_an_event"],
             "actual_release_has_only_binary_result": set(response) == {"result"}
             and type(response["result"]) is int and response["result"] in (0,1)}
    lab.check("positive", "The deployed fixture mechanism realizes the declared finite bound and releases one bit",
              all(valid.values()), valid)
    (lab.evidence/"approved-privacy-parameters-observations.json").write_text(json.dumps({
        "baseline": red, "approved_parameters": gate, "deployed": valid, "finite_distribution": observed,
    },sort_keys=True,indent=2)+"\n")
