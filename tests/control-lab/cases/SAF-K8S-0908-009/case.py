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
CLIENT = "fixture-privacy-client"
COLLECTOR = "fixture-privacy-collector"
COLLECTOR_ACCOUNT = "fixture-privacy-collector"
INPUT = "fixture-privacy-client-input"
OUTPUT = "fixture-privacy-collected-result"
DENY = "the exact reviewed privacy parameter record is required"
SCOPE = (
    "Native Kubernetes admission rejects unapproved binary randomized-response parameters "
    "for one named fixture deployment. Its actual worker validates the mounted approval and "
    "the case enumerates the executed mechanism's finite outcomes for replacing one bit. "
    "A second case-owned client keeps one inert bit in a client-only mount, applies the same "
    "mechanism locally, and sends only its one-field noisy result to a separate scoped collector. "
    "This proves only the toy mechanism and fixture data boundary, not real population privacy or "
    "application utility."
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


def client_collector(lab, image):
    create(lab, "ConfigMap", INPUT, data={"bit": "1"})
    create(lab, "ConfigMap", OUTPUT, data={"result": ""})
    create(lab, "ServiceAccount", COLLECTOR_ACCOUNT, automountServiceAccountToken=True)
    create(lab, "Role", COLLECTOR_ACCOUNT, "rbac.authorization.k8s.io/v1", rules=[
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [OUTPUT],
         "verbs": ["patch"]},
    ])
    create(lab, "RoleBinding", COLLECTOR_ACCOUNT, "rbac.authorization.k8s.io/v1",
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": COLLECTOR_ACCOUNT},
           subjects=[{"kind": "ServiceAccount", "name": COLLECTOR_ACCOUNT, "namespace": NS}])

    collector_unit = container(
        "collector", image=image, imagePullPolicy="Never",
        command=["python", "/fixture/mechanism.py", "serve-collector"],
        volumeMounts=[{"name": "source", "mountPath": "/fixture", "readOnly": True},
                      {"name": "policy", "mountPath": "/policy", "readOnly": True}],
    )
    collector_unit["readinessProbe"] = {
        "exec": {"command": ["python", "-c",
                             "import socket; socket.create_connection(('127.0.0.1', 8080), 2).close()"]},
        "periodSeconds": 1,
    }
    collector_pod = pod(COLLECTOR, [collector_unit], serviceAccountName=COLLECTOR_ACCOUNT,
                        automountServiceAccountToken=True, volumes=[
                            {"name": "source", "configMap": {"name": CODE}},
                            {"name": "policy", "configMap": {"name": NAME}},
                        ])
    collector_pod["metadata"]["labels"] = {"fixture-role": "privacy-collector"}
    lab.create(collector_pod)
    create(lab, "Service", COLLECTOR, spec={
        "selector": {"fixture-role": "privacy-collector"},
        "ports": [{"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"}],
    })

    client_unit = container(
        "client", image=image, imagePullPolicy="Never",
        command=["sleep", "300"],
        volumeMounts=[{"name": "source", "mountPath": "/fixture", "readOnly": True},
                      {"name": "policy", "mountPath": "/policy", "readOnly": True},
                      {"name": "input", "mountPath": "/input", "readOnly": True}],
    )
    client_pod = pod(CLIENT, [client_unit], automountServiceAccountToken=False, volumes=[
        {"name": "source", "configMap": {"name": CODE}},
        {"name": "policy", "configMap": {"name": NAME}},
        {"name": "input", "configMap": {"name": INPUT}},
    ])
    lab.create(client_pod)
    ready(lab, COLLECTOR)
    ready(lab, CLIENT)
    for _ in range(12):
        probe = lab.kubectl("exec", CLIENT, "--", "python", "/fixture/mechanism.py",
                             "collector-ready", timeout=12)
        if probe.stdout.strip() == "ready":
            break
        time.sleep(1)
    else:
        lab.block("The collector service did not become ready from the client")
    client_record = json.loads(lab.kubectl("get", "pod", CLIENT, "-o", "json").stdout)
    collector_record = json.loads(lab.kubectl("get", "pod", COLLECTOR, "-o", "json").stdout)
    return client_record, collector_record


def persisted_result(lab):
    result = lab.kubectl("get", "configmap", OUTPUT, "-o", "json")
    return json.loads(result.stdout)["data"]


def client_collector_path(lab, image):
    client_pod, collector_pod = client_collector(lab, image)
    input_read = lab.kubectl("exec", COLLECTOR, "--", "python", "/fixture/mechanism.py",
                             "collector-input-probe", timeout=12)
    input_read_status = json.loads(input_read.stdout)["status"]
    wrong = lab.kubectl("exec", CLIENT, "--", "python", "/fixture/mechanism.py",
                        "wrong-schema-probe", timeout=12)
    wrong_response = json.loads(wrong.stdout)
    after_wrong = persisted_result(lab)
    sent = lab.kubectl("exec", CLIENT, "--", "python", "/fixture/mechanism.py",
                       "client-send", timeout=12)
    sent_result = json.loads(sent.stdout)
    after_send = persisted_result(lab)
    client_mounts = {mount["name"] for mount in client_pod["spec"]["containers"][0]["volumeMounts"]}
    collector_mounts = {mount["name"] for mount in collector_pod["spec"]["containers"][0]["volumeMounts"]}
    return {
        "input_volume_is_client_only": "input" in client_mounts and "input" not in collector_mounts,
        "client_has_no_serviceaccount_token": client_pod["spec"]["automountServiceAccountToken"] is False,
        "collector_cannot_read_input_configmap": input_read_status == 403,
        "wrong_schema_denied_without_state_change": wrong_response == {
            "decision": "rejected", "status": 400} and after_wrong == {"result": ""},
        "accepted_one_field_release_matches_persisted_observation":
            sent_result.get("status") == 200 and sent_result.get("decision") == "accepted"
            and type(sent_result.get("sent_result")) is int
            and sent_result["sent_result"] in (0, 1)
            and set(after_send) == {"result"}
            and after_send == {"result": str(sent_result["sent_result"])},
    }


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
    flow = client_collector_path(lab, image)
    lab.check("supplement", "The owned client sends only a schema-valid noisy result to its collector",
              all(flow.values()), flow)
    (lab.evidence/"approved-privacy-parameters-observations.json").write_text(json.dumps({
        "baseline": red, "approved_parameters": gate, "deployed": valid,
        "client_collector_path": flow, "finite_distribution": observed,
    },sort_keys=True,indent=2)+"\n")
