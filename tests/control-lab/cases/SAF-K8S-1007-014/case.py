"""Exercise synthetic AI asset classification admission and API readback."""
import json
from pathlib import Path
import time

from lab import NAMESPACE


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
POLICY = "saf-1007-014-ai-classification"
BINDING = "saf-1007-014-ai-classification"
DEPLOYMENT = "mock-inference"
ASSET_CONFIG = "synthetic-ai-asset"
POLICY_LABEL = "saf-k8s.example/control"
ASSET_ID = "synth-asset-1007-014"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "Disposable Kind Kubernetes v1.36.1 cluster. Creates one owned namespace, a scaled-to-zero mock Deployment, "
    "and a native ValidatingAdmissionPolicy for one "
    "synthetic AI asset ConfigMap. Missing and out-of-set sensitivity/criticality/exposure "
    "labels are tested through API denial and absence on readback. A valid record is read "
    "back, then its classification is updated and read back to show a fixture-only risk-route "
    "change. This does not discover assets, establish a real taxonomy, enforce classification "
    "on other resource kinds or clusters, create operational tickets, validate regulatory "
    "applicability, or prove production governance or response performance."
)


def read_fixture(name):
    return json.loads((FIXTURES / name).read_text())


def save_raw(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def policy_resources():
    # Each expression guards field presence before indexing the labels map. Keep the
    # admission scope to ConfigMaps in the uniquely labeled case namespace.
    validations = [
        ("'saf-k8s.example/sensitivity'", "['public', 'internal', 'confidential', 'restricted']",
         "sensitivity must use an allowed synthetic class"),
        ("'saf-k8s.example/criticality'", "['low', 'medium', 'high', 'critical']",
         "criticality must use an allowed synthetic class"),
        ("'saf-k8s.example/exposure'", "['none', 'review']",
         "exposure must use an allowed synthetic class"),
    ]
    rules = []
    for key, allowed, message in validations:
        label_key = key[1:-1]
        rules.append({
            "expression": (
                f"has(object.metadata.labels) && '{label_key}' in object.metadata.labels && "
                f"object.metadata.labels[{key}] in {allowed}"
            ),
            "message": message,
        })
    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "namespaceSelector": {"matchLabels": {POLICY_LABEL: "SAF-K8S-1007-014"}},
                "resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"],
                    "operations": ["CREATE", "UPDATE"], "resources": ["configmaps"],
                }],
            },
            "validations": rules,
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING},
        "spec": {"policyName": POLICY, "validationActions": ["Deny"]},
    }
    return policy, binding


def wait_for_policy(lab):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "validatingadmissionpolicy", POLICY, "-o", "json",
                             timeout=15, allow_failure=True)
        if result.returncode == 0:
            obj = json.loads(result.stdout)
            status = obj.get("status", {})
            typed = "typeChecking" in status
            if typed:
                warnings = status.get("typeChecking", {}).get("expressionWarnings", [])
                if warnings:
                    lab.block("Admission policy reports CEL type-check warnings")
                return obj
        time.sleep(0.5)
    lab.block("Admission policy did not finish CEL type checking")


def wait_for_enforcement(lab, unclassified_asset):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        probe = lab.create(unclassified_asset, dry_run=True, allow_failure=True)
        if probe.returncode:
            if POLICY in probe.stderr and "denied request" in probe.stderr.lower():
                return {"exit_code": probe.returncode, "policy_response": probe.stderr}
            lab.block(f"Unexpected admission response during policy activation: {probe.stderr}")
        time.sleep(0.25)
    lab.block("The expected admission policy denial did not become active")


def workload():
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": DEPLOYMENT, "namespace": NAMESPACE,
                     "labels": {POLICY_LABEL: "SAF-K8S-1007-014"}},
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {"app": DEPLOYMENT}},
            "template": {
                "metadata": {"labels": {"app": DEPLOYMENT}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "mock-inference", "image": PYTHON_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c", "import time; time.sleep(3600)"],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                    }],
                },
            },
        },
    }


def asset_record(labels, record):
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": ASSET_CONFIG, "namespace": NAMESPACE,
                     "labels": labels},
        "immutable": False,
        "data": {"record.json": json.dumps(record, sort_keys=True)},
    }


def get_asset(lab):
    return json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", ASSET_CONFIG,
                                  "-o", "json").stdout)


def route(labels, routes):
    if (labels.get("saf-k8s.example/sensitivity") == "restricted"
            or labels.get("saf-k8s.example/criticality") in {"high", "critical"}
            or labels.get("saf-k8s.example/exposure") == "review"):
        return routes["priority"]
    return routes["standard"]


def attempt_denied(lab, name, resource):
    created = lab.create(resource, allow_failure=True)
    lookup = lab.kubectl("-n", NAMESPACE, "get", "configmap", name, "-o", "json",
                         allow_failure=True)
    return {
        "create_exit_code": created.returncode,
        "create_stdout": created.stdout,
        "create_stderr": created.stderr,
        "readback_exit_code": lookup.returncode,
        "readback_stdout": lookup.stdout,
        "readback_stderr": lookup.stderr,
    }


def is_not_found(result):
    text = (result["readback_stdout"] + result["readback_stderr"]).lower()
    return result["readback_exit_code"] != 0 and "not found" in text


def run(lab):
    fixture = read_fixture("asset-record.json")
    missing = read_fixture("classification-missing.json")
    invalid = read_fixture("classification-invalid.json")
    policy, binding = policy_resources()

    lab.kubectl("label", "namespace", NAMESPACE, f"{POLICY_LABEL}=SAF-K8S-1007-014")
    baseline_asset = asset_record(missing["labels"], fixture["asset_record"])
    baseline = lab.create(baseline_asset, dry_run=True)
    baseline_accepted = baseline.get("metadata", {}).get("name") == ASSET_CONFIG
    save_raw(lab, "classification-unenforced.raw.json", baseline)
    lab.check("red", "The API admits an unclassified record before the admission policy is installed",
              baseline_accepted, {"unclassified_server_dry_run_admitted": baseline_accepted})
    lab.create(policy)
    lab.create(binding)
    policy_state = wait_for_policy(lab)
    enforcement = wait_for_enforcement(lab, baseline_asset)
    save_raw(lab, "classification-policy-ready.raw.json", enforcement)

    lab.create(workload())
    live_workload = json.loads(lab.kubectl("-n", NAMESPACE, "get", "deployment", DEPLOYMENT,
                                           "-o", "json").stdout)
    workload_image = live_workload["spec"]["template"]["spec"]["containers"][0]["image"]
    if workload_image != PYTHON_IMAGE or live_workload["spec"]["replicas"] != 0:
        lab.block("Mock Deployment did not retain the expected pinned image and zero replicas")

    # These are attempted against the same admission policy and must leave no object behind.
    missing_result = attempt_denied(
        lab, ASSET_CONFIG,
        asset_record(missing["labels"], fixture["asset_record"]),
    )
    invalid_result = attempt_denied(
        lab, ASSET_CONFIG,
        asset_record(invalid["labels"], fixture["asset_record"]),
    )
    save_raw(lab, "classification-denials.raw.json", {
        "missing_classification": missing_result,
        "invalid_classification": invalid_result,
    })
    missing_denied = (missing_result["create_exit_code"] != 0
                      and is_not_found(missing_result)
                      and POLICY in missing_result["create_stderr"]
                      and "denied request" in missing_result["create_stderr"].lower())
    invalid_denied = (invalid_result["create_exit_code"] != 0
                      and is_not_found(invalid_result)
                      and POLICY in invalid_result["create_stderr"]
                      and "denied request" in invalid_result["create_stderr"].lower())
    lab.check("green", "Admission denies missing and out-of-set classification and neither persists",
              missing_denied and invalid_denied,
              {"missing_classification_denied_and_absent": missing_denied,
               "invalid_classification_denied_and_absent": invalid_denied,
               "missing_classification_error": missing_result["create_stderr"],
               "invalid_classification_error": invalid_result["create_stderr"]})

    low_labels = fixture["classifications"]["standard"]
    valid_record = asset_record(low_labels, fixture["asset_record"])
    create_result = lab.create(valid_record)
    low = get_asset(lab)
    low_labels_live = low["metadata"].get("labels", {})
    low_route = route(low_labels_live, fixture["routes"])
    stored_record = json.loads(low["data"].get("record.json", "{}"))
    record_binds_workload = (stored_record.get("namespace") == NAMESPACE
                             and stored_record.get("workload") == DEPLOYMENT
                             and stored_record.get("asset_id") == ASSET_ID
                             and live_workload["metadata"].get("name") == DEPLOYMENT
                             and live_workload["metadata"].get("namespace") == NAMESPACE)
    low_durable = (
        low["metadata"].get("uid") == create_result["metadata"].get("uid")
        and low["data"].get("record.json") == json.dumps(fixture["asset_record"], sort_keys=True)
        and all(low_labels_live.get(k) == v for k, v in low_labels.items())
        and record_binds_workload
    )
    save_raw(lab, "classification-readback.raw.json", {
        "policy_status": policy_state,
        "mock_workload": {
            "namespace": NAMESPACE, "name": DEPLOYMENT,
            "uid": live_workload["metadata"]["uid"], "image": workload_image,
        },
        "asset_record_low": low,
        "route": low_route,
    })
    lab.check("green", "Allowed classification is durably readable from the Kubernetes API",
              low_durable and low_route == fixture["routes"]["standard"],
              {"uid_matches_create_response": low["metadata"].get("uid") ==
               create_result["metadata"].get("uid"),
               "record_data_matches_fixture": low["data"].get("record.json") ==
               json.dumps(fixture["asset_record"], sort_keys=True),
               "record_binds_live_mock_workload": record_binds_workload,
               "classification_labels_match": all(low_labels_live.get(k) == v
                                                   for k, v in low_labels.items()),
               "route": low_route})

    high_labels = fixture["classifications"]["priority"]
    label_args = [f"{key}={value}" for key, value in high_labels.items()]
    lab.kubectl("-n", NAMESPACE, "label", "configmap", ASSET_CONFIG, *label_args, "--overwrite")
    high = get_asset(lab)
    high_labels_live = high["metadata"].get("labels", {})
    high_route = route(high_labels_live, fixture["routes"])
    same_record = (
        high["metadata"].get("uid") == low["metadata"].get("uid")
        and high.get("data", {}).get("record.json") == low.get("data", {}).get("record.json")
    )
    save_raw(lab, "classification-readback.raw.json", {
        "policy_status": policy_state,
        "mock_workload": {
            "namespace": NAMESPACE, "name": DEPLOYMENT,
            "uid": live_workload["metadata"]["uid"], "image": workload_image,
        },
        "asset_record_low": low,
        "asset_record_high": high,
        "routes": {"low": low_route, "high": high_route},
        "same_synthetic_record_uid_and_data": same_record,
    })
    lab.check("positive", "The same synthetic asset record changes from standard to priority routing",
              same_record and low_route == fixture["routes"]["standard"]
              and high_route == fixture["routes"]["priority"]
              and all(high_labels_live.get(k) == v for k, v in high_labels.items()),
              {"same_record_uid_and_data": same_record,
               "initial_route": low_route, "updated_route": high_route,
               "updated_classification_labels_match": all(high_labels_live.get(k) == v
                                                           for k, v in high_labels.items())})
