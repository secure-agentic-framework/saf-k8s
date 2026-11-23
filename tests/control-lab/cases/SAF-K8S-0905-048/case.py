"""Admission check for reviewed OCI model manifest digest references."""
import json
import time
from pathlib import Path


HERE = Path(__file__).parent
NAMESPACE = "saf-test"
POLICY = "saf-0905-048-model-digest"
BINDING = "saf-0905-048-model-digest"
REVIEWED_DIGEST = "saf-k8s.example/reviewed-manifest-digest"
DENIAL = "model image must use the reviewed sha256 manifest digest"
SCOPE = (
    "A pinned Distribution registry stores two harmless model versions in one disposable cluster. "
    "Native Kubernetes admission compares a Pod's model reference and release annotation with a "
    "named registry digest record. The same mutable tag is admitted before policy and rejected "
    "after activation. A correct digest passes admission and resolves to the original manifest "
    "and blob bytes even after the separate mutable tag is updated. This exercises server dry-run "
    "admission and a fixture registry consumer."
)
REGISTRY_IMAGE = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
IMAGE = "saf-048-registry:5000/saf-fixture/model"
RELEASE = "saf-048-reviewed-release"


def _install_registry(lab):
    spec = {"name": "registry", "image": REGISTRY_IMAGE, "ports": [{"containerPort": 5000}],
            "readinessProbe": {"httpGet": {"path": "/v2/", "port": 5000}, "periodSeconds": 1}}
    labels = {"app": "saf-048-registry"}
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": "saf-048-registry"},
                "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                         "template": {"metadata": {"labels": labels},
                                      "spec": {"automountServiceAccountToken": False, "containers": [spec]}}}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "saf-048-registry"},
                "spec": {"selector": labels, "ports": [{"port": 5000, "targetPort": 5000}]}})
    program = (HERE / "registry_client.py").read_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "saf-048-client"},
                "data": {"client.py": program}})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "saf-048-client"},
                "spec": {"automountServiceAccountToken": False,
                         "containers": [{"name": "probe", "image": PYTHON,
                                         "command": ["sleep", "3600"],
                                         "volumeMounts": [{"name": "client", "mountPath": "/fixture", "readOnly": True}]}],
                         "volumes": [{"name": "client", "configMap": {"name": "saf-048-client"}}]}})
    lab.kubectl("rollout", "status", "deployment/saf-048-registry", "--timeout=75s", timeout=80)
    lab.kubectl("wait", "--for=condition=Ready", "pod/saf-048-client", "--timeout=75s", timeout=80)


def _registry(lab, *args):
    result = lab.kubectl("exec", "saf-048-client", "--", "python", "-B", "/fixture/client.py", *args)
    return json.loads(result.stdout)


def _pod(image, digest):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "saf-0905-048-fixture",
            "namespace": NAMESPACE,
            "labels": {"saf-k8s.example/model-fixture": "synthetic"},
            "annotations": {REVIEWED_DIGEST: digest},
        },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "fixture",
                "image": image,
                "imagePullPolicy": "Never",
                "command": ["/bin/false"],
            }],
        },
    }


def _request(lab, pod):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(pod), allow_failure=True)


def _install(lab):
    image = ("params != null && has(object.metadata.annotations) && "
             f"'{REVIEWED_DIGEST}' in object.metadata.annotations && "
             f"object.metadata.annotations['{REVIEWED_DIGEST}'] == params.data['digest'] && "
             "object.spec.containers.all(c, c.image == params.data['repository'] + '@' + params.data['digest'])")
    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"],
                "resources": ["pods"], "scope": "Namespaced",
            }]},
            "validations": [{"expression": image, "message": DENIAL, "reason": "Forbidden"}],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING},
        "spec": {
            "policyName": POLICY,
            "validationActions": ["Deny"],
            "paramRef": {"name": RELEASE, "namespace": NAMESPACE, "parameterNotFoundAction": "Deny"},
            "matchResources": {"namespaceSelector": {"matchLabels": {
                "saf-k8s.example/control": "0905-048-fixture",
            }}},
        },
    }
    lab.kubectl("apply", "-f", "-", payload=(
        json.dumps(policy) + "\n---\n" + json.dumps(binding)))


def _filtered_observation(result):
    response = (result.stderr or "")
    return {
        "admitted": result.returncode == 0,
        "expected_policy_named": POLICY in response,
        "expected_denial_message": DENIAL in response,
    }


def run(lab):
    _install_registry(lab)
    initial = _registry(lab, "seed")
    digest = initial["manifest_digest"]
    review = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": RELEASE},
              "immutable": True, "data": {"repository": IMAGE, "digest": digest}}
    stored = lab.create(review)
    lab.check("positive", "The release record persists the reviewed registry manifest digest",
              stored.get("immutable") is True and stored["data"] == review["data"],
              {"repository": IMAGE, **initial})

    lab.kubectl("label", "namespace", NAMESPACE, "saf-k8s.example/control=0905-048-fixture", "--overwrite")
    tag_image = IMAGE + ":reviewed"
    request = _pod(tag_image, digest)
    baseline = _request(lab, request)
    lab.check("red", "The exact mutable-tag request passes before policy activation",
              baseline.returncode == 0 and json.loads(baseline.stdout)["spec"]["containers"][0]["image"] == tag_image,
              _filtered_observation(baseline))

    _install(lab)
    deadline = time.monotonic() + 25
    while True:
        rejected = _request(lab, request)
        denied = _filtered_observation(rejected)
        if rejected.returncode and denied["expected_policy_named"] and denied["expected_denial_message"]:
            break
        if rejected.returncode or time.monotonic() >= deadline:
            lab.block("Expected reviewed-digest policy denial did not become active")
        time.sleep(0.5)
    lab.check("green", "The same mutable-tag request receives the named policy denial",
              rejected.returncode != 0 and denied["expected_denial_message"], denied)

    changed = _registry(lab, "advance")
    changed_digest = changed["manifest_digest"]
    lab.check("red", "The unconstrained fixture tag can be advanced to a different manifest",
              changed_digest != digest and changed["fixture_version"] == "replacement-v2", changed)
    wrong = _request(lab, _pod(IMAGE + "@" + changed_digest, changed_digest))
    rejected_digest = _filtered_observation(wrong)
    lab.check("green", "A well-formed digest with matching self-declared metadata still needs the trusted release record",
              wrong.returncode != 0 and rejected_digest["expected_policy_named"] and rejected_digest["expected_denial_message"],
              rejected_digest)
    pinned = IMAGE + "@" + digest
    accepted = _request(lab, _pod(pinned, digest))
    if accepted.returncode:
        lab.block("The reviewed digest pin was not admitted")
    admitted = json.loads(accepted.stdout)["spec"]["containers"][0]["image"]
    extracted = admitted.rsplit("@", 1)[1]
    fetched = _registry(lab, "read", extracted)
    lab.check("positive", "The admitted reference retrieves the exact reviewed manifest and blob after the tag moves",
              admitted == pinned and fetched == initial, {"admitted": admitted, "retrieved": fetched})
    (lab.evidence / "registry-resolution.json").write_text(
        json.dumps({"initial": initial, "updated_tag": changed, "admitted": admitted,
                    "retrieved": fetched}, indent=2, sort_keys=True) + "\n")
