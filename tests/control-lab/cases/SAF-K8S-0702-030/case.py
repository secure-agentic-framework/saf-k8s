"""Observe automatic classification changes on synthetic promotion artifacts."""
from datetime import datetime, timezone
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
CLASSIFICATION = "saf-k8s.example/data-classification"
SOURCE = "source-artifact"
POLICY = "promotion-policy"
ACCOUNT = "promotion-fixture"
SCOPE = (
    "Three ordinary Kubernetes Jobs apply a versioned synthetic promotion policy to distinct "
    "artifact metadata objects. The case observes uplift, equality and unresolved policy, "
    "and preserves the source classification. Real model systems, policy authoring, "
    "production deployment permissions and governance require separate evidence."
)


def get(lab, name):
    return json.loads(lab.kubectl("get", f"configmap/{name}", "-o", "json").stdout)


def register_fixtures(lab, source, targets):
    names = [f"target-{target}" for target in targets]
    for name in [SOURCE, *names]:
        lab.create({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "labels": {CLASSIFICATION: source["classification"]}},
            "immutable": True, "data": {"artifact": source["artifact_id"]},
        })
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": POLICY},
        "immutable": True,
        "data": {name: (ROOT / name).read_text()
                 for name in ("source-artifact.json", "promotion-policy-v1.json", "promote.py")},
    })
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT}})
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": ACCOUNT},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": names, "verbs": ["patch"]}],
    })
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": ACCOUNT},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACCOUNT},
        "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": ACCOUNT}],
    })


def promote(lab, targets):
    for target in targets:
        lab.create({
            "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": f"promote-{target}"},
            "spec": {"activeDeadlineSeconds": 80, "backoffLimit": 0, "template": {"spec": {
                "restartPolicy": "Never", "serviceAccountName": ACCOUNT,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "promotion", "image": IMAGE,
                                "command": ["python", "/fixture/promote.py", target],
                                "securityContext": {"allowPrivilegeEscalation": False,
                                                    "readOnlyRootFilesystem": True,
                                                    "capabilities": {"drop": ["ALL"]}},
                                "volumeMounts": [{"name": "policy", "mountPath": "/fixture", "readOnly": True}]}],
                "volumes": [{"name": "policy", "configMap": {"name": POLICY}}],
            }}},
        })
    for target in targets:
        name = f"job/promote-{target}"
        lab.kubectl("wait", "--for=condition=Complete", name, "--timeout=90s", timeout=100)
        yield target, json.loads(lab.kubectl("logs", name).stdout)


def run(lab):
    source = json.loads((ROOT / "source-artifact.json").read_text())
    policy = json.loads((ROOT / "promotion-policy-v1.json").read_text())
    targets = policy["targets"]
    register_fixtures(lab, source, targets)
    original = get(lab, SOURCE)
    initial = {name: get(lab, f"target-{name}") for name in targets}
    high_before = initial["higher"]["metadata"]["labels"][CLASSIFICATION]
    required = targets["higher"]["required_classification"]
    lab.check("red", "A copied source classification fails to satisfy the higher policy",
              high_before == source["classification"] != required,
              {"copied_source_classification": high_before, "required": required})

    events = dict(promote(lab, targets))
    states = {name: get(lab, f"target-{name}") for name in targets}
    high = states["higher"]["metadata"]
    assigned = high["labels"][CLASSIFICATION]
    timestamp = high["annotations"]["saf-k8s.example/promotion-reviewed-at"]
    timestamp_valid = datetime.fromisoformat(timestamp).tzinfo == timezone.utc
    lab.check("green", "The promotion Job persists the uplift and a policy-verifiable decision record",
              assigned == required == events["higher"]["applied"] and events["higher"]["decision"] == "uplifted"
              and high["annotations"]["saf-k8s.example/promotion-policy"] == policy["policy_version"]
              and timestamp_valid,
              {"applied_classification": assigned, "decision": events["higher"]["decision"],
               "versioned_policy_record": timestamp_valid})

    equal_ok = states["equal"]["metadata"]["labels"][CLASSIFICATION] == source["classification"]
    unknown_unchanged = (states["unknown"]["metadata"]["resourceVersion"]
                         == initial["unknown"]["metadata"]["resourceVersion"])
    source_unchanged = get(lab, SOURCE) == original
    lab.check("positive", "Equal classification is preserved and unknown policy leaves both source and target unchanged",
              equal_ok and events["equal"]["decision"] == "preserved" and unknown_unchanged and source_unchanged
              and events["unknown"]["decision"] == "unresolved_requirement" and events["unknown"]["applied"] is None,
              {"equal_preserved": equal_ok, "unknown_target_unchanged": unknown_unchanged,
               "source_unchanged": source_unchanged, "unknown_applied": events["unknown"]["applied"]})
