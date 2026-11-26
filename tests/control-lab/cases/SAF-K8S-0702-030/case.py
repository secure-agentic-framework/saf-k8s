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
UNAPPROVED = "promotion-unapproved"
SCOPE = (
    "Ordinary Kubernetes Jobs apply a versioned synthetic promotion policy to owned artifact "
    "metadata, preserve a higher existing classification, and expose API-backed authorization "
    "comparisons. Real model systems, policy governance and external deployment remain adopter evidence."
)


def get(lab, name):
    return json.loads(lab.kubectl("get", f"configmap/{name}", "-o", "json").stdout)


def register_fixtures(lab, source, targets):
    names = [f"target-{target}" for target in targets]
    for name in [SOURCE, *names]:
        classification = ("synthetic-confidential" if name == "target-already-higher"
                          else source["classification"])
        lab.create({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "labels": {CLASSIFICATION: classification}},
            "immutable": True, "data": {"artifact": source["artifact_id"]},
        })
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": POLICY},
        "immutable": True,
        "data": {name: (ROOT / name).read_text()
                 for name in ("source-artifact.json", "promotion-policy-v1.json", "promote.py")},
    })
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": UNAPPROVED}})
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": ACCOUNT},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": names,
                    "verbs": ["get", "update"]}],
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


def authorization_probes(lab):
    probes = (("target", UNAPPROVED, "deny-target", "higher"),
              ("policy", ACCOUNT, "deny-policy", ""))
    for label, account, mode, argument in probes:
        job = f"probe-{label}-authority"
        command = ["python", "/fixture/promote.py", mode]
        if argument:
            command.append(argument)
        lab.create({
            "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": job},
            "spec": {"activeDeadlineSeconds": 60, "backoffLimit": 0, "template": {"spec": {
                "restartPolicy": "Never", "serviceAccountName": account,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "probe", "image": IMAGE,
                                "command": command,
                                "securityContext": {"allowPrivilegeEscalation": False,
                                                    "readOnlyRootFilesystem": True,
                                                    "capabilities": {"drop": ["ALL"]}},
                                "volumeMounts": [{"name": "policy", "mountPath": "/fixture", "readOnly": True}]}],
                "volumes": [{"name": "policy", "configMap": {"name": POLICY}}],
            }}},
        })
        lab.kubectl("wait", "--for=condition=Complete", f"job/{job}", "--timeout=75s", timeout=85)
        yield label, json.loads(lab.kubectl("logs", f"job/{job}").stdout)


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

    already_higher = states["already-higher"]["metadata"]
    monotonic = (already_higher["labels"][CLASSIFICATION] == "synthetic-confidential"
                 and already_higher["annotations"]["saf-k8s.example/promotion-decision"] == "preserved"
                 and states["already-higher"]["data"] == initial["already-higher"]["data"])
    lab.check("positive", "Promotion preserves an existing higher target classification",
              monotonic and events["already-higher"]["decision"] == "preserved",
              {"higher_target_preserved": monotonic,
               "resulting_classification": already_higher["labels"][CLASSIFICATION]})

    target_before = get(lab, "target-higher")
    policy_before = get(lab, POLICY)
    probe_events = dict(authorization_probes(lab))
    target_after = get(lab, "target-higher")
    policy_after = get(lab, POLICY)
    authz_ok = (probe_events["target"]["http_status"] == 403
                and probe_events["target"]["denied"] is True
                and probe_events["policy"]["http_status"] == 403
                and probe_events["policy"]["denied"] is True
                and target_after["metadata"]["resourceVersion"] == target_before["metadata"]["resourceVersion"]
                and target_after["metadata"]["labels"] == target_before["metadata"]["labels"]
                and policy_after["metadata"]["resourceVersion"] == policy_before["metadata"]["resourceVersion"]
                and policy_after["data"] == policy_before["data"])
    lab.check("green", "Only the scoped promotion identity can update targets and the policy remains protected",
              authz_ok,
              {"unapproved_target_patch_denied": probe_events["target"]["http_status"] == 403,
               "policy_change_denied": probe_events["policy"]["http_status"] == 403,
               "target_unchanged": target_after["metadata"]["resourceVersion"]
               == target_before["metadata"]["resourceVersion"],
               "policy_unchanged": policy_after["metadata"]["resourceVersion"]
               == policy_before["metadata"]["resourceVersion"]})
