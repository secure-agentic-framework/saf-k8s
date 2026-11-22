"""Replay the ordinary RBAC audit and check the versioned DRA authorization matrix."""
import importlib.util
import json
from pathlib import Path
import time


NAMESPACE = "saf-0401-002-dra"
API_GROUP = "resource.k8s.io"
CLAIM = "saf-0401-002-dra-claim"
DRIVER = "saf-dra.example.invalid"
OTHER_DRIVER = "other-dra.example.invalid"
VERBS = ("patch", "update")
SCOPE = (
    "Replays the existing synthetic ConfigMap permission audit. A second isolated namespace "
    "tests v1.36.1 SubjectAccessReview decisions for ordinary ResourceClaim status plus "
    "the DRA binding and driver permissions. The test uses fixed synthetic principals, "
    "driver names and node-aware verbs. Production role inventory, native status request "
    "construction, node association, actual driver behavior and allocation remain separate."
)


def grant(lab, subject, rules):
    name = f"saf-dra-{subject}"
    binding = {
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
        "subjects": [{"kind": "User", "name": f"saf-k8s:dra:{subject}",
                      "apiGroup": "rbac.authorization.k8s.io"}],
    }
    for kind, fields in (("Role", {"rules": rules}), ("RoleBinding", binding)):
        body = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind,
                "metadata": {"name": name, "namespace": NAMESPACE}, **fields}
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(body))


def rule(resource, verbs, **fields):
    return {"apiGroups": [API_GROUP], "resources": [f"resourceclaims/{resource}"],
            "verbs": list(verbs), **fields}


def review(lab, subject, verb, resource, name, expected, phase):
    attributes = {"namespace": NAMESPACE, "verb": verb, "group": API_GROUP,
                  "resource": "resourceclaims", "subresource": resource, "name": name}
    spec = {"user": f"saf-k8s:dra:{subject}", "groups": ["system:authenticated"],
            "resourceAttributes": attributes}
    body = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": spec}
    deadline = time.monotonic() + 6
    while True:
        response = lab.kubectl("create", "-f", "-", "-o", "json", payload=json.dumps(body))
        status = json.loads(response.stdout)["status"]
        if status.get("evaluationError"):
            lab.block(status["evaluationError"])
        allowed = status.get("allowed", False)
        if allowed or not expected or time.monotonic() >= deadline:
            break
        time.sleep(0.2)
    lab.check(phase, f"{subject}: {verb} resourceclaims/{resource} {name}",
              allowed is expected, {"attributes": attributes, "allowed": allowed})


def run(lab):
    original = importlib.util.spec_from_file_location("rbac_audit_baseline", Path(__file__).with_name("case.py"))
    module = importlib.util.module_from_spec(original)
    original.loader.exec_module(module)
    module.run(lab)

    lab.kubectl("create", "namespace", NAMESPACE)
    status = rule("status", VERBS)
    grant(lab, "status-only", [status])
    for verb in VERBS:
        review(lab, "status-only", verb, "status", CLAIM, True, "positive")
        review(lab, "status-only", verb, "binding", CLAIM, False, "red")
        for prefix in ("associated-node", "arbitrary-node"):
            review(lab, "status-only", f"{prefix}:{verb}", "driver", DRIVER, False, "red")

    grant(lab, "scheduler", [status, rule("binding", VERBS)])
    for verb in VERBS:
        review(lab, "scheduler", verb, "status", CLAIM, True, "positive")
        review(lab, "scheduler", verb, "binding", CLAIM, True, "green")
        for prefix in ("associated-node", "arbitrary-node"):
            review(lab, "scheduler", f"{prefix}:{verb}", "driver", DRIVER, False, "green")

    for principal, allowed_prefix, opposite in (
        ("node-driver", "associated-node", "arbitrary-node"),
        ("multi-node", "arbitrary-node", "associated-node"),
    ):
        verbs = [f"{allowed_prefix}:{verb}" for verb in VERBS]
        grant(lab, principal, [status, rule("driver", verbs, resourceNames=[DRIVER])])
        for verb in VERBS:
            review(lab, principal, verb, "status", CLAIM, True, "positive")
            review(lab, principal, f"{allowed_prefix}:{verb}", "driver", DRIVER, True, "green")
            review(lab, principal, f"{allowed_prefix}:{verb}", "driver", OTHER_DRIVER, False, "green")
            review(lab, principal, f"{opposite}:{verb}", "driver", DRIVER, False, "green")
            review(lab, principal, verb, "binding", CLAIM, False, "green")

    for verb in VERBS:
        review(lab, "tenant", verb, "status", CLAIM, False, "green")
        review(lab, "tenant", verb, "binding", CLAIM, False, "green")
        for prefix in ("associated-node", "arbitrary-node"):
            review(lab, "tenant", f"{prefix}:{verb}", "driver", DRIVER, False, "green")
