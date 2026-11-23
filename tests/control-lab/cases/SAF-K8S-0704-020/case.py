"""Constrain the fixture node identity without breaking separate workload access."""

import json
import time

SCOPE = "Live Kubernetes authorization for modeled provider node and workload roles against owned markers."
NAMESPACE = "saf-test"
RBAC = "rbac.authorization.k8s.io"
NODE_USER = "fixture-node-role-subject"
APP_USER = "fixture-workload-role-subject"
NODE_MARKER = "node-infrastructure-marker"
APP_MARKER = "workload-data-marker"


def grant(lab, role, user, resources):
    rules = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": resources}]
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": role}, "rules": rules})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": role},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": role},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": user}]})
    return rules


def decision(lab, user, marker):
    result = lab.create({"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                         "spec": {"user": user, "groups": ["system:authenticated"], "resourceAttributes": {
                             "namespace": NAMESPACE, "verb": "get", "resource": "configmaps", "name": marker}}})["status"]
    if result.get("evaluationError"):
        lab.block("The fixture authorization review could not evaluate access")
    return result.get("allowed", False)


def matrix(lab):
    return {"node_infrastructure": decision(lab, NODE_USER, NODE_MARKER), "node_workload_data": decision(lab, NODE_USER, APP_MARKER),
            "workload_infrastructure": decision(lab, APP_USER, NODE_MARKER), "workload_data": decision(lab, APP_USER, APP_MARKER)}


def read(lab, user, name):
    result = lab.kubectl("--as", user, "get", "configmap", name, "-o", "json")
    return json.loads(result.stdout)["data"]["public-marker"] == name


def run(lab):
    for marker in (NODE_MARKER, APP_MARKER):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": marker}, "data": {"public-marker": marker}})
    node_rule = grant(lab, "fixture-node-role", NODE_USER, [NODE_MARKER, APP_MARKER])
    grant(lab, "fixture-workload-role", APP_USER, [APP_MARKER])
    expected = {"node_infrastructure": True, "node_workload_data": False, "workload_infrastructure": False, "workload_data": True}
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        before = matrix(lab)
        if before["node_workload_data"] and before["workload_data"]:
            break
        time.sleep(0.4)
    lab.check("red", "The modeled broad node grant and the distinct workload grant initially both authorize the workload resource",
              before == dict(expected, node_workload_data=True), before)
    node_rule[0]["resourceNames"] = [NODE_MARKER]
    lab.kubectl("patch", "role", "fixture-node-role", "--type=merge", "-p", json.dumps({"rules": node_rule}))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        after = matrix(lab)
        if not after["node_workload_data"]:
            break
        time.sleep(0.4)
    lab.check("green", "Narrowing only the modeled node role removes its workload read without breaking either required decision",
              after == expected, after)

    reads = {"required_node_read": read(lab, NODE_USER, NODE_MARKER), "required_workload_read": read(lab, APP_USER, APP_MARKER)}
    lab.check("positive", "The two synthetic subjects still complete their own permitted marker reads", all(reads.values()), reads)
    (lab.evidence / "node-role-observations.json").write_text(json.dumps(
        {"before": before, "after": after, "positive_reads": reads, "provider_roles_are_modeled": True}, indent=2) + "\n")
